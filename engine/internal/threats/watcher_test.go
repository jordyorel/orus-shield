package threats

import (
	"context"
	"io"
	"log/slog"
	"slices"
	"testing"
	"time"

	"github.com/jordyorel/orus-shield/engine/internal/store"
)

// fakeStore keeps templates in memory, with the store's baseline rule.
type fakeStore struct {
	templates map[string]store.ThreatTemplate
	emerging  map[string]bool
	processed map[string]bool
	targets   []store.TargetTechnologies
	recorded  []store.ThreatMatch
}

func (f *fakeStore) SyncThreatTemplates(_ context.Context, ts []store.ThreatTemplate, _ time.Time) (int, error) {
	baseline := len(f.templates) == 0
	n := 0
	for _, t := range ts {
		if _, ok := f.templates[t.ID]; ok {
			continue
		}
		f.templates[t.ID] = t
		f.emerging[t.ID] = !baseline || t.New
		n++
	}
	return n, nil
}

func (f *fakeStore) PendingThreats(_ context.Context, limit int) ([]store.ThreatTemplate, error) {
	var out []store.ThreatTemplate
	for id, t := range f.templates {
		if f.emerging[id] && !f.processed[id] && len(out) < limit {
			out = append(out, t)
		}
	}
	slices.SortFunc(out, func(a, b store.ThreatTemplate) int { return compare(a.ID, b.ID) })
	return out, nil
}

func compare(a, b string) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

func (f *fakeStore) VerifiedTargetTechnologies(context.Context) ([]store.TargetTechnologies, error) {
	return f.targets, nil
}

func (f *fakeStore) RecordThreats(_ context.Context, ids []string, ms []store.ThreatMatch, _ time.Time) (int, error) {
	for _, id := range ids {
		f.processed[id] = true
	}
	f.recorded = append(f.recorded, ms...)
	targets := map[string]bool{}
	for _, m := range ms {
		targets[m.TargetID] = true
	}
	return len(targets), nil
}

func TestWatcher(t *testing.T) {
	st := &fakeStore{templates: map[string]store.ThreatTemplate{}, emerging: map[string]bool{}, processed: map[string]bool{},
		targets: []store.TargetTechnologies{{TargetID: "t1", Technologies: []string{"WordPress 6.1"}}, {TargetID: "t2", Technologies: []string{"jira"}}}}
	w := NewWatcher(st, "testdata/templates", slog.New(slog.NewTextHandler(io.Discard, nil)))

	// First pass: the baseline. Only the release's new template (Avada,
	// WordPress) is emerging; the Atlassian one is old and alerts nobody.
	added, rescans, err := w.RunOnce(context.Background())
	if err != nil || added != 2 || rescans != 1 {
		t.Fatalf("first pass: added %d, rescans %d, err %v", added, rescans, err)
	}
	if len(st.recorded) != 1 || st.recorded[0].TargetID != "t1" || st.recorded[0].TemplateID != "CVE-2026-0001" {
		t.Errorf("recorded %+v", st.recorded)
	}

	// Second pass, same release: nothing new, nothing rescanned.
	if added, rescans, err := w.RunOnce(context.Background()); err != nil || added != 0 || rescans != 0 {
		t.Errorf("second pass: added %d, rescans %d, err %v", added, rescans, err)
	}
}
