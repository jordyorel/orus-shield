package threats

import (
	"context"
	"log/slog"
	"slices"
	"time"

	"github.com/jordyorel/orus-shield/engine/internal/store"
)

// Store is the part of store.Store the watcher uses.
type Store interface {
	SyncThreatTemplates(ctx context.Context, templates []store.ThreatTemplate, now time.Time) (int, error)
	PendingThreats(ctx context.Context, limit int) ([]store.ThreatTemplate, error)
	VerifiedTargetTechnologies(ctx context.Context) ([]store.TargetTechnologies, error)
	RecordThreats(ctx context.Context, templateIDs []string, matches []store.ThreatMatch, now time.Time) (int, error)
}

const (
	// DefaultInterval is the wait between passes. New templates arrive
	// when the operator installs a release, so once an hour is plenty;
	// the worker also runs a pass when it starts.
	DefaultInterval = time.Hour
	// batch bounds the templates matched per pass.
	batch = 200
)

// Watcher syncs the installed templates and rescans the targets that new
// ones may concern.
type Watcher struct {
	store     Store
	templates string // nuclei-templates directory
	log       *slog.Logger
	now       func() time.Time
}

// NewWatcher returns a watcher of the templates in dir.
func NewWatcher(st Store, dir string, log *slog.Logger) *Watcher {
	return &Watcher{store: st, templates: dir, log: log, now: time.Now}
}

// Run makes a pass every interval until ctx ends.
func (w *Watcher) Run(ctx context.Context, interval time.Duration) {
	for {
		if _, _, err := w.RunOnce(ctx); err != nil && ctx.Err() == nil {
			w.log.Error("emerging threats", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(interval):
		}
	}
}

// RunOnce records the templates not seen before, then matches the pending
// emerging ones against every verified target's technologies. It returns
// the templates added and the rescans queued.
func (w *Watcher) RunOnce(ctx context.Context) (added, rescans int, err error) {
	templates, err := Index(w.templates)
	if err != nil {
		return 0, 0, err
	}
	rows := make([]store.ThreatTemplate, len(templates))
	for i, t := range templates {
		rows[i] = store.ThreatTemplate{ID: t.ID, CVE: t.CVE, Name: t.Name, Severity: t.Severity,
			Products: t.Products, KEV: t.KEV, EPSS: t.EPSS, New: t.New}
	}
	if added, err = w.store.SyncThreatTemplates(ctx, rows, w.now()); err != nil {
		return 0, 0, err
	}

	for {
		pending, err := w.store.PendingThreats(ctx, batch)
		if err != nil || len(pending) == 0 {
			return added, rescans, err
		}
		targets, err := w.store.VerifiedTargetTechnologies(ctx)
		if err != nil {
			return added, rescans, err
		}
		ids, matches := matchAll(pending, targets)
		n, err := w.store.RecordThreats(ctx, ids, matches, w.now())
		if err != nil {
			return added, rescans, err
		}
		rescans += n
		// Counts only: which customer runs what is customer data.
		w.log.Info("emerging threats matched", "templates", len(ids), "matches", len(matches), "rescans", n)
		if len(pending) < batch {
			return added, rescans, nil
		}
	}
}

// matchAll matches templates against targets.
func matchAll(pending []store.ThreatTemplate, targets []store.TargetTechnologies) ([]string, []store.ThreatMatch) {
	ids := make([]string, 0, len(pending))
	var matches []store.ThreatMatch
	keys := make([][]string, len(targets))
	for i, t := range targets {
		for _, d := range t.Technologies {
			for _, k := range TechKeys(d) {
				if !slices.Contains(keys[i], k) {
					keys[i] = append(keys[i], k)
				}
			}
		}
	}
	for _, p := range pending {
		ids = append(ids, p.ID)
		t := Template{ID: p.ID, Products: p.Products}
		for i, target := range targets {
			if products := Match(t, keys[i]); len(products) > 0 {
				matches = append(matches, store.ThreatMatch{TemplateID: p.ID, TargetID: target.TargetID, Products: products})
			}
		}
	}
	return ids, matches
}
