package store

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jordyorel/orus-shield/engine/internal/finding"
)

// history returns the kinds and times of a finding's events.
func (l *lifecycle) history(f finding.Finding) []FindingEvent {
	l.t.Helper()
	events, err := l.org.FindingHistory(context.Background(), l.target.ID, f.ID)
	if err != nil {
		l.t.Fatalf("FindingHistory: %v", err)
	}
	return events
}

// fixedAt returns the fixed_at of a finding, from the column and from the
// JSON copy, failing if they disagree.
func (l *lifecycle) fixedAt(f finding.Finding) *time.Time {
	l.t.Helper()
	var col *time.Time
	if err := l.s.pool.QueryRow(context.Background(),
		"SELECT fixed_at FROM findings WHERE target_id = $1 AND id = $2", l.target.ID, f.ID).Scan(&col); err != nil {
		l.t.Fatal(err)
	}
	json := l.state()[f.CheckID].FixedAt
	if (col == nil) != (json == nil) || (col != nil && !col.Equal(*json)) {
		l.t.Errorf("fixed_at column %v and JSON %v disagree", col, json)
	}
	return col
}

func kinds(events []FindingEvent) string {
	var out []string
	for _, e := range events {
		out = append(out, e.Kind()+"@"+e.At.UTC().Format("01-02"))
	}
	return strings.Join(out, " ")
}

func TestFindingHistoryFromScans(t *testing.T) {
	l := newLifecycle(t)
	spf := makeFinding("email", "spf-missing", "example.com")
	email := []string{"email"}

	l.mustScan(t1, email, nil, spf) // opened
	if got := l.fixedAt(spf); got != nil {
		t.Errorf("open finding has fixed_at %v", got)
	}
	l.mustScan(t2, email, nil) // fixed
	if got := l.fixedAt(spf); got == nil || !got.Equal(t2) {
		t.Errorf("fixed_at = %v, want %v (the scan that stopped seeing it)", got, t2)
	}
	l.mustScan(t3, email, nil, spf) // reopened
	if got := l.fixedAt(spf); got != nil {
		t.Errorf("reopened finding keeps fixed_at %v", got)
	}
	l.mustScan(t4, email, nil, spf)              // seen again: no event
	l.mustScan(t4.Add(24*time.Hour), email, nil) // fixed again

	events := l.history(spf)
	if got, want := kinds(events), "opened@11-01 fixed@11-02 reopened@11-03 fixed@11-05"; got != want {
		t.Errorf("history = %s, want %s", got, want)
	}
	for _, e := range events {
		if e.Actor != "worker:test" || e.ScanID == "" || e.OrgID != l.org.ID() {
			t.Errorf("scan event %+v must name the worker, the scan and the organization", e)
		}
	}
	var reopened int
	err := l.s.pool.QueryRow(context.Background(), `SELECT count(*) FROM audit_log
		WHERE action = $1 AND (details->>'reopened')::int = 1`, ActionScanFinished).Scan(&reopened)
	if err != nil || reopened != 1 {
		t.Errorf("scan.finished entries counting one reopened finding = %d, %v; want 1", reopened, err)
	}
}

func TestFindingHistoryManualChanges(t *testing.T) {
	l := newLifecycle(t)
	ctx := context.Background()
	spf := makeFinding("email", "spf-missing", "example.com")
	l.mustScan(t1, []string{"email"}, nil, spf)
	l.mustScan(t2, []string{"email"}, nil) // fixed

	// Accepting the risk of a fixed finding: it is no longer fixed.
	if err := l.org.SetFindingStatus(ctx, l.target.ID, spf.ID, finding.StatusAcceptedRisk, "user:alice"); err != nil {
		t.Fatal(err)
	}
	if got := l.fixedAt(spf); got != nil {
		t.Errorf("accepted finding keeps fixed_at %v", got)
	}
	// The same decision twice records one event.
	if err := l.org.SetFindingStatus(ctx, l.target.ID, spf.ID, finding.StatusAcceptedRisk, "user:alice"); err != nil {
		t.Fatal(err)
	}
	if err := l.org.SetFindingStatus(ctx, l.target.ID, spf.ID, finding.StatusOpen, "user:bob"); err != nil {
		t.Fatal(err)
	}

	events := l.history(spf)
	var got []string
	for _, e := range events {
		got = append(got, e.Kind()+" by "+e.Actor)
	}
	want := "opened by worker:test, fixed by worker:test, risk_accepted by user:alice, risk_withdrawn by user:bob"
	if strings.Join(got, ", ") != want {
		t.Errorf("history = %s, want %s", strings.Join(got, ", "), want)
	}
	if last := events[len(events)-1]; last.ScanID != "" || last.At.IsZero() {
		t.Errorf("manual event %+v: want no scan and a time", last)
	}
}

// The database refuses a fixed finding without fixed_at, and the reverse.
func TestFixedAtConstraint(t *testing.T) {
	l := newLifecycle(t)
	spf := makeFinding("email", "spf-missing", "example.com")
	l.mustScan(t1, []string{"email"}, nil, spf)
	for _, stmt := range []string{
		"UPDATE findings SET status = 'fixed'",
		"UPDATE findings SET fixed_at = now()",
	} {
		_, err := l.s.pool.Exec(context.Background(), stmt)
		if err == nil || !strings.Contains(err.Error(), "fixed_at_iff_fixed") {
			t.Errorf("%s = %v, want the fixed_at_iff_fixed constraint", stmt, err)
		}
	}
}

// Migration 0004 gives existing fixed findings a fixed_at and reconstructs a
// minimal history.
func TestFindingHistoryMigrationBackfill(t *testing.T) {
	s := newEmptyTestStore(t)
	ctx := context.Background()
	if err := s.migrate(ctx, "0003_organizations"); err != nil {
		t.Fatal(err)
	}
	org := defaultOrg(t, s)
	target, err := org.CreateTarget(ctx, NewTarget{Domain: "orushield.xyz"})
	if err != nil {
		t.Fatal(err)
	}
	scanEnd := t3
	for _, stmt := range []string{
		"INSERT INTO scans (org_id, target_id, modules, requested_by, status, finished_at) VALUES ($1, $2, '{email}', 'x', 'done', '" + scanEnd.Format(time.RFC3339) + "')",
		"INSERT INTO findings (org_id, target_id, id, module_id, check_id, severity, status, first_seen, last_seen, data) " +
			"VALUES ($1, $2, 'gone', 'email', 'spf-missing', 'high', 'fixed', '" + t1.Format(time.RFC3339) + "', '" + t2.Format(time.RFC3339) + "', '{\"status\": \"fixed\"}')",
		"INSERT INTO findings (org_id, target_id, id, module_id, check_id, severity, status, first_seen, last_seen, data) " +
			"VALUES ($1, $2, 'still', 'email', 'dmarc-missing', 'high', 'open', '" + t1.Format(time.RFC3339) + "', '" + t3.Format(time.RFC3339) + "', '{}')",
	} {
		if _, err := s.pool.Exec(ctx, stmt, org.ID(), target.ID); err != nil {
			t.Fatalf("%s: %v", stmt, err)
		}
	}
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	var fixedAt time.Time
	var jsonFixedAt string
	if err := s.pool.QueryRow(ctx, "SELECT fixed_at, data->>'fixed_at' FROM findings WHERE id = 'gone'").Scan(&fixedAt, &jsonFixedAt); err != nil {
		t.Fatal(err)
	}
	if !fixedAt.Equal(scanEnd) || jsonFixedAt == "" {
		t.Errorf("backfilled fixed_at = %v (JSON %q), want %v, the next finished scan", fixedAt, jsonFixedAt, scanEnd)
	}
	for id, want := range map[string]string{"gone": "opened@11-01 fixed@11-03", "still": "opened@11-01"} {
		events, err := org.FindingHistory(ctx, target.ID, id)
		if err != nil {
			t.Fatal(err)
		}
		if got := kinds(events); got != want {
			t.Errorf("%s history = %s, want %s", id, got, want)
		}
		for _, e := range events {
			if e.Actor != "migration:0004" {
				t.Errorf("reconstructed event actor = %q, want migration:0004", e.Actor)
			}
		}
	}
}
