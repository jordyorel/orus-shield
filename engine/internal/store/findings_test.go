package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jordyorel/orus-shield/engine/internal/finding"
)

func makeFinding(moduleID, checkID, domain string) finding.Finding {
	asset := checkID + "." + domain
	return finding.Finding{
		SchemaVersion: finding.SchemaVersion,
		ID:            finding.NewID(moduleID, checkID, domain, asset),
		ModuleID:      moduleID,
		CheckID:       checkID,
		Target:        domain,
		Asset:         asset,
		Severity:      finding.SeverityHigh,
		Title:         "Title of " + checkID,
		Description:   "Description of " + checkID,
	}
}

// lifecycle runs successive scans on one target and inspects the result.
type lifecycle struct {
	t      *testing.T
	s      *Store
	org    *Org
	target Target
}

func newLifecycle(t *testing.T) *lifecycle {
	s := newTestStore(t)
	return &lifecycle{t: t, s: s, org: defaultOrg(t, s), target: newTarget(t, s, "example.com")}
}

// scan enqueues, claims and finishes a scan with the given results.
func (l *lifecycle) scan(at time.Time, succeeded []string, failed map[string]string, findings ...finding.Finding) error {
	l.t.Helper()
	ctx := context.Background()
	if _, err := l.org.EnqueueScan(ctx, l.target.ID, []string{"email", "tls"}, "jordy"); err != nil {
		l.t.Fatal(err)
	}
	sc, ok, err := l.s.ClaimScan(ctx, "worker:test", time.Minute, 3)
	if err != nil || !ok {
		l.t.Fatalf("claim: %v, %v", ok, err)
	}
	return l.s.FinishScan(ctx, ScanResult{
		ScanID: sc.ID, Attempt: sc.Attempt, WorkerID: "worker:test", At: at,
		Succeeded: succeeded, Failed: failed, Findings: findings,
	})
}

func (l *lifecycle) mustScan(at time.Time, succeeded []string, failed map[string]string, findings ...finding.Finding) {
	l.t.Helper()
	if err := l.scan(at, succeeded, failed, findings...); err != nil {
		l.t.Fatalf("FinishScan: %v", err)
	}
}

// state returns the stored findings by check ID.
func (l *lifecycle) state() map[string]finding.Finding {
	l.t.Helper()
	findings, err := l.org.ListFindings(context.Background(), l.target.ID)
	if err != nil {
		l.t.Fatalf("ListFindings: %v", err)
	}
	out := make(map[string]finding.Finding)
	for _, f := range findings {
		out[f.CheckID] = f
	}
	return out
}

// expect checks status, first and last seen of one finding, in the JSON copy
// and in the columns.
func (l *lifecycle) expect(checkID string, status finding.Status, first, last time.Time) {
	l.t.Helper()
	f, ok := l.state()[checkID]
	if !ok {
		l.t.Fatalf("finding %s not stored", checkID)
	}
	if f.Status != status || !f.FirstSeen.Equal(first) || !f.LastSeen.Equal(last) {
		l.t.Errorf("%s: status %s, first %v, last %v; want %s, %v, %v",
			checkID, f.Status, f.FirstSeen, f.LastSeen, status, first, last)
	}
	var colStatus string
	var colFirst, colLast time.Time
	err := l.s.pool.QueryRow(context.Background(),
		"SELECT status, first_seen, last_seen FROM findings WHERE target_id = $1 AND id = $2",
		l.target.ID, f.ID).Scan(&colStatus, &colFirst, &colLast)
	if err != nil {
		l.t.Fatal(err)
	}
	if colStatus != string(f.Status) || !colFirst.Equal(f.FirstSeen) || !colLast.Equal(f.LastSeen) {
		l.t.Errorf("%s: columns (%s, %v, %v) disagree with JSON (%s, %v, %v)",
			checkID, colStatus, colFirst, colLast, f.Status, f.FirstSeen, f.LastSeen)
	}
}

var (
	t1 = time.Date(2026, 11, 1, 10, 0, 0, 0, time.UTC)
	t2 = t1.Add(24 * time.Hour)
	t3 = t2.Add(24 * time.Hour)
	t4 = t3.Add(24 * time.Hour)
)

func TestFindingLifecycle(t *testing.T) {
	l := newLifecycle(t)
	spf := makeFinding("email", "spf-missing", "example.com")
	dmarc := makeFinding("email", "dmarc-missing", "example.com")
	both := []string{"email", "tls"}

	// Scan 1: two new findings.
	l.mustScan(t1, both, nil, spf, dmarc)
	l.expect("spf-missing", finding.StatusOpen, t1, t1)
	l.expect("dmarc-missing", finding.StatusOpen, t1, t1)

	// Scan 2: only SPF is still there. DMARC was fixed.
	l.mustScan(t2, both, nil, spf)
	l.expect("spf-missing", finding.StatusOpen, t1, t2)
	l.expect("dmarc-missing", finding.StatusFixed, t1, t1)

	// Scan 3: DMARC is back: a regression reopens it, first_seen is kept.
	l.mustScan(t3, both, nil, spf, dmarc)
	l.expect("dmarc-missing", finding.StatusOpen, t1, t3)
}

func TestAcceptedRiskIsNeverChangedByScans(t *testing.T) {
	l := newLifecycle(t)
	ctx := context.Background()
	spf := makeFinding("email", "spf-missing", "example.com")
	l.mustScan(t1, []string{"email"}, nil, spf)

	if err := l.org.SetFindingStatus(ctx, l.target.ID, spf.ID, finding.StatusAcceptedRisk, "jordy"); err != nil {
		t.Fatalf("SetFindingStatus: %v", err)
	}
	l.expect("spf-missing", finding.StatusAcceptedRisk, t1, t1)

	// Seen again: stays accepted, last_seen moves.
	l.mustScan(t2, []string{"email"}, nil, spf)
	l.expect("spf-missing", finding.StatusAcceptedRisk, t1, t2)

	// Not seen: stays accepted, not marked fixed.
	l.mustScan(t3, []string{"email"}, nil)
	l.expect("spf-missing", finding.StatusAcceptedRisk, t1, t2)

	audit := actions(t, l.s, "example.com")
	found := false
	for _, a := range audit {
		found = found || a == "jordy "+ActionFindingStatus
	}
	if !found {
		t.Errorf("audit %v has no status change by jordy", audit)
	}
}

// A module that failed says nothing about its findings: they stay open.
func TestFailedModuleDoesNotFixItsFindings(t *testing.T) {
	l := newLifecycle(t)
	spf := makeFinding("email", "spf-missing", "example.com")
	tlsFinding := makeFinding("tls", "tls-cert-expired", "example.com")
	l.mustScan(t1, []string{"email", "tls"}, nil, spf, tlsFinding)

	// The TLS module times out; email succeeds and finds nothing.
	l.mustScan(t2, []string{"email"}, map[string]string{"tls": "timeout"})
	l.expect("spf-missing", finding.StatusFixed, t1, t1)
	l.expect("tls-cert-expired", finding.StatusOpen, t1, t1)

	// Everything failed: nothing changes.
	l.mustScan(t3, nil, map[string]string{"email": "dns timeout", "tls": "timeout"})
	l.expect("tls-cert-expired", finding.StatusOpen, t1, t1)
}

func TestFinishScanIsAllOrNothing(t *testing.T) {
	l := newLifecycle(t)
	good := makeFinding("email", "spf-missing", "example.com")
	bad := makeFinding("email", "dmarc-missing", "example.com")
	bad.Severity = "severe"

	if err := l.scan(t1, []string{"email"}, nil, good, bad); err == nil {
		t.Fatal("FinishScan with an invalid finding = nil, want error")
	}
	if n := len(l.state()); n != 0 {
		t.Errorf("%d findings stored after a failed FinishScan, want 0", n)
	}

	other := makeFinding("email", "spf-missing", "other.example")
	if err := l.scan(t2, []string{"email"}, nil, other); err == nil {
		t.Error("FinishScan with a finding for another domain = nil, want error")
	}
}

func TestFinishScanIsFenced(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	target := newTarget(t, s, "example.com")
	enqueue(t, s, target, "email")
	sc, _, err := s.ClaimScan(ctx, "worker:a", time.Minute, 3)
	if err != nil {
		t.Fatal(err)
	}
	err = s.FinishScan(ctx, ScanResult{
		ScanID: sc.ID, Attempt: sc.Attempt + 1, WorkerID: "worker:a", At: t1,
		Succeeded: []string{"email"}, Findings: []finding.Finding{makeFinding("email", "spf-missing", "example.com")},
	})
	if !errors.Is(err, ErrLeaseLost) {
		t.Fatalf("FinishScan with a stale attempt = %v, want ErrLeaseLost", err)
	}
	findings, err := defaultOrg(t, s).ListFindings(ctx, target.ID)
	if err != nil || len(findings) != 0 {
		t.Errorf("findings after fenced FinishScan = %v, %v; want none", findings, err)
	}
}

func TestFinishScanRecordsOutcome(t *testing.T) {
	l := newLifecycle(t)
	l.mustScan(t1, []string{"email"}, map[string]string{"tls": "connection refused"},
		makeFinding("email", "spf-missing", "example.com"))

	var status, errMsg string
	err := l.s.pool.QueryRow(context.Background(),
		"SELECT status, coalesce(error, '') FROM scans ORDER BY created_at DESC LIMIT 1").Scan(&status, &errMsg)
	if err != nil {
		t.Fatal(err)
	}
	if status != StatusDone || errMsg != "tls: connection refused" {
		t.Errorf("scan status %q, error %q", status, errMsg)
	}
	audit := actions(t, l.s, "example.com")
	if audit[len(audit)-1] != "worker:test "+ActionScanFinished {
		t.Errorf("last audit entry = %q, want scan.finished", audit[len(audit)-1])
	}
}

func TestListFindingsOrder(t *testing.T) {
	l := newLifecycle(t)
	low := makeFinding("email", "dmarc-no-reporting", "example.com")
	low.Severity = finding.SeverityLow
	critical := makeFinding("email", "spf-pass-all", "example.com")
	critical.Severity = finding.SeverityCritical
	l.mustScan(t4, []string{"email"}, nil, low, critical)

	findings, err := l.org.ListFindings(context.Background(), l.target.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 2 || findings[0].CheckID != "spf-pass-all" {
		t.Errorf("order = %v, want critical first", findings)
	}
}

func TestSetFindingStatusRejects(t *testing.T) {
	l := newLifecycle(t)
	ctx := context.Background()
	spf := makeFinding("email", "spf-missing", "example.com")
	l.mustScan(t1, []string{"email"}, nil, spf)

	if err := l.org.SetFindingStatus(ctx, l.target.ID, spf.ID, finding.StatusFixed, "jordy"); err == nil {
		t.Error("manual fixed = nil, want error: only scans mark findings fixed")
	}
	if err := l.org.SetFindingStatus(ctx, l.target.ID, "unknown", finding.StatusAcceptedRisk, "jordy"); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown finding = %v, want ErrNotFound", err)
	}
}
