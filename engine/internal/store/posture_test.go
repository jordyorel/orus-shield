package store

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jordyorel/orus-shield/engine/internal/finding"
	"github.com/jordyorel/orus-shield/engine/internal/module"
)

func outcome(id string, sev finding.Severity, st module.CheckStatus, findings int) module.CheckOutcome {
	return module.CheckOutcome{
		Check:    module.Check{ID: id, Category: module.CategoryEmail, Severity: sev, Title: id},
		Status:   st,
		Findings: findings,
	}
}

// scanChecks runs a scan where "email" succeeded with these outcomes and
// findings, and "tls" failed unless tlsChecks is non-nil.
func (l *lifecycle) scanChecks(at time.Time, email []module.CheckOutcome, tlsChecks []module.CheckOutcome, findings ...finding.Finding) error {
	l.t.Helper()
	ctx := context.Background()
	if _, err := l.org.EnqueueScan(ctx, l.target.ID, []string{"email", "tls"}, "jordy"); err != nil {
		l.t.Fatal(err)
	}
	sc, ok, err := l.s.ClaimScan(ctx, "worker:test", time.Minute, 3)
	if err != nil || !ok {
		l.t.Fatalf("claim: %v, %v", ok, err)
	}
	r := ScanResult{
		ScanID: sc.ID, Attempt: sc.Attempt, WorkerID: "worker:test", At: at,
		Succeeded: []string{"email"}, Failed: map[string]string{}, Findings: findings,
		Checks: map[string][]module.CheckOutcome{"email": email},
	}
	if tlsChecks != nil {
		r.Succeeded = append(r.Succeeded, "tls")
		r.Checks["tls"] = tlsChecks
	} else {
		r.Failed["tls"] = "timeout"
	}
	return l.s.FinishScan(ctx, r)
}

func (l *lifecycle) posture() []PostureSnapshot {
	l.t.Helper()
	snaps, err := l.org.PostureHistory(context.Background(), l.target.ID, 10)
	if err != nil {
		l.t.Fatal(err)
	}
	return snaps
}

func TestPostureFromChecks(t *testing.T) {
	l := newLifecycle(t)
	dmarc := makeFinding("email", "dmarc-missing", "example.com")
	high, med := finding.SeverityHigh, finding.SeverityMedium

	// Scan 1: SPF passes (6), DMARC fails (6), policy not applicable.
	if err := l.scanChecks(t1, []module.CheckOutcome{
		outcome("spf-missing", high, module.CheckPassed, 0),
		outcome("dmarc-missing", high, module.CheckFailed, 1),
		outcome("dmarc-policy-none", med, module.CheckNotApplicable, 0),
	}, nil, dmarc); err != nil {
		t.Fatal(err)
	}
	snaps := l.posture()
	if len(snaps) != 1 || snaps[0].Score == nil || *snaps[0].Score != 50 {
		t.Fatalf("posture = %+v, want one snapshot scoring 50", snaps)
	}
	if got := snaps[0].Details.FailedChecks; len(got) != 1 || got[0] != "dmarc-missing" {
		t.Errorf("failed checks = %v", got)
	}

	// Scan 2: DMARC fixed, and the policy is now evaluated and passes.
	// tls succeeds too, with a failed check of its own.
	if err := l.scanChecks(t2, []module.CheckOutcome{
		outcome("spf-missing", high, module.CheckPassed, 0),
		outcome("dmarc-missing", high, module.CheckPassed, 0),
		outcome("dmarc-policy-none", med, module.CheckPassed, 0),
	}, []module.CheckOutcome{
		{Check: module.Check{ID: "tls-cert-weak-key", Category: module.CategoryTLS, Severity: med, Title: "x"}, Status: module.CheckFailed, Findings: 1},
	}, makeFinding("tls", "tls-cert-weak-key", "example.com")); err != nil {
		t.Fatal(err)
	}
	// passed 6 + 6 + 3 = 15, failed 3: 15 / 18 = 83
	snaps = l.posture()
	if len(snaps) != 2 || *snaps[0].Score != 83 || *snaps[1].Score != 50 {
		t.Errorf("history = %v, %v; want 83 then 50 (newest first)", *snaps[0].Score, *snaps[1].Score)
	}

	// Scan 3: tls fails. Its check keeps its last status, so the score
	// stays computed over everything known.
	if err := l.scanChecks(t3, []module.CheckOutcome{
		outcome("spf-missing", high, module.CheckPassed, 0),
		outcome("dmarc-missing", high, module.CheckPassed, 0),
		outcome("dmarc-policy-none", med, module.CheckPassed, 0),
	}, nil); err != nil {
		t.Fatal(err)
	}
	states, err := l.org.CheckStatuses(context.Background(), l.target.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range states {
		if s.CheckID == "tls-cert-weak-key" && (s.Status != module.CheckFailed || !s.EvaluatedAt.Equal(t2)) {
			t.Errorf("tls check after a failed tls run = %+v, want failed, evaluated at %v", s, t2)
		}
	}
	if got := *l.posture()[0].Score; got != 83 {
		t.Errorf("score = %d, want 83", got)
	}
}

func TestNoSnapshotWithoutEvaluatedChecks(t *testing.T) {
	l := newLifecycle(t)
	// Every module failed: no check outcome, no snapshot.
	l.mustScan(t1, nil, map[string]string{"email": "dns timeout", "tls": "timeout"})
	if snaps := l.posture(); len(snaps) != 0 {
		t.Errorf("snapshots = %+v, want none", snaps)
	}
	// Only not-applicable checks: a snapshot, but no score.
	if err := l.scanChecks(t2, []module.CheckOutcome{
		outcome("dmarc-policy-none", finding.SeverityMedium, module.CheckNotApplicable, 0),
	}, nil); err != nil {
		t.Fatal(err)
	}
	if snaps := l.posture(); len(snaps) != 1 || snaps[0].Score != nil {
		t.Errorf("snapshots = %+v, want one with no score", snaps)
	}
}

func TestFinishScanRejectsInconsistentChecks(t *testing.T) {
	tests := []struct {
		name     string
		checks   []module.CheckOutcome
		findings []finding.Finding
		want     string
	}{
		{"failed without finding", []module.CheckOutcome{outcome("dmarc-missing", finding.SeverityHigh, module.CheckFailed, 1)}, nil, "findings claimed"},
		{"finding but passed", []module.CheckOutcome{outcome("dmarc-missing", finding.SeverityHigh, module.CheckPassed, 0)},
			[]finding.Finding{makeFinding("email", "dmarc-missing", "example.com")}, "findings claimed"},
		{"unknown status", []module.CheckOutcome{outcome("dmarc-missing", finding.SeverityHigh, "maybe", 0)}, nil, "unknown status"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := newLifecycle(t)
			err := l.scanChecks(t1, tt.checks, nil, tt.findings...)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("FinishScan = %v, want error mentioning %q", err, tt.want)
			}
		})
	}
}
