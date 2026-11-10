package api

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/jordyorel/orus-shield/engine/internal/finding"
	"github.com/jordyorel/orus-shield/engine/internal/module"
	"github.com/jordyorel/orus-shield/engine/internal/store"
)

func emailCheck(id string, sev finding.Severity, status module.CheckStatus, findings int) module.CheckOutcome {
	return module.CheckOutcome{
		Check:  module.Check{ID: id, Category: module.CategoryEmail, Severity: sev, Title: id},
		Status: status, Findings: findings,
	}
}

func emailFinding(checkID, domain string, sev finding.Severity) finding.Finding {
	return finding.Finding{
		SchemaVersion: finding.SchemaVersion, ModuleID: "email", CheckID: checkID,
		ID: finding.NewID("email", checkID, domain, domain), Target: domain, Asset: domain,
		Severity: sev, Title: "Title of " + checkID, Description: "Description of " + checkID,
	}
}

// emailScan records a finished "email" scan of targetID observed at at.
func (e *env) emailScan(org *store.Org, targetID string, at time.Time, outcomes []module.CheckOutcome, findings ...finding.Finding) {
	e.t.Helper()
	ctx := context.Background()
	if _, err := org.EnqueueScan(ctx, targetID, []string{"email"}, "test"); err != nil {
		e.t.Fatal(err)
	}
	sc, ok, err := e.st.ClaimScan(ctx, "worker:test", time.Minute, 3)
	if err != nil || !ok {
		e.t.Fatalf("claim: %v %v", ok, err)
	}
	if err := e.st.FinishScan(ctx, store.ScanResult{
		ScanID: sc.ID, Attempt: sc.Attempt, WorkerID: "worker:test", At: at,
		Succeeded: []string{"email"}, Findings: findings,
		Checks: map[string][]module.CheckOutcome{"email": outcomes},
	}); err != nil {
		e.t.Fatal(err)
	}
}

func TestOverviewFigures(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	orgID := e.org("Acme")
	org, err := e.st.Org(orgID)
	if err != nil {
		t.Fatal(err)
	}
	e.user("viewer@acme.example", orgID, store.RoleViewer)
	day := 24 * time.Hour
	now := e.now

	// acme.example: DMARC missing three days ago, fixed yesterday.
	acme, err := org.CreateTarget(ctx, store.NewTarget{Domain: "acme.example"})
	if err != nil {
		t.Fatal(err)
	}
	e.emailScan(org, acme.ID, now.Add(-3*day), []module.CheckOutcome{
		emailCheck("dmarc-missing", finding.SeverityHigh, module.CheckFailed, 1),
		emailCheck("spf-missing", finding.SeverityMedium, module.CheckPassed, 0),
	}, emailFinding("dmarc-missing", "acme.example", finding.SeverityHigh))
	e.emailScan(org, acme.ID, now.Add(-1*day), []module.CheckOutcome{
		emailCheck("dmarc-missing", finding.SeverityHigh, module.CheckPassed, 0),
		emailCheck("spf-missing", finding.SeverityMedium, module.CheckPassed, 0),
	})
	// beta.example: a critical finding still open, a high one too.
	beta, err := org.CreateTarget(ctx, store.NewTarget{Domain: "beta.example"})
	if err != nil {
		t.Fatal(err)
	}
	passAll := emailFinding("spf-pass-all", "beta.example", finding.SeverityCritical)
	e.emailScan(org, beta.ID, now.Add(-2*day), []module.CheckOutcome{
		emailCheck("spf-pass-all", finding.SeverityCritical, module.CheckFailed, 1),
		emailCheck("dmarc-missing", finding.SeverityHigh, module.CheckPassed, 0),
	}, passAll)

	var ov overviewJSON
	r := e.do("GET", "/api/v1/orgs/"+orgID+"/overview", e.login("viewer@acme.example"), nil)
	if r.status != http.StatusOK {
		t.Fatalf("overview = %d %s", r.status, r.body)
	}
	r.json(t, &ov)

	// Pooled now: acme 9/9, beta 6/16 -> 15/25 = 60. Three days ago acme
	// alone at 3/9 = 33: +27 over the period.
	if ov.Days != 30 || len(ov.Trend) != 31 || ov.Score == nil || *ov.Score != 60 ||
		ov.ScoreChange == nil || *ov.ScoreChange != 27 {
		t.Errorf("score = %v, change %v, %d days, %d points", ov.Score, ov.ScoreChange, ov.Days, len(ov.Trend))
	}
	if ov.Trend[0].Score != nil || ov.Trend[30].Score == nil || *ov.Trend[30].Score != 60 {
		t.Errorf("trend starts with a score or ends without one: %+v ... %+v", ov.Trend[0], ov.Trend[30])
	}
	rem := ov.Remediation
	if rem.Fixed != 1 || rem.MeanSeconds == nil || *rem.MeanSeconds != (2*day).Seconds() ||
		rem.PreviousFixed != 0 || rem.PreviousMeanSeconds != nil {
		t.Errorf("remediation = %+v", rem)
	}
	if ov.OpenFindings["critical"] != 1 || ov.OpenFindings["high"] != 0 {
		t.Errorf("open findings = %v", ov.OpenFindings)
	}

	// Priorities: the critical finding, then both targets to verify.
	kinds := ""
	for _, p := range ov.Priorities {
		kinds += p.Kind + ":" + p.Domain + " "
	}
	if want := "finding:beta.example verify_target:acme.example verify_target:beta.example "; kinds != want {
		t.Errorf("priorities = %s, want %s", kinds, want)
	}
	if p := ov.Priorities[0]; p.FindingID != passAll.ID || p.Severity != finding.SeverityCritical || p.FirstSeen == nil {
		t.Errorf("finding priority = %+v", p)
	}

	// The period is a parameter, bounded.
	e.do("GET", "/api/v1/orgs/"+orgID+"/overview?days=7", e.login("viewer@acme.example"), nil).json(t, &ov)
	if ov.Days != 7 || len(ov.Trend) != 8 {
		t.Errorf("days=7: %d days, %d points", ov.Days, len(ov.Trend))
	}
	for _, bad := range []string{"0", "366", "abc"} {
		if r := e.do("GET", "/api/v1/orgs/"+orgID+"/overview?days="+bad, e.login("viewer@acme.example"), nil); r.status != http.StatusBadRequest {
			t.Errorf("days=%s = %d, want 400", bad, r.status)
		}
	}
}

func TestOverviewEmptyOrganization(t *testing.T) {
	e := newEnv(t)
	orgID := e.org("Empty")
	e.user("viewer@empty.example", orgID, store.RoleViewer)
	var ov overviewJSON
	r := e.do("GET", "/api/v1/orgs/"+orgID+"/overview", e.login("viewer@empty.example"), nil)
	r.json(t, &ov)
	if r.status != http.StatusOK || ov.Score != nil || ov.ScoreChange != nil || ov.Targets != 0 ||
		ov.Priorities == nil || ov.PerTarget == nil || len(ov.Trend) != 31 {
		t.Errorf("empty overview = %d %+v", r.status, ov)
	}
}
