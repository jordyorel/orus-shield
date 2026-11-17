package api

import (
	"encoding/json"
	"net/http"
	"slices"
	"testing"
	"time"

	"github.com/jordyorel/orus-shield/engine/internal/module"
	"github.com/jordyorel/orus-shield/engine/internal/plan"
)

func planCode(t *testing.T, r response) {
	t.Helper()
	var body struct{ Code string }
	_ = json.Unmarshal(r.body, &body)
	if r.status != http.StatusForbidden || body.Code != codePlanLimit {
		t.Errorf("status %d %s, want 403 plan_limit", r.status, r.body)
	}
}

func auditCode(t *testing.T, r response) {
	t.Helper()
	var body struct{ Code string }
	_ = json.Unmarshal(r.body, &body)
	if r.status != http.StatusForbidden || body.Code != codeAuditUsed {
		t.Errorf("status %d %s, want 403 audit_used", r.status, r.body)
	}
}

func TestAllowedModulesOnGratuit(t *testing.T) {
	e := newEnv(t)
	e.srv.cfg.Modules = append(e.srv.cfg.Modules, "ports")
	e.srv.cfg.Catalog = append(e.srv.cfg.Catalog, module.Info{ID: "ports", Name: "Ports", Kind: module.KindActive})
	free, _ := plan.Get(plan.Discovery)
	pro, _ := plan.Get(plan.Pro)
	if got := e.srv.allowedModules(free); slices.Contains(got, "ports") || len(got) == 0 {
		t.Errorf("Gratuit runs %v, want the passive modules only", got)
	}
	if got := e.srv.allowedModules(pro); !slices.Contains(got, "ports") {
		t.Errorf("Pro runs %v, want ports too", got)
	}
}

func TestPlanLimits(t *testing.T) {
	e := newEnv(t)
	// The catalog gets an active module, for the passive-only offer.
	e.srv.cfg.Modules = append(e.srv.cfg.Modules, "ports")
	e.srv.cfg.Catalog = append(e.srv.cfg.Catalog, module.Info{ID: "ports", Name: "Ports", Kind: module.KindActive})
	a := e.tenant("A", "example.com")
	base := "/api/v1/orgs/" + a.orgID
	e.setPlan(a.orgID, plan.Subscription{Plan: plan.Discovery, Status: plan.Active})
	e.verifyTarget(a.session, a.orgID, a.target.ID)

	// Gratuit: one domain (it has one), a single audit (the fixture's scan
	// was it), no schedule, no report.
	planCode(t, e.do("POST", base+"/targets", a.session, map[string]any{"domain": "second.example"}))
	scans := base + "/targets/" + a.target.ID + "/scans"
	auditCode(t, e.do("POST", scans, a.session, nil))
	auditCode(t, e.do("POST", scans, a.session, map[string]any{"modules": []string{"email"}}))
	fix := base + "/targets/" + a.target.ID + "/findings/" + a.finding.ID + "/status"
	auditCode(t, e.do("PUT", fix, a.session, map[string]any{"status": "fixed"}))
	if r := e.do("PUT", fix, a.session, map[string]any{"status": "accepted_risk"}); r.status != http.StatusNoContent {
		t.Errorf("accepted risk on Gratuit = %d %s", r.status, r.body)
	}
	monthly := map[string]any{"frequency": "monthly", "weekday": 1, "hour": 2, "timezone": "Africa/Brazzaville", "modules": []string{"email"}}
	planCode(t, e.do("PATCH", base+"/targets/"+a.target.ID, a.session, map[string]any{"schedule": monthly}))
	weekly := monthly
	planCode(t, e.do("GET", base+"/report", a.viewer, nil))
	// Two members already (admin and viewer): one is the limit.
	planCode(t, e.do("POST", base+"/members", a.session, map[string]any{"email": "new@example.com", "role": "viewer"}))

	var sub subscriptionJSON
	e.do("GET", base+"/subscription", a.viewer, nil).json(t, &sub)
	if sub.Plan.ID != plan.Discovery || sub.Status != "active" || sub.Usage.Domains != 1 || sub.Usage.Members != 2 ||
		len(sub.Plans) != 4 || sub.Plans[1].USDMonthly == 0 {
		t.Errorf("subscription = %+v", sub)
	}

	// A lapsed trial is Gratuit too, and says so.
	ended := e.now.Add(-time.Hour)
	e.setPlan(a.orgID, plan.Subscription{Plan: plan.SME, Status: plan.Trialing, TrialEndsAt: &ended})
	e.do("GET", base+"/subscription", a.viewer, nil).json(t, &sub)
	if sub.Plan.ID != plan.Discovery || !sub.Lapsed || sub.Status != "trialing" {
		t.Errorf("lapsed trial = %+v", sub)
	}

	// Essentiel: three domains, active modules, weekly.
	end := e.now.AddDate(0, 1, 0)
	e.setPlan(a.orgID, plan.Subscription{Plan: plan.SME, Status: plan.Active, PeriodEnd: &end})
	for _, d := range []string{"second.example", "third.example"} {
		if r := e.do("POST", base+"/targets", a.session, map[string]any{"domain": d}); r.status != http.StatusCreated {
			t.Fatalf("add %s = %d %s", d, r.status, r.body)
		}
	}
	planCode(t, e.do("POST", base+"/targets", a.session, map[string]any{"domain": "fourth.example"}))
	if r := e.do("POST", base+"/targets/"+a.target.ID+"/scans", a.session, map[string]any{"modules": []string{"ports"}}); r.status != http.StatusAccepted {
		t.Errorf("active scan on Essentiel = %d %s", r.status, r.body)
	}
	weekly["frequency"] = "daily"
	planCode(t, e.do("PATCH", base+"/targets/"+a.target.ID, a.session, map[string]any{"schedule": weekly}))
}
