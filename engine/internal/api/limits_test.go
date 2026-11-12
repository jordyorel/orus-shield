package api

import (
	"encoding/json"
	"net/http"
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

func TestPlanLimits(t *testing.T) {
	e := newEnv(t)
	// The catalog gets an active module, for the passive-only offer.
	e.srv.cfg.Modules = append(e.srv.cfg.Modules, "ports")
	e.srv.cfg.Catalog = append(e.srv.cfg.Catalog, module.Info{ID: "ports", Name: "Ports", Kind: module.KindActive})
	a := e.tenant("A", "example.com")
	base := "/api/v1/orgs/" + a.orgID
	e.setPlan(a.orgID, plan.Subscription{Plan: plan.Discovery, Status: plan.Active})

	// Gratuit: one domain (it has one), passive checks, monthly, no report.
	planCode(t, e.do("POST", base+"/targets", a.session, map[string]any{"domain": "second.example"}))
	planCode(t, e.do("POST", base+"/targets/"+a.target.ID+"/scans", a.session, map[string]any{"modules": []string{"email", "ports"}}))
	if r := e.do("POST", base+"/targets/"+a.target.ID+"/scans", a.session, map[string]any{"modules": []string{"email"}}); r.status != http.StatusAccepted {
		t.Errorf("passive scan = %d %s", r.status, r.body)
	}
	weekly := map[string]any{"frequency": "weekly", "weekday": 1, "hour": 2, "timezone": "Africa/Brazzaville", "modules": []string{"email"}}
	planCode(t, e.do("PATCH", base+"/targets/"+a.target.ID, a.session, map[string]any{"schedule": weekly}))
	weekly["frequency"] = "monthly"
	if r := e.do("PATCH", base+"/targets/"+a.target.ID, a.session, map[string]any{"schedule": weekly}); r.status != http.StatusOK {
		t.Errorf("monthly schedule = %d %s", r.status, r.body)
	}
	planCode(t, e.do("GET", base+"/report", a.viewer, nil))
	// Two members already (admin and viewer): one is the limit.
	planCode(t, e.do("POST", base+"/members", a.session, map[string]any{"email": "new@example.com", "role": "viewer"}))

	var sub subscriptionJSON
	e.do("GET", base+"/subscription", a.viewer, nil).json(t, &sub)
	if sub.Plan.ID != plan.Discovery || sub.Status != "active" || sub.Usage.Domains != 1 || sub.Usage.Members != 2 ||
		len(sub.Plans) != 4 || sub.Plans[1].XAFMonthly == 0 {
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
