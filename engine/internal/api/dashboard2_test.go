package api

import (
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/jordyorel/orus-shield/engine/internal/finding"
	"github.com/jordyorel/orus-shield/engine/internal/store"
)

// Tests of the routes the 2026-11-12 dashboard needs: profile, sessions,
// activity, organization settings, enriched findings, public offers.

func TestProfileAndSessions(t *testing.T) {
	e := newEnv(t)
	orgID := e.org("Acme")
	e.user("alice@example.com", orgID, store.RoleViewer)
	first := e.login("alice@example.com")
	second := e.login("alice@example.com")

	var me meResponse
	r := e.do("PATCH", "/api/v1/auth/me", first, updateMeRequest{Name: ptrTo("  Alice Martin ")})
	r.json(t, &me)
	if r.status != http.StatusOK || me.Name != "Alice Martin" || me.PasswordChangedAt == nil {
		t.Errorf("update me = %d %+v", r.status, me)
	}
	if r := e.do("PATCH", "/api/v1/auth/me", first, updateMeRequest{Name: ptrTo(strings.Repeat("a", 101))}); r.status != http.StatusBadRequest {
		t.Errorf("long name = %d, want 400", r.status)
	}
	if r := e.do("PATCH", "/api/v1/auth/me", first, updateMeRequest{Name: ptrTo("a\x00b")}); r.status != http.StatusBadRequest {
		t.Errorf("control character = %d, want 400", r.status)
	}

	var sessions list[sessionJSON]
	e.do("GET", "/api/v1/auth/sessions", first, nil).json(t, &sessions)
	if len(sessions.Items) != 2 || !sessions.Items[0].Current || sessions.Items[1].Current {
		t.Fatalf("sessions = %+v, want the current one first", sessions.Items)
	}
	other := sessions.Items[1].ID

	// Another user cannot end Alice's session.
	e.user("bob@example.com", orgID, store.RoleViewer)
	if r := e.do("DELETE", "/api/v1/auth/sessions/"+other, e.login("bob@example.com"), nil); r.status != http.StatusNotFound {
		t.Errorf("other user's session = %d, want 404", r.status)
	}
	if r := e.do("DELETE", "/api/v1/auth/sessions/"+other, first, nil); r.status != http.StatusNoContent {
		t.Fatalf("end session = %d %s", r.status, r.body)
	}
	if r := e.do("GET", "/api/v1/auth/me", second, nil); r.status != http.StatusUnauthorized {
		t.Errorf("ended session still works: %d", r.status)
	}
	if r := e.do("DELETE", "/api/v1/auth/sessions/not-a-uuid", first, nil); r.status != http.StatusNotFound {
		t.Errorf("bad id = %d, want 404", r.status)
	}

	var activity list[authActivityJSON]
	e.do("GET", "/api/v1/auth/activity", first, nil).json(t, &activity)
	var actions []string
	for _, a := range activity.Items {
		actions = append(actions, a.Action)
	}
	if !slices.Contains(actions, "login.ok") || !slices.Contains(actions, "session.ended") || !slices.Contains(actions, "profile.name_changed") {
		t.Errorf("activity = %v", actions)
	}
}

func TestOrgSettings(t *testing.T) {
	e := newEnv(t)
	a := e.tenant("A", "example.com")
	path := "/api/v1/orgs/" + a.orgID + "/settings"

	var got orgSettingsJSON
	e.do("GET", path, a.viewer, nil).json(t, &got)
	if got.AlertLevel != "high" || !got.EmailAlerts || got.Profile != "standard" || got.Frequency != "" {
		t.Errorf("defaults = %+v", got)
	}
	want := orgSettingsJSON{AlertLevel: "critical", EmailAlerts: true, Profile: "quick", DisabledModules: []string{"email"},
		Frequency: "weekly", Weekday: 6, Hour: 2, TimeZone: "Africa/Brazzaville", RatePerSec: 50}
	if r := e.do("PUT", path, a.viewer, want); r.status != http.StatusForbidden {
		t.Errorf("viewer = %d, want 403", r.status)
	}
	if r := e.do("PUT", path, a.session, want); r.status != http.StatusOK {
		t.Fatalf("put = %d %s", r.status, r.body)
	}
	// Applied to the target: weekly, without email (off) and vulns (quick).
	var tj targetJSON
	e.do("GET", "/api/v1/orgs/"+a.orgID+"/targets/"+a.target.ID, a.session, nil).json(t, &tj)
	if tj.Schedule == nil || tj.Schedule.Frequency != "weekly" || slices.Contains(tj.Schedule.Modules, "email") ||
		slices.Contains(tj.Schedule.Modules, "vulns") || tj.RatePerSec != 50 {
		t.Errorf("target after settings = %+v %+v", tj, tj.Schedule)
	}
	for _, bad := range []orgSettingsJSON{
		{AlertLevel: "loud", Profile: "standard", TimeZone: "UTC"},
		{AlertLevel: "high", Profile: "deep", TimeZone: "UTC"},
		{AlertLevel: "high", Profile: "standard", TimeZone: "UTC", DisabledModules: []string{"discovery"}},
		{AlertLevel: "high", Profile: "standard", TimeZone: "Mars/Olympus"},
		{AlertLevel: "high", Profile: "standard", TimeZone: "UTC", Frequency: "hourly"},
		{AlertLevel: "high", Profile: "standard", TimeZone: "UTC", RatePerSec: 500},
	} {
		if r := e.do("PUT", path, a.session, bad); r.status != http.StatusBadRequest {
			t.Errorf("%+v = %d, want 400", bad, r.status)
		}
	}
}

func TestActivityAndEnrichedFindings(t *testing.T) {
	e := newEnv(t)
	a := e.tenant("A", "example.com")

	var act list[activityJSON]
	e.do("GET", "/api/v1/orgs/"+a.orgID+"/activity", a.viewer, nil).json(t, &act)
	var kinds []store.ActivityKind
	for _, x := range act.Items {
		kinds = append(kinds, x.Kind)
	}
	if !slices.Contains(kinds, store.ActivityFinding) || !slices.Contains(kinds, store.ActivityScan) {
		t.Errorf("activity = %+v", act.Items)
	}

	var fs list[orgFinding]
	e.do("GET", "/api/v1/orgs/"+a.orgID+"/findings", a.viewer, nil).json(t, &fs)
	if len(fs.Items) != 1 {
		t.Fatalf("findings = %+v", fs.Items)
	}
	f := fs.Items[0]
	// dmarc-missing failed, spf-missing passed (both high): 50 now, 100
	// once fixed.
	if f.Minutes != 15 || f.Gain != 50 || f.Category != "email" || f.CVE != nil {
		t.Errorf("extras = %+v", f.findingExtras)
	}
}

func TestParseCVE(t *testing.T) {
	f := finding.Finding{References: []string{"CWE-79", "CVE-2024-6387"},
		Evidence: "template: x\ncvss: 8.1\nepss: 0.4200\nknown exploited: yes (CISA KEV catalog)\n"}
	c := parseCVE(f)
	if c == nil || c.ID != "CVE-2024-6387" || c.CVSS == nil || *c.CVSS != 8.1 || c.EPSS == nil || *c.EPSS != 0.42 || !c.KEV {
		t.Errorf("parseCVE = %+v", c)
	}
	if parseCVE(finding.Finding{Evidence: "cvss: 99\n"}) != nil {
		t.Error("an out-of-range CVSS is ignored")
	}
}

func TestPublicPlans(t *testing.T) {
	e := newEnv(t)
	var plans list[planJSON]
	r := e.do("GET", "/api/v1/plans", "", nil)
	r.json(t, &plans)
	if r.status != http.StatusOK || len(plans.Items) != 4 || plans.Items[0].Name != "Gratuit" || plans.Items[1].Name != "Essentiel" {
		t.Errorf("plans = %d %+v", r.status, plans.Items)
	}
}

func ptrTo[T any](v T) *T { return &v }
