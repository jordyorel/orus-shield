package api

import (
	"context"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jordyorel/orus-shield/engine/internal/finding"
	"github.com/jordyorel/orus-shield/engine/internal/plan"
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

func TestDeepProfile(t *testing.T) {
	e := newEnv(t)
	a := e.tenant("A", "example.com")
	path := "/api/v1/orgs/" + a.orgID + "/settings"
	deep := orgSettingsJSON{AlertLevel: "high", EmailAlerts: true, Profile: "deep", TimeZone: "UTC", DisabledModules: []string{}}

	// Without a consent on record: refused, with a code the dashboard reads.
	r := e.do("PUT", path, a.session, deep)
	if r.status != http.StatusBadRequest || !strings.Contains(string(r.body), "deep_consent_required") {
		t.Fatalf("deep without consent = %d %s", r.status, r.body)
	}
	// With it: recorded, and kept for later changes.
	deep.DeepConsent = true
	var got orgSettingsJSON
	r = e.do("PUT", path, a.session, deep)
	r.json(t, &got)
	if r.status != http.StatusOK || got.Profile != "deep" || got.DeepConsentAt == nil {
		t.Fatalf("deep with consent = %d %s", r.status, r.body)
	}
	deep.DeepConsent = false
	if r := e.do("PUT", path, a.session, deep); r.status != http.StatusOK {
		t.Errorf("deep again, consent on record = %d %s", r.status, r.body)
	}
	if p, err := e.st.ScanProfileOf(context.Background(), a.orgID); err != nil || p != "deep" {
		t.Errorf("worker sees profile %q, %v", p, err)
	}
	// An offer without the deep profile refuses it.
	soon := time.Now().Add(time.Hour)
	e.setPlan(a.orgID, plan.Subscription{Plan: plan.SME, Status: plan.Trialing, TrialEndsAt: &soon})
	if r := e.do("PUT", path, a.session, deep); r.status != http.StatusForbidden || !strings.Contains(string(r.body), "plan_limit") {
		t.Errorf("deep on Essentiel = %d %s", r.status, r.body)
	}
}

func TestDeclaredAPIs(t *testing.T) {
	e := newEnv(t)
	a := e.tenant("A", "example.com")
	path := "/api/v1/orgs/" + a.orgID + "/targets/" + a.target.ID + "/apis"

	ok := createAPIRequest{Name: "Users", Kind: "openapi", BaseURL: "https://api.example.com/v1", SpecURL: "https://api.example.com/openapi.json"}
	if r := e.do("POST", path, a.viewer, ok); r.status != http.StatusForbidden {
		t.Errorf("viewer = %d, want 403", r.status)
	}
	var created apiJSON
	r := e.do("POST", path, a.session, ok)
	r.json(t, &created)
	if r.status != http.StatusCreated || created.ID == "" || created.SpecURL != ok.SpecURL {
		t.Fatalf("create = %d %s", r.status, r.body)
	}
	if r := e.do("POST", path, a.session, ok); r.status != http.StatusConflict {
		t.Errorf("same base URL = %d, want 409", r.status)
	}
	for name, bad := range map[string]createAPIRequest{
		"other domain":        {Name: "x", Kind: "openapi", BaseURL: "https://api.other.org/v1", Spec: "{}"},
		"look-alike":          {Name: "x", Kind: "openapi", BaseURL: "https://evilexample.com/v1", Spec: "{}"},
		"spec elsewhere":      {Name: "x", Kind: "openapi", BaseURL: "https://example.com/v2", SpecURL: "https://raw.github.com/x.json"},
		"credentials in URL":  {Name: "x", Kind: "openapi", BaseURL: "https://user:pw@example.com/v3", Spec: "{}"}, //nolint:gosec // G101: a fake credential, the request the API must refuse
		"openapi without doc": {Name: "x", Kind: "openapi", BaseURL: "https://example.com/v4"},
		"unknown kind":        {Name: "x", Kind: "soap", BaseURL: "https://example.com/v5"},
		"no name":             {Kind: "graphql", BaseURL: "https://example.com/graphql"},
	} {
		if r := e.do("POST", path, a.session, bad); r.status != http.StatusBadRequest {
			t.Errorf("%s = %d %s, want 400", name, r.status, r.body)
		}
	}
	if r := e.do("POST", path, a.session, createAPIRequest{Name: "Graph", Kind: "graphql", BaseURL: "https://example.com/graphql"}); r.status != http.StatusCreated {
		t.Errorf("graphql = %d %s", r.status, r.body)
	}
	var list list[apiJSON]
	e.do("GET", path, a.viewer, nil).json(t, &list)
	if len(list.Items) != 2 {
		t.Errorf("list = %+v", list.Items)
	}
	if r := e.do("DELETE", path+"/"+created.ID, a.session, nil); r.status != http.StatusNoContent {
		t.Errorf("delete = %d", r.status)
	}
	if r := e.do("DELETE", path+"/"+created.ID, a.session, nil); r.status != http.StatusNotFound {
		t.Errorf("delete again = %d, want 404", r.status)
	}
	// Another tenant cannot see or touch them.
	b := e.tenant("B", "example.org")
	other := "/api/v1/orgs/" + b.orgID + "/targets/" + a.target.ID + "/apis"
	if r := e.do("GET", other, b.session, nil); r.status != http.StatusNotFound {
		t.Errorf("cross-tenant list = %d, want 404", r.status)
	}
	// An offer without API scans refuses new ones.
	soon := time.Now().Add(time.Hour)
	e.setPlan(a.orgID, plan.Subscription{Plan: plan.SME, Status: plan.Trialing, TrialEndsAt: &soon})
	if r := e.do("POST", path, a.session, createAPIRequest{Name: "x", Kind: "graphql", BaseURL: "https://example.com/gql"}); r.status != http.StatusForbidden {
		t.Errorf("Essentiel = %d, want 403", r.status)
	}
}

func TestTestAccounts(t *testing.T) {
	e := newEnv(t)
	a := e.tenant("A", "example.com")
	path := "/api/v1/orgs/" + a.orgID + "/targets/" + a.target.ID + "/credential"

	if r := e.do("GET", path, a.session, nil); r.status != http.StatusNotFound {
		t.Errorf("none yet = %d, want 404", r.status)
	}
	header := setCredentialRequest{Kind: "header", HeaderName: "Authorization", HeaderValue: "Bearer s3cret-token", Consent: true}
	if r := e.do("PUT", path, a.viewer, header); r.status != http.StatusForbidden {
		t.Errorf("viewer = %d, want 403", r.status)
	}
	if r := e.do("GET", path, a.viewer, nil); r.status != http.StatusForbidden {
		t.Errorf("viewer read = %d, want 403", r.status)
	}
	noConsent := header
	noConsent.Consent = false
	if r := e.do("PUT", path, a.session, noConsent); r.status != http.StatusBadRequest || !strings.Contains(string(r.body), "consent_required") {
		t.Errorf("without consent = %d %s", r.status, r.body)
	}
	r := e.do("PUT", path, a.session, header)
	if r.status != http.StatusOK || strings.Contains(string(r.body), "s3cret") {
		t.Fatalf("set = %d %s (the secret must never come back)", r.status, r.body)
	}
	r = e.do("GET", path, a.session, nil)
	var got credentialJSON
	r.json(t, &got)
	if got.Kind != "header" || got.HeaderName != "Authorization" || strings.Contains(string(r.body), "s3cret") {
		t.Errorf("get = %s", r.body)
	}
	// Sealed for this target: the worker opens it with the same key.
	c, sealed, err := e.st.TargetCredential(context.Background(), a.target.ID)
	if err != nil || c == nil || strings.Contains(string(sealed), "s3cret") {
		t.Fatalf("stored = %+v %q, %v", c, sealed, err)
	}
	if plain, err := e.srv.creds.Open(sealed, store.CredentialOwner(a.target.ID)); err != nil || string(plain) != "Bearer s3cret-token" {
		t.Errorf("open = %q, %v", plain, err)
	}
	if _, err := e.srv.creds.Open(sealed, store.CredentialOwner("another-target")); err == nil {
		t.Error("a sealed secret opened for another target")
	}
	form := setCredentialRequest{Kind: "form", LoginURL: "https://app.example.com/login", Username: "tester", Password: "pw", Consent: true}
	if r := e.do("PUT", path, a.session, form); r.status != http.StatusOK {
		t.Errorf("form = %d %s", r.status, r.body)
	}
	for name, bad := range map[string]setCredentialRequest{
		"header injection": {Kind: "header", HeaderName: "Authorization", HeaderValue: "x\r\nHost: evil.org", Consent: true},
		"forbidden header": {Kind: "header", HeaderName: "Host", HeaderValue: "evil.org", Consent: true},
		"bad header name":  {Kind: "header", HeaderName: "Auth orization", HeaderValue: "x", Consent: true},
		"login elsewhere":  {Kind: "form", LoginURL: "https://login.other.org/", Username: "u", Password: "p", Consent: true},
		"no password":      {Kind: "form", LoginURL: "https://example.com/login", Username: "u", Consent: true},
		"unknown kind":     {Kind: "oauth", Consent: true},
	} {
		if r := e.do("PUT", path, a.session, bad); r.status != http.StatusBadRequest {
			t.Errorf("%s = %d %s, want 400", name, r.status, r.body)
		}
	}
	if r := e.do("DELETE", path, a.session, nil); r.status != http.StatusNoContent {
		t.Errorf("delete = %d", r.status)
	}
	soon := time.Now().Add(time.Hour)
	e.setPlan(a.orgID, plan.Subscription{Plan: plan.SME, Status: plan.Trialing, TrialEndsAt: &soon})
	if r := e.do("PUT", path, a.session, header); r.status != http.StatusForbidden {
		t.Errorf("Essentiel = %d, want 403", r.status)
	}
}
