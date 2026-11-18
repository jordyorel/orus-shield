package api

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jordyorel/orus-shield/engine/internal/plan"
)

// keyDo calls the API with an API key instead of a session, as a script
// would: no cookie, no browser headers.
func (e *env) keyDo(method, path, key string, body any) response {
	e.t.Helper()
	return e.doHeaders(method, path, map[string]string{"Authorization": "Bearer " + key}, body)
}

func (e *env) newKey(orgID, session, scope string) (apiKeyJSON, string) {
	e.t.Helper()
	var created struct {
		Key    apiKeyJSON `json:"key"`
		Secret string     `json:"secret"`
	}
	r := e.do("POST", "/api/v1/orgs/"+orgID+"/apikeys", session, createKeyRequest{Name: "CI " + scope, Scope: scope})
	r.json(e.t, &created)
	if r.status != http.StatusCreated || !strings.HasPrefix(created.Secret, "orus_") || created.Key.Prefix != created.Secret[:12] {
		e.t.Fatalf("create key = %d %s", r.status, r.body)
	}
	return created.Key, created.Secret
}

func TestAPIKeys(t *testing.T) {
	e := newEnv(t)
	a := e.tenant("A", "example.com")
	b := e.tenant("B", "example.org")
	base := "/api/v1/orgs/" + a.orgID

	_, read := e.newKey(a.orgID, a.session, "read")
	writeKey, write := e.newKey(a.orgID, a.session, "write")

	// The key itself is never shown again.
	r := e.do("GET", base+"/apikeys", a.session, nil)
	if r.status != http.StatusOK || strings.Contains(string(r.body), read) || strings.Contains(string(r.body), write) {
		t.Fatalf("list = %d %s", r.status, r.body)
	}
	// Viewers cannot manage keys.
	if r := e.do("GET", base+"/apikeys", a.viewer, nil); r.status != http.StatusForbidden {
		t.Errorf("viewer lists keys = %d, want 403", r.status)
	}

	// A read key reads its organization's results.
	for _, p := range []string{"/overview", "/findings", "/assets", "/targets", "/checks"} {
		if r := e.keyDo("GET", base+p, read, nil); r.status != http.StatusOK {
			t.Errorf("GET %s with a key = %d %s", p, r.status, r.body)
		}
	}
	// ...but cannot write, and nobody's key reaches another organization.
	status := base + "/targets/" + a.target.ID + "/findings/" + a.finding.ID + "/status"
	if r := e.keyDo("PUT", status, read, map[string]string{"status": "accepted_risk"}); r.status != http.StatusForbidden {
		t.Errorf("read key writes = %d, want 403", r.status)
	}
	if r := e.keyDo("GET", "/api/v1/orgs/"+b.orgID+"/findings", write, nil); r.status != http.StatusNotFound {
		t.Errorf("key on another organization = %d, want 404", r.status)
	}
	// A write key marks a finding, recorded in its name.
	if r := e.keyDo("PUT", status, write, map[string]string{"status": "accepted_risk"}); r.status != http.StatusNoContent && r.status != http.StatusOK {
		t.Errorf("write key marks a finding = %d %s", r.status, r.body)
	}

	// Never with a key: members, billing, settings, test accounts, keys.
	for _, c := range []struct{ method, path string }{
		{"GET", base + "/members"},
		{"PUT", base + "/settings"},
		{"POST", base + "/checkout"},
		{"GET", base + "/targets/" + a.target.ID + "/credential"},
		{"POST", base + "/apikeys"},
		{"GET", base + "/audit"},
	} {
		if r := e.keyDo(c.method, c.path, write, map[string]string{}); r.status != http.StatusUnauthorized {
			t.Errorf("%s %s with a key = %d, want 401", c.method, c.path, r.status)
		}
	}

	// Unknown and revoked keys: 401.
	if r := e.keyDo("GET", base+"/overview", "orus_nope", nil); r.status != http.StatusUnauthorized {
		t.Errorf("unknown key = %d", r.status)
	}
	if r := e.do("DELETE", base+"/apikeys/"+writeKey.ID, a.session, nil); r.status != http.StatusNoContent {
		t.Fatalf("revoke = %d %s", r.status, r.body)
	}
	if r := e.keyDo("GET", base+"/overview", write, nil); r.status != http.StatusUnauthorized {
		t.Errorf("revoked key = %d, want 401", r.status)
	}

	// The offer decides at every call: on Essentiel the key stops working.
	e.setPlan(a.orgID, plan.Subscription{Plan: plan.SME, Status: plan.Active})
	if r := e.keyDo("GET", base+"/overview", read, nil); r.status != http.StatusForbidden || !strings.Contains(string(r.body), "plan_limit") {
		t.Errorf("key on Essentiel = %d %s", r.status, r.body)
	}
	if r := e.do("POST", base+"/apikeys", a.session, createKeyRequest{Name: "x", Scope: "read"}); r.status != http.StatusForbidden {
		t.Errorf("create on Essentiel = %d, want 403", r.status)
	}
}

func TestKeyLimiter(t *testing.T) {
	var l keyLimiter
	now := time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)
	for i := 0; i < keyRate; i++ {
		if !l.allow("k", now) {
			t.Fatalf("request %d refused", i)
		}
	}
	if l.allow("k", now.Add(30*time.Second)) {
		t.Error("over the rate in the same minute")
	}
	if !l.allow("other", now) {
		t.Error("another key was limited")
	}
	if !l.allow("k", now.Add(time.Minute)) {
		t.Error("the next minute was refused")
	}
}
