package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/jordyorel/orus-shield/engine/internal/store"
)

func TestModulesAndRecentScans(t *testing.T) {
	e := newEnv(t)
	a := e.tenant("A", "example.com")
	base := "/api/v1/orgs/" + a.orgID

	var mods list[moduleJSON]
	e.do("GET", base+"/modules", a.viewer, nil).json(t, &mods)
	if len(mods.Items) != 2 || mods.Items[0] != (moduleJSON{ID: "email", Name: "Email security", Kind: "passive"}) {
		t.Errorf("modules = %+v", mods.Items)
	}

	var scans list[scanJSON]
	r := e.do("GET", base+"/scans", a.viewer, nil)
	r.json(t, &scans)
	if r.status != http.StatusOK || len(scans.Items) != 1 || scans.Items[0].ID != a.scanID || scans.Items[0].Domain != "example.com" ||
		scans.Items[0].NewFindings == nil || *scans.Items[0].NewFindings != 1 {
		t.Errorf("recent scans = %d %+v", r.status, scans.Items)
	}
	if r := e.do("GET", base+"/scans?limit=0", a.viewer, nil); r.status != http.StatusBadRequest {
		t.Errorf("limit=0 = %d, want 400", r.status)
	}
}

func TestUpdateTarget(t *testing.T) {
	e := newEnv(t)
	a := e.tenant("A", "example.com")
	b := e.tenant("B", "example.org")
	path := "/api/v1/orgs/" + a.orgID + "/targets/" + a.target.ID

	r := e.do("PATCH", path, a.session, map[string]any{"rate_per_sec": 20, "exclusions": map[string]any{"paths": []string{"/admin"}, "ports": []int{3389}}})
	var got targetJSON
	r.json(t, &got)
	if r.status != http.StatusOK || got.RatePerSec != 20 || !strings.Contains(string(got.Exclusions), "3389") {
		t.Fatalf("update = %d %s", r.status, r.body)
	}
	// Only the rate: exclusions unchanged.
	e.do("PATCH", path, a.session, map[string]any{"rate_per_sec": 10}).json(t, &got)
	if got.RatePerSec != 10 || !strings.Contains(string(got.Exclusions), "/admin") {
		t.Errorf("rate-only update = %+v", got)
	}

	for name, body := range map[string]any{
		"empty":             map[string]any{},
		"null exclusions":   map[string]any{"exclusions": nil, "rate_per_sec": 5},
		"unknown key":       map[string]any{"exclusions": map[string]any{"domains": []string{"x"}}},
		"zero rate":         map[string]any{"rate_per_sec": 0},
		"rate above limit":  map[string]any{"rate_per_sec": 101},
		"exclusions string": map[string]any{"exclusions": "all"},
	} {
		if r := e.do("PATCH", path, a.session, body); r.status != http.StatusBadRequest {
			t.Errorf("%s = %d %s, want 400", name, r.status, r.body)
		}
	}
	if r := e.do("PATCH", path, a.viewer, map[string]any{"rate_per_sec": 5}); r.status != http.StatusForbidden {
		t.Errorf("viewer update = %d, want 403", r.status)
	}
	// Another organization's admin cannot reach it, even through their own org's URL.
	if r := e.do("PATCH", "/api/v1/orgs/"+b.orgID+"/targets/"+a.target.ID, b.session, map[string]any{"rate_per_sec": 5}); r.status != http.StatusNotFound {
		t.Errorf("cross-organization update = %d, want 404", r.status)
	}

	// The audit log keeps who changed what.
	var audit list[auditEntryJSON]
	e.do("GET", "/api/v1/orgs/"+a.orgID+"/audit?target=example.com", a.session, nil).json(t, &audit)
	var found bool
	for _, entry := range audit.Items {
		if entry.Action == actionTargetUpdated && entry.Actor == "user:admin@example.com" {
			var d struct {
				Before map[string]any `json:"before"`
				After  map[string]any `json:"after"`
			}
			found = found || (json.Unmarshal(entry.Details, &d) == nil && d.Before["rate_per_sec"] == float64(store.DefaultRatePerSec))
		}
	}
	if !found {
		t.Errorf("no target.updated audit entry with the old rate: %+v", audit.Items)
	}
}
