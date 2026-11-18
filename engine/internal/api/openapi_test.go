package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// The OpenAPI document must describe the server it is built into: every
// documented operation answers an API key (no 404 or 405), with its
// documented scope.
func TestOpenAPIMatchesTheServer(t *testing.T) {
	var spec struct {
		OpenAPI string                                `json:"openapi"`
		Paths   map[string]map[string]json.RawMessage `json:"paths"`
	}
	if err := json.Unmarshal(openAPISpec, &spec); err != nil {
		t.Fatalf("openapi.json: %v", err)
	}
	if spec.OpenAPI != "3.1.0" || len(spec.Paths) == 0 {
		t.Fatalf("openapi = %q, %d paths", spec.OpenAPI, len(spec.Paths))
	}

	e := newEnv(t)
	a := e.tenant("A", "example.com")
	_, read := e.newKey(a.orgID, a.session, "read")
	_, write := e.newKey(a.orgID, a.session, "write")
	ids := strings.NewReplacer("{org}", a.orgID, "{target}", a.target.ID, "{finding}", a.finding.ID, "{scan}", a.scanID)

	// The public document itself.
	r := e.do("GET", "/api/v1/openapi.json", "", nil)
	if r.status != http.StatusOK || !strings.HasPrefix(r.header.Get("Content-Type"), "application/json") || string(r.body) != string(openAPISpec) {
		t.Errorf("GET /openapi.json = %d %s", r.status, r.header.Get("Content-Type"))
	}

	for path, ops := range spec.Paths {
		for method, raw := range ops {
			var op struct {
				Scope string `json:"x-scope"`
			}
			if err := json.Unmarshal(raw, &op); err != nil {
				t.Fatalf("%s %s: %v", method, path, err)
			}
			url := "/api/v1" + ids.Replace(path)
			if path == "/orgs/{org}/report" {
				url += "?kind=executive&lang=fr"
			}
			m := strings.ToUpper(method)
			var body any
			switch m {
			case "PUT":
				body = map[string]string{"status": "accepted_risk"}
			case "POST":
				body = map[string]any{}
			}
			if op.Scope == "read" {
				if got := e.keyDo(m, url, read, body); got.status != http.StatusOK {
					t.Errorf("%s %s with a read key = %d %s", m, path, got.status, got.body)
				}
				continue
			}
			if op.Scope != "write" {
				t.Errorf("%s %s: x-scope %q", m, path, op.Scope)
				continue
			}
			if got := e.keyDo(m, url, read, body); got.status != http.StatusForbidden {
				t.Errorf("%s %s with a read key = %d, want 403", m, path, got.status)
			}
			got := e.keyDo(m, url, write, body)
			if got.status == http.StatusNotFound || got.status == http.StatusMethodNotAllowed || got.status >= 500 || got.status == http.StatusUnauthorized {
				t.Errorf("%s %s with a write key = %d %s", m, path, got.status, got.body)
			}
		}
	}
}
