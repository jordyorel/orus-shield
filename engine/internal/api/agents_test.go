package api

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jordyorel/orus-shield/engine/internal/finding"
	"github.com/jordyorel/orus-shield/engine/internal/module"
	"github.com/jordyorel/orus-shield/engine/internal/modules/ports"
	"github.com/jordyorel/orus-shield/engine/internal/plan"
	"github.com/jordyorel/orus-shield/engine/internal/worker"
)

func TestPrivateRange(t *testing.T) {
	for raw, ok := range map[string]bool{
		"10.0.0.0/24": true, "192.168.1.0/24": true, "172.16.4.0/22": true, "fd00::/112": true,
		"10.0.0.5/32": true, "10.0.0.0/8": false, "8.8.8.0/24": false, "164.92.136.224/32": false,
		"127.0.0.0/24": false, "fd00::/64": false, "nonsense": false,
	} {
		if _, got := PrivateRange(raw); got != ok {
			t.Errorf("PrivateRange(%s) = %v, want %v", raw, got, ok)
		}
	}
}

// agentDo calls an agent endpoint: no session, the agent's bearer token.
func (e *env) agentDo(method, path, token string, body any) response {
	e.t.Helper()
	r := e.doHeaders(method, path, map[string]string{"Authorization": "Bearer " + token}, body)
	return r
}

func TestAgentEndToEnd(t *testing.T) {
	e := newEnv(t)
	a := e.tenant("A", "example.com")
	base := "/api/v1/orgs/" + a.orgID + "/agents"

	// Pro has no agents; Sur devis has.
	if r := e.do("POST", base, a.session, createAgentRequest{Name: "Bureau", Ranges: []string{"10.0.0.0/24"}}); r.status != http.StatusForbidden {
		t.Errorf("Pro = %d, want 403", r.status)
	}
	e.setPlan(a.orgID, plan.Subscription{Plan: plan.Enterprise, Status: plan.Active})
	for name, bad := range map[string]createAgentRequest{
		"public range": {Name: "x", Ranges: []string{"164.92.136.0/24"}},
		"too large":    {Name: "x", Ranges: []string{"10.0.0.0/8"}},
		"no name":      {Ranges: []string{"10.0.0.0/24"}},
	} {
		if r := e.do("POST", base, a.session, bad); r.status != http.StatusBadRequest {
			t.Errorf("%s = %d, want 400", name, r.status)
		}
	}
	if r := e.do("POST", base, a.viewer, createAgentRequest{Name: "x", Ranges: []string{"10.0.0.0/24"}}); r.status != http.StatusForbidden {
		t.Errorf("viewer = %d", r.status)
	}
	var created enrolmentJSON
	r := e.do("POST", base, a.session, createAgentRequest{Name: "Bureau", Ranges: []string{"10.0.0.0/24"}})
	r.json(t, &created)
	if r.status != http.StatusCreated || created.Code == "" {
		t.Fatalf("create = %d %s", r.status, r.body)
	}

	// The agent enrols, then claims the scan of its internal network.
	var enrolled struct {
		Token  string   `json:"token"`
		Ranges []string `json:"ranges"`
	}
	r = e.do("POST", "/api/v1/agent/enroll", "", agentEnrolRequest{Code: created.Code, Hostname: "srv-01", OS: "linux/amd64", Version: "0.1.0"})
	r.json(t, &enrolled)
	if r.status != http.StatusOK || enrolled.Token == "" {
		t.Fatalf("enrol = %d %s", r.status, r.body)
	}
	if r := e.agentDo("POST", "/api/v1/agent/claim", enrolled.Token, nil); r.status != http.StatusNoContent {
		t.Errorf("nothing to do = %d", r.status)
	}
	org, _ := e.st.Org(a.orgID)
	if _, err := org.EnqueueScan(context.Background(), created.Agent.TargetID, []string{"ports"}, "user:admin@example.com"); err != nil {
		t.Fatal(err)
	}
	if r := e.agentDo("POST", "/api/v1/agent/claim", "wrong-token", nil); r.status != http.StatusUnauthorized {
		t.Errorf("wrong token = %d", r.status)
	}
	var job agentJobJSON
	r = e.agentDo("POST", "/api/v1/agent/claim", enrolled.Token, nil)
	r.json(t, &job)
	if r.status != http.StatusOK || job.Domain == "" || job.Ranges[0] != "10.0.0.0/24" {
		t.Fatalf("claim = %d %s", r.status, r.body)
	}

	// It sends an open RDP port on 10.0.0.5, and the worker records it.
	f := finding.Finding{SchemaVersion: finding.SchemaVersion, ModuleID: "ports", CheckID: "port-remote-desktop-exposed",
		ID: finding.NewID("ports", "port-remote-desktop-exposed", job.Domain, "10.0.0.5:3389"), Target: job.Domain,
		Asset: "10.0.0.5:3389", Severity: finding.SeverityCritical, Title: "RDP", Description: "d", Evidence: "e"}
	result := `{"findings":[` + mustJSON(t, f) + `],"assets":[{"kind":"ip","value":"10.0.0.5"}],"evaluated":["port-remote-desktop-exposed"]}`
	if r := e.agentDo("POST", "/api/v1/agent/scans/"+job.ScanID+"/result", enrolled.Token,
		map[string]any{"attempt": job.Attempt, "results": map[string]any{"ports": rawJSON(result)}}); r.status != http.StatusAccepted {
		t.Fatalf("result = %d %s", r.status, r.body)
	}
	reg := module.NewRegistry()
	if err := reg.Register(ports.New(nil, nil)); err != nil {
		t.Fatal(err)
	}
	w := worker.New(e.st, reg, nil, worker.Config{ID: "worker:test"}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if worked, err := w.RunOnce(context.Background()); err != nil || !worked {
		t.Fatalf("ingest = %v, %v", worked, err)
	}
	var fs list[orgFinding]
	e.do("GET", "/api/v1/orgs/"+a.orgID+"/findings", a.session, nil).json(t, &fs)
	var found bool
	for _, x := range fs.Items {
		if x.Asset == "10.0.0.5:3389" && x.Target == job.Domain {
			found = true
		}
	}
	if !found {
		t.Errorf("the agent's finding is not recorded: %+v", fs.Items)
	}

	// An address outside the agent's ranges is rejected: the module fails.
	if _, err := org.EnqueueScan(context.Background(), created.Agent.TargetID, []string{"ports"}, "user:admin@example.com"); err != nil {
		t.Fatal(err)
	}
	e.agentDo("POST", "/api/v1/agent/claim", enrolled.Token, nil).json(t, &job)
	g := f
	g.Asset = "8.8.8.8:3389"
	g.ID = finding.NewID("ports", g.CheckID, job.Domain, g.Asset)
	outside := `{"findings":[` + mustJSON(t, g) + `],"evaluated":["port-remote-desktop-exposed"]}`
	e.agentDo("POST", "/api/v1/agent/scans/"+job.ScanID+"/result", enrolled.Token,
		map[string]any{"attempt": job.Attempt, "results": map[string]any{"ports": rawJSON(outside)}})
	if _, err := w.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	var sc scanJSON
	e.do("GET", "/api/v1/orgs/"+a.orgID+"/scans/"+job.ScanID, a.session, nil).json(t, &sc)
	if !strings.Contains(sc.Error, "outside the agent's ranges") {
		t.Errorf("an address outside the ranges was accepted: %+v", sc)
	}

	// Revoked: the agent is locked out at once.
	if r := e.do("DELETE", base+"/"+created.Agent.ID, a.session, nil); r.status != http.StatusNoContent {
		t.Errorf("revoke = %d", r.status)
	}
	if r := e.agentDo("POST", "/api/v1/agent/claim", enrolled.Token, nil); r.status != http.StatusUnauthorized {
		t.Errorf("revoked agent = %d", r.status)
	}
}

// doHeaders is do without a session cookie, with extra headers (agents).
func (e *env) doHeaders(method, path string, headers map[string]string, body any) response {
	e.t.Helper()
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			e.t.Fatal(err)
		}
		rd = bytes.NewReader(b)
	}
	req := httptest.NewRequest(method, path, rd)
	req.RemoteAddr = "192.0.2.1:4000"
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	e.handler.ServeHTTP(rec, req)
	return response{status: rec.Code, header: rec.Header(), body: rec.Body.Bytes()}
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

type rawJSON string

func (r rawJSON) MarshalJSON() ([]byte, error) { return []byte(r), nil }
