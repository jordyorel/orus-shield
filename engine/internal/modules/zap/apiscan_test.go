package zap

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jordyorel/orus-shield/engine/internal/dialer"
	"github.com/jordyorel/orus-shield/engine/internal/finding"
	"github.com/jordyorel/orus-shield/engine/internal/module"
)

func apiReq(apis ...module.ScanAPI) module.Request {
	cfg, _ := json.Marshal(module.RunConfig{APIs: apis})
	return module.Request{Target: module.Target{Domain: "example.com", Verified: true}, Gate: &allowGate{}, Config: cfg}
}

func newAPITest(t *testing.T, report string) (*APIModule, *fakeRunner) {
	t.Helper()
	m := NewAPI(fakeDNS{ips: map[string][]netip.Addr{"example.com": {netip.MustParseAddr("127.0.0.1")}}}, dialer.NewSystem(),
		Config{Image: "zaproxy/zap-stable@sha256:test", WorkDir: t.TempDir()})
	r := &fakeRunner{report: report}
	m.runner = r
	return m, r
}

func TestAPIModuleWithoutAPIsDoesNothing(t *testing.T) {
	m, r := newAPITest(t, sampleReport)
	res, err := m.Run(context.Background(), apiReq())
	if err != nil || len(res.Findings) != 0 || len(res.Evaluated) != 0 || r.ran != 0 {
		t.Errorf("no API: %+v, %v, ran %d", res, err, r.ran)
	}
	if !m.Info().UsesAPIs || m.Info().Kind != module.KindActive {
		t.Errorf("info = %+v", m.Info())
	}
}

func TestAPIModuleRefusesOutOfScope(t *testing.T) {
	m, r := newAPITest(t, sampleReport)
	_, err := m.Run(context.Background(), apiReq(module.ScanAPI{Kind: "openapi", BaseURL: "https://api.other.org/v1", SpecURL: "https://api.other.org/openapi.json"}))
	if err == nil || r.ran != 0 {
		t.Errorf("out of scope API: %v, ran %d", err, r.ran)
	}
}

func TestAPIModulePlanAndFindings(t *testing.T) {
	report := `{"site":[{"alerts":[
	 {"pluginid":"40018","name":"SQL Injection","riskcode":"3","cweid":"89","desc":"x","solution":"y","instances":[{"uri":"https://api.example.com/v1/users/1","method":"GET","param":"id","attack":"1'"}]},
	 {"pluginid":"10062","name":"PII Disclosure","riskcode":"3","cweid":"359","desc":"x","solution":"y","instances":[{"uri":"https://api.example.com/v1/users","method":"GET"}]},
	 {"pluginid":"40040","name":"CORS Misconfiguration","riskcode":"2","cweid":"942","desc":"x","solution":"y","instances":[{"uri":"https://api.example.com/v1/","method":"GET"}]},
	 {"pluginid":"10021","name":"X-Content-Type-Options Header Missing","riskcode":"1","cweid":"693","desc":"x","solution":"y","instances":[{"uri":"https://api.example.com/v1/","method":"GET"}]}
	]}]}`
	m, r := newAPITest(t, report)
	res, err := m.Run(context.Background(), apiReq(
		module.ScanAPI{Name: "Users", Kind: "openapi", BaseURL: "https://api.example.com/v1", Spec: `{"openapi":"3.0.0"}`},
		module.ScanAPI{Name: "Graph", Kind: "graphql", BaseURL: "https://example.com/graphql"},
	))
	if err != nil {
		t.Fatal(err)
	}
	jobs := r.plan["jobs"].([]any)
	first, second := jobs[0].(map[string]any), jobs[1].(map[string]any)
	if first["type"] != "openapi" || first["parameters"].(map[string]any)["apiFile"] != "/zap/wrk/spec-0" ||
		first["parameters"].(map[string]any)["targetUrl"] != "https://api.example.com/v1" {
		t.Errorf("openapi job = %v", first)
	}
	if second["type"] != "graphql" || second["parameters"].(map[string]any)["endpoint"] != "https://example.com/graphql" {
		t.Errorf("graphql job = %v", second)
	}
	got := map[string]finding.Severity{}
	for _, f := range res.Findings {
		if f.ModuleID != APIID {
			t.Errorf("module = %s", f.ModuleID)
		}
		got[f.CheckID] = f.Severity
	}
	want := map[string]finding.Severity{CheckAPIInjection: finding.SeverityCritical, CheckAPIExposure: finding.SeverityHigh, CheckAPIConfig: finding.SeverityMedium}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("findings = %v, want %v", got, want)
	}
}

// TestRealAPIScan imports a local OpenAPI description with the real image
// and finds the SQL injection of its users endpoint (ORUS_ZAP_IMAGE set).
func TestRealAPIScan(t *testing.T) {
	image := os.Getenv("ORUS_ZAP_IMAGE")
	if image == "" {
		t.Skip("ORUS_ZAP_IMAGE is not set")
	}
	app := http.NewServeMux()
	app.HandleFunc("/api/users", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		name := r.URL.Query().Get("name")
		if strings.ContainsAny(name, `'"`) {
			// Deliberately vulnerable: a database error leaks, as with a
			// query built by concatenation.
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = fmt.Fprint(w, `{"error":"You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version"}`)
			return
		}
		_, _ = fmt.Fprint(w, `[{"id":1,"name":"alice"}]`)
	})
	srv := httptest.NewServer(app)
	defer srv.Close()
	port := srv.Listener.Addr().(interface{ String() string }).String()
	port = port[strings.LastIndexByte(port, ':')+1:]
	base := "http://example.com:" + port + "/api"
	spec := fmt.Sprintf(`{"openapi":"3.0.0","info":{"title":"Users","version":"1"},"servers":[{"url":%q}],
	 "paths":{"/users":{"get":{"parameters":[{"name":"name","in":"query","schema":{"type":"string"}}],
	 "responses":{"200":{"description":"ok"}}}}}}`, base)

	m := NewAPI(fakeDNS{ips: map[string][]netip.Addr{"example.com": {netip.MustParseAddr("127.0.0.1")}}}, dialer.NewSystem(),
		Config{Image: image, ProxyHost: os.Getenv("ORUS_ZAP_PROXY_HOST"), Network: os.Getenv("ORUS_ZAP_NETWORK"), WorkDir: os.Getenv("ORUS_ZAP_WORKDIR")})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()
	res, err := m.Run(ctx, apiReq(module.ScanAPI{Name: "Users", Kind: "openapi", BaseURL: base, Spec: spec}))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Evaluated) != len(APIChecks) {
		t.Errorf("evaluated = %v: nothing reached the API through the proxy", res.Evaluated)
	}
	var sqli bool
	for _, f := range res.Findings {
		t.Logf("%s %s %s", f.Severity, f.CheckID, f.Title)
		if f.CheckID == CheckAPIInjection {
			sqli = true
		}
	}
	if !sqli {
		t.Error("the SQL injection of /api/users was not found")
	}
}
