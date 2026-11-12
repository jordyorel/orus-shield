package zap

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jordyorel/orus-shield/engine/internal/dialer"
	"github.com/jordyorel/orus-shield/engine/internal/finding"
	"github.com/jordyorel/orus-shield/engine/internal/module"
	"github.com/jordyorel/orus-shield/engine/internal/resolver"
)

// ---- Fakes ------------------------------------------------------------------

type fakeDNS struct{ ips map[string][]netip.Addr }

func (f fakeDNS) LookupIP(ctx context.Context, host string) ([]netip.Addr, error) {
	if a, ok := f.ips[host]; ok {
		return a, nil
	}
	return nil, fmt.Errorf("lookup %s: %w", host, resolver.ErrNotFound)
}
func (fakeDNS) LookupTXT(ctx context.Context, name string) ([]string, error) {
	return nil, resolver.ErrNotFound
}
func (fakeDNS) LookupMX(ctx context.Context, name string) ([]*net.MX, error) {
	return nil, resolver.ErrNotFound
}
func (fakeDNS) LookupAddr(ctx context.Context, ip netip.Addr) ([]string, error) {
	return nil, resolver.ErrNotFound
}

type allowGate struct {
	mu   sync.Mutex
	seen []module.Destination
}

func (g *allowGate) Allow(ctx context.Context, d module.Destination) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.seen = append(g.seen, d)
	return nil
}

// fakeRunner checks the inputs, then writes the report ZAP would. It does
// not send requests, so the proxy counts none: tests that need "evaluated"
// use the real runner.
type fakeRunner struct {
	report string
	plan   map[string]any
	conf   string
	ran    int
}

func (f *fakeRunner) Run(ctx context.Context, cfg Config, dir string) error {
	f.ran++
	b, err := os.ReadFile(filepath.Join(dir, planFile)) //nolint:gosec // G304: the test run's own directory
	if err != nil {
		return err
	}
	if err := json.Unmarshal(b, &f.plan); err != nil {
		return err
	}
	c, err := os.ReadFile(filepath.Join(dir, configFile)) //nolint:gosec // G304: the test run's own directory
	if err != nil {
		return err
	}
	f.conf = string(c)
	return os.WriteFile(filepath.Join(dir, reportFile), []byte(f.report), 0o600)
}

// newTest: example.com answers on 127.0.0.1 at a local listener's port.
func newTest(t *testing.T, report string) (*Module, *fakeRunner) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port
	m := New(fakeDNS{ips: map[string][]netip.Addr{"example.com": {netip.MustParseAddr("127.0.0.1")}}}, dialer.NewSystem(),
		Config{Image: "zaproxy/zap-stable@sha256:test", WorkDir: t.TempDir()})
	m.urls = func(h string) []string { return []string{fmt.Sprintf("http://%s:%d", h, port)} }
	r := &fakeRunner{report: report}
	m.runner = r
	return m, r
}

func deepReq(g module.Gate) module.Request {
	return module.Request{Target: module.Target{Domain: "example.com", Verified: true}, Gate: g, Config: json.RawMessage(`{"deep":true}`)}
}

const sampleReport = `{"@version":"2.16.1","site":[{"@name":"https://example.com","alerts":[
 {"pluginid":"40018","name":"SQL Injection","riskcode":"3","cweid":"89","desc":"<p>SQL injection may be possible.</p>",
  "solution":"<p>Use prepared statements &amp; parameters.</p>","reference":"<p>https://owasp.org/sqli</p>",
  "instances":[{"uri":"https://example.com/search?q=1","method":"GET","param":"q","attack":"1' OR '1'='1","evidence":"SQL syntax\u001b[31m"},
               {"uri":"https://example.com/search?q=2","method":"GET","param":"q","attack":"2'","evidence":""}]},
 {"pluginid":"40012","name":"Cross Site Scripting (Reflected)","riskcode":"3","cweid":"79","desc":"x","solution":"y","reference":"",
  "instances":[{"uri":"https://www.example.com/hello?name=x","method":"GET","param":"name","attack":"<script>alert(1)</script>","evidence":"<script>alert(1)</script>"}]},
 {"pluginid":"10038","name":"Content Security Policy (CSP) Header Not Set","riskcode":"2","cweid":"693","desc":"x","solution":"y","reference":"",
  "instances":[{"uri":"https://example.com/","method":"GET"}]},
 {"pluginid":"10021","name":"X-Content-Type-Options Header Missing","riskcode":"1","cweid":"693","desc":"x","solution":"y","reference":"",
  "instances":[{"uri":"https://example.com/","method":"GET"}]},
 {"pluginid":"40018","name":"SQL Injection","riskcode":"3","cweid":"89","desc":"x","solution":"y","reference":"",
  "instances":[{"uri":"https://evil.example.org/x?id=1","method":"GET","param":"id"}]},
 {"pluginid":"90020","name":"Remote OS Command Injection","riskcode":"2","cweid":"78","desc":"x","solution":"","reference":"",
  "instances":[{"uri":"https://example.com/ping","method":"POST","param":"host","attack":";id"}]},
 {"pluginid":"99999","name":"Some high risk thing","riskcode":"3","cweid":"0","desc":"x","solution":"y","reference":"",
  "instances":[{"uri":"https://example.com/admin","method":"GET"}]}
]}]}`

// ---- Tests -------------------------------------------------------------------

func TestStandardProfileDoesNothing(t *testing.T) {
	m, r := newTest(t, sampleReport)
	for _, cfg := range []json.RawMessage{nil, json.RawMessage(`{"deep":false}`)} {
		req := deepReq(&allowGate{})
		req.Config = cfg
		res, err := m.Run(context.Background(), req)
		if err != nil || len(res.Findings) != 0 || len(res.Evaluated) != 0 {
			t.Errorf("config %s: %+v, %v", cfg, res, err)
		}
	}
	if r.ran != 0 {
		t.Error("ZAP ran outside the deep profile")
	}
}

func TestNotInstalledAndNotVerified(t *testing.T) {
	m, _ := newTest(t, sampleReport)
	m.cfg.Image = ""
	if _, err := m.Run(context.Background(), deepReq(&allowGate{})); !errors.Is(err, ErrNotInstalled) {
		t.Errorf("no image = %v", err)
	}
	m.cfg.Image = "x"
	req := deepReq(&allowGate{})
	req.Target.Verified = false
	if _, err := m.Run(context.Background(), req); err == nil || !strings.Contains(err.Error(), "verified") {
		t.Errorf("unverified = %v", err)
	}
}

func TestDeepRunConvertsReport(t *testing.T) {
	m, r := newTest(t, sampleReport)
	res, err := m.Run(context.Background(), deepReq(&allowGate{}))
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]finding.Finding{}
	for _, f := range res.Findings {
		stamped := f // the worker stamps the lifecycle fields
		stamped.FirstSeen, stamped.LastSeen, stamped.Status = time.Now(), time.Now(), finding.StatusOpen
		if err := stamped.Validate(); err != nil {
			t.Errorf("invalid finding %s: %v", f.Title, err)
		}
		got[f.CheckID+" "+f.Asset] = f
	}
	sqli, ok := got[CheckInjection+" https://example.com/search#zap-40018"]
	if !ok {
		t.Fatalf("findings = %v", keys(got))
	}
	if sqli.Severity != finding.SeverityCritical || strings.Count(sqli.Evidence, "request: ") != 2 ||
		!strings.Contains(sqli.Evidence, "payload: 1' OR '1'='1") || strings.Contains(sqli.Evidence, "\x1b") {
		t.Errorf("sqli = %+v", sqli)
	}
	if sqli.Description != "SQL injection may be possible." || sqli.Remediation[0] != "Use prepared statements & parameters." ||
		!slices.Equal(sqli.References, []string{"CWE-89", "https://owasp.org/sqli"}) {
		t.Errorf("sqli texts = %q %q %q", sqli.Description, sqli.Remediation, sqli.References)
	}
	if f := got[CheckXSS+" https://www.example.com/hello#zap-40012"]; f.Severity != finding.SeverityHigh {
		t.Errorf("xss = %+v", f)
	}
	if f := got[CheckInjection+" https://example.com/ping#zap-90020"]; f.Severity != finding.SeverityMedium {
		t.Errorf("medium command injection = %+v", f)
	}
	if f := got[CheckOther+" https://example.com/admin#zap-99999"]; f.Severity != finding.SeverityHigh {
		t.Errorf("other high = %+v", f)
	}
	// Hygiene alerts (the web module's) and out-of-scope hosts are dropped.
	if len(res.Findings) != 4 {
		t.Errorf("findings = %v", keys(got))
	}
	// The plan scans what answered, in scope, and the config chains the proxy.
	env := r.plan["env"].(map[string]any)
	ctxs := env["contexts"].([]any)[0].(map[string]any)
	if urls := ctxs["urls"].([]any); len(urls) != 1 || !strings.HasPrefix(urls[0].(string), "http://example.com:") {
		t.Errorf("plan urls = %v", urls)
	}
	if inc := ctxs["includePaths"].([]any)[0].(string); inc != `^https?://([a-z0-9-]+\.)*example\.com(:[0-9]+)?(/.*)?$` {
		t.Errorf("scope = %q", inc)
	}
	for _, want := range []string{"network.connection.httpProxy.enabled=true", "network.connection.httpProxy.host=host.docker.internal", "network.connection.httpProxy.username=orus"} {
		if !strings.Contains(r.conf, want) {
			t.Errorf("config lacks %q:\n%s", want, r.conf)
		}
	}
}

func TestDockerArgs(t *testing.T) {
	a := strings.Join(dockerArgs(Config{Image: "img@sha256:x", ProxyHost: "host.docker.internal"}, "/tmp/run", "orus-zap-1"), " ")
	for _, want := range []string{"--rm", "--cap-drop ALL", "no-new-privileges", "-v /tmp/run:/zap/wrk:rw", "--add-host host.docker.internal:host-gateway",
		"img@sha256:x zap.sh -cmd -silent -configfile /zap/wrk/zap.conf -autorun /zap/wrk/plan.yaml"} {
		if !strings.Contains(a, want) {
			t.Errorf("args lack %q: %s", want, a)
		}
	}
	h := strings.Join(dockerArgs(Config{Image: "img", ProxyHost: "127.0.0.1", Network: "host"}, "/d", "n"), " ")
	if !strings.Contains(h, "--network host") || strings.Contains(h, "--add-host") {
		t.Errorf("host network args: %s", h)
	}
}

func keys(m map[string]finding.Finding) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

func TestApplyAuth(t *testing.T) {
	read := func(dir, name string) string {
		b, err := os.ReadFile(filepath.Join(dir, name)) //nolint:gosec // G304: the test's own directory
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	// Header: every request carries it; the value is only in auth.env.
	dir := t.TempDir()
	if err := writeInputs(dir, "example.com", []string{"https://example.com"}, proxyAddr{Host: "h", Port: "1", User: "orus", Pass: "p"},
		&module.ScanAuth{Kind: "header", HeaderName: "Authorization", Secret: "Bearer s3cret"}); err != nil {
		t.Fatal(err)
	}
	env := read(dir, authEnvFile)
	if !strings.Contains(env, "ZAP_AUTH_HEADER=Authorization\n") || !strings.Contains(env, "ZAP_AUTH_HEADER_VALUE=Bearer s3cret\n") || !strings.Contains(env, "ZAP_AUTH_HEADER_SITE=example.com\n") {
		t.Errorf("auth.env = %q", env)
	}
	if fi, err := os.Stat(filepath.Join(dir, authEnvFile)); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("auth.env mode = %v, %v", fi.Mode(), err)
	}
	if strings.Contains(read(dir, planFile), "s3cret") {
		t.Error("the secret is in the plan")
	}
	if !strings.Contains(strings.Join(dockerArgs(Config{Image: "i", ProxyHost: "h"}, dir, "n"), " "), "--env-file "+filepath.Join(dir, authEnvFile)) {
		t.Error("docker run does not read auth.env")
	}

	// No account: no auth.env, no --env-file.
	dir = t.TempDir()
	if err := writeInputs(dir, "example.com", []string{"https://example.com"}, proxyAddr{Host: "h", Port: "1"}, nil); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.Join(dockerArgs(Config{Image: "i", ProxyHost: "h"}, dir, "n"), " "), "--env-file") {
		t.Error("--env-file without a test account")
	}
}
