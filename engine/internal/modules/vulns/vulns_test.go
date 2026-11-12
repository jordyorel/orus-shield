package vulns

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/jordyorel/orus-shield/engine/internal/finding"
	"github.com/jordyorel/orus-shield/engine/internal/module"
)

// line builds one Nuclei JSONL result.
func line(id, severity, matchedAt string, tags []string, extra map[string]any) string {
	info := map[string]any{"name": "Template " + id, "severity": severity, "tags": tags, "description": "What it is."}
	for k, v := range extra {
		info[k] = v
	}
	b, _ := json.Marshal(map[string]any{"template-id": id, "info": info, "type": "http", "matched-at": matchedAt, "ip": "192.0.2.1"})
	return string(b)
}

func parse(t *testing.T, lines ...string) []result {
	t.Helper()
	p := parser{domain: "example.com"}
	_, _ = p.Write([]byte(strings.Join(lines, "\n")))
	p.Flush()
	if p.err != nil {
		t.Fatal(p.err)
	}
	return p.results
}

func TestConvert(t *testing.T) {
	cve := map[string]any{"classification": map[string]any{"cve-id": []string{"CVE-2021-41773"}, "cwe-id": []string{"CWE-22"}, "cvss-score": 7.5, "epss-score": 0.94},
		"reference": []string{"https://nvd.nist.gov/vuln/detail/CVE-2021-41773", "javascript:alert(1)"}, "remediation": "Upgrade Apache."}
	results := parse(t,
		line("CVE-2021-41773", "high", "https://www.example.com/cgi-bin/.%2e/x?payload=1", []string{"cve", "apache", "kev"}, cve),
		line("git-config", "medium", "https://example.com/.git/config", []string{"config", "git", "exposure"}, nil),
		line("git-config", "medium", "https://example.com/.git/config", []string{"config", "git", "exposure"}, nil), // second matcher: same finding
		line("jenkins-panel", "info", "http://ci.example.com/login", []string{"panel", "jenkins"}, nil),
		line("tech-detect", "info", "https://example.com/", []string{"tech", "discovery"}, map[string]any{}),
		line("waf-detect", "info", "https://example.com/", []string{"waf"}, nil),                 // informational: dropped
		line("git-config", "medium", "https://evil.test/.git/config", []string{"exposure"}, nil), // outside the domain
		line("x-unknown", "unknown", "https://example.com/", []string{"misconfig"}, nil),         // unknown severity
		line("s3-takeover", "high", "https://old.example.com/", []string{"takeover"}, nil),
		line("cors-misconfig", "medium", "https://example.com/api", []string{"misconfig"}, map[string]any{"name": "CORS\x1b[31m misconfig\n"}), // control characters
	)
	// tech-detect writes the technology in matcher-name.
	for i := range results {
		if results[i].TemplateID == "tech-detect" {
			results[i].MatcherName = "nginx"
			results[i].Extracted = strList{"1.18.0"}
		}
	}

	res := convert("example.com", results)
	got := map[string]finding.Finding{}
	for _, f := range res.Findings {
		got[f.Asset] = f
	}
	if len(res.Findings) != 5 {
		t.Fatalf("findings: %v", slices.Sorted(maps.Keys(got)))
	}
	c := got["https://www.example.com/cgi-bin/.%2e/x#cve-2021-41773"]
	if c.CheckID != CheckKnownCVE || c.Severity != finding.SeverityHigh || !strings.Contains(c.Title, "CVE-2021-41773") {
		t.Errorf("cve finding = %+v", c)
	}
	if !slices.Contains(c.References, "CVE-2021-41773") || !slices.Contains(c.References, "CWE-22") ||
		slices.Contains(c.References, "javascript:alert(1)") || c.Remediation[0] != "Upgrade Apache." {
		t.Errorf("cve references %v, remediation %v", c.References, c.Remediation)
	}
	if !strings.Contains(c.Evidence, "cvss: 7.5") || !strings.Contains(c.Evidence, "matched at") ||
		!strings.Contains(c.Evidence, "epss: 0.9400") || !strings.Contains(c.Evidence, "CISA KEV") || !slices.Contains(c.References, kevCatalog) {
		t.Errorf("cve evidence %q", c.Evidence)
	}
	if f := got["https://example.com/.git/config#git-config"]; f.CheckID != CheckExposedData {
		t.Errorf("git-config check = %q", f.CheckID)
	}
	if f := got["http://ci.example.com/login#jenkins-panel"]; f.CheckID != CheckExposedPanel || f.Severity != finding.SeverityLow {
		t.Errorf("panel = %+v, want an exposed panel raised to low", f)
	}
	if f := got["https://old.example.com/#s3-takeover"]; f.CheckID != CheckTakeover {
		t.Errorf("takeover check = %q", f.CheckID)
	}
	for asset, f := range got {
		if strings.ContainsAny(asset+f.Evidence+f.Title, "\x1b") {
			t.Errorf("control character kept in %q", asset)
		}
		f.FirstSeen, f.LastSeen, f.Status = f.FirstSeen.AddDate(2000, 0, 0), f.FirstSeen.AddDate(2000, 0, 0), finding.StatusOpen
		if err := f.Validate(); err != nil {
			t.Errorf("%s: invalid finding: %v", asset, err)
		}
	}

	var techs string
	for _, a := range res.Assets {
		if a.Value == "example.com" {
			techs = a.Details["technologies"]
		}
		if err := a.Validate("example.com"); err != nil {
			t.Errorf("invalid asset %+v: %v", a, err)
		}
	}
	if techs != "nginx 1.18.0" {
		t.Errorf("technologies of example.com = %q", techs)
	}
}

func TestParserBounds(t *testing.T) {
	p := parser{}
	_, _ = p.Write([]byte(strings.Repeat("x", maxLine+1)))
	if p.err == nil {
		t.Error("endless line: no error")
	}

	p = parser{}
	one := line("a", "low", "https://example.com/", nil, nil) + "\n"
	_, _ = p.Write([]byte(strings.Repeat(one, maxResults+1)))
	if p.err == nil || len(p.results) != maxResults {
		t.Errorf("results %d, err %v; want the bound and an error", len(p.results), p.err)
	}

	p = parser{}
	_, _ = p.Write([]byte("not json\n"))
	if p.err == nil {
		t.Error("invalid line: no error")
	}
}

// fakeRunner stands in for Nuclei: it sends one request through the proxy
// file it was given, then prints lines.
type fakeRunner struct {
	target string // URL to request through the proxy; "" for none
	lines  []string
	err    error
	calls  [][]string
}

func (f *fakeRunner) Run(ctx context.Context, binary string, args []string, dir string, out *parser) error {
	f.calls = append(f.calls, args)
	if f.target != "" {
		raw, err := os.ReadFile(filepath.Join(dir, "proxy.txt")) //nolint:gosec // G304: the run's own work directory
		if err != nil {
			return err
		}
		pu, _ := url.Parse(strings.TrimSpace(string(raw)))
		c := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(pu)}}
		resp, err := c.Get(f.target)
		if err != nil {
			return err
		}
		_ = resp.Body.Close()
	}
	for _, l := range f.lines {
		_, _ = out.Write([]byte(l + "\n"))
	}
	return f.err
}

func newTestModule(t *testing.T, r Runner) (*Module, string) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	t.Cleanup(srv.Close)
	u, _ := url.Parse(srv.URL)
	tmpl := t.TempDir()
	_ = os.MkdirAll(filepath.Join(tmpl, "http/exposures"), 0o700)
	m := New(fakeDNS{hosts: map[string]netip.Addr{"example.com": netip.MustParseAddr("127.0.0.1")}}, &net.Dialer{},
		Config{Binary: "/nonexistent/nuclei", Templates: tmpl})
	m.runner = r
	m.urls = func(host string) []string { return []string{"http://" + host + ":" + u.Port()} }
	return m, "http://example.com:" + u.Port()
}

func verified() module.Target { return module.Target{Domain: "example.com", Verified: true} }

func TestRun(t *testing.T) {
	r := &fakeRunner{}
	m, base := newTestModule(t, r)
	r.target = base + "/"
	r.lines = []string{line("git-config", "medium", base+"/.git/config", []string{"exposure"}, nil)}

	res, err := m.Run(context.Background(), module.Request{Target: verified(), Gate: &recordGate{}})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 { // both passes print it: one finding
		t.Errorf("findings = %d", len(res.Findings))
	}
	if len(res.Evaluated) != len(Checks) {
		t.Errorf("evaluated = %v, want every check", res.Evaluated)
	}
	if len(r.calls) != 2 {
		t.Fatalf("nuclei ran %d times, want the detect and generic passes", len(r.calls))
	}
	for _, args := range r.calls {
		joined := strings.Join(args, " ")
		for _, must := range []string{"-type http", "-no-interactsh", "-disable-update-check", "-proxy ", "intrusive", "default-login"} {
			if !strings.Contains(joined, must) {
				t.Errorf("args lack %q: %s", must, joined)
			}
		}
		for _, never := range []string{"-code", "-headless", "-dast", "-env-vars", "-allow-local-file-access", "orus:"} {
			if slices.Contains(args, never) || strings.Contains(joined, "orus:") {
				t.Errorf("args contain %q (the proxy secret belongs in a file): %s", never, joined)
			}
		}
	}
}

func TestRunWithoutAnswerEvaluatesNothing(t *testing.T) {
	r := &fakeRunner{}
	m, _ := newTestModule(t, r)
	res, err := m.Run(context.Background(), module.Request{Target: verified(), Gate: &recordGate{}})
	if err != nil || len(res.Evaluated) != 0 {
		t.Errorf("no request reached the target: evaluated %v, err %v; want nothing", res.Evaluated, err)
	}
}

func TestRunRefusals(t *testing.T) {
	excludeAll := &recordGate{deny: func(d module.Destination) error {
		if d.IP.IsValid() {
			return fmt.Errorf("unverified: %w", module.ErrExcluded)
		}
		return nil
	}}
	r := &fakeRunner{}
	m, _ := newTestModule(t, r)

	res, err := m.Run(context.Background(), module.Request{Target: verified(), Gate: excludeAll})
	if err != nil || len(r.calls) != 0 || !slices.Equal(res.Unreached, []string{"example.com"}) {
		t.Errorf("every IP refused: calls %d, unreached %v, err %v; want no run and example.com unreached", len(r.calls), res.Unreached, err)
	}

	if _, err := m.Run(context.Background(), module.Request{Target: module.Target{Domain: "example.com"}, Gate: &recordGate{}}); !errors.Is(err, module.ErrNotVerified) {
		t.Errorf("unverified target: %v", err)
	}
	if _, err := New(nil, nil, Config{}).Run(context.Background(), module.Request{Target: verified()}); !errors.Is(err, ErrNotInstalled) {
		t.Errorf("not installed: %v", err)
	}

	failing := &fakeRunner{err: errors.New("exit status 1")}
	m, base := newTestModule(t, failing)
	failing.target = base + "/"
	if _, err := m.Run(context.Background(), module.Request{Target: verified(), Gate: &recordGate{}}); err == nil {
		t.Error("nuclei failed: nil error")
	}
}

func TestInfo(t *testing.T) {
	info := New(nil, nil, Config{}).Info()
	if info.Kind != module.KindActive || info.Timeout != Timeout || info.ID != ID {
		t.Errorf("info = %+v", info)
	}
	for _, c := range info.Checks {
		if !c.Category.Valid() || !c.Severity.Valid() {
			t.Errorf("check %+v", c)
		}
	}
}
