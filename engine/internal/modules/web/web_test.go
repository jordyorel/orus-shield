package web

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/jordyorel/orus-shield/engine/internal/finding"
	"github.com/jordyorel/orus-shield/engine/internal/module"
	"github.com/jordyorel/orus-shield/engine/internal/resolver"
)

// ---- Fakes ----------------------------------------------------------------

type fakeDNS struct {
	ips map[string][]netip.Addr
	err error
}

func (f *fakeDNS) LookupIP(_ context.Context, host string) ([]netip.Addr, error) {
	if f.err != nil {
		return nil, f.err
	}
	if a, ok := f.ips[host]; ok {
		return a, nil
	}
	return nil, fmt.Errorf("lookup %s: %w", host, resolver.ErrNotFound)
}
func (f *fakeDNS) LookupTXT(context.Context, string) ([]string, error) {
	return nil, resolver.ErrNotFound
}
func (f *fakeDNS) LookupMX(context.Context, string) ([]*net.MX, error) {
	return nil, resolver.ErrNotFound
}
func (f *fakeDNS) LookupAddr(context.Context, netip.Addr) ([]string, error) {
	return nil, resolver.ErrNotFound
}

// fakeDialer routes the addresses the module asks for (documentation IPs
// such as 192.0.2.10:443) to local test servers. Unrouted addresses are
// refused, like a closed port.
type fakeDialer struct {
	mu     sync.Mutex
	routes map[string]string
}

func (f *fakeDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	f.mu.Lock()
	target, ok := f.routes[address]
	f.mu.Unlock()
	if !ok {
		return nil, &net.OpError{Op: "dial", Net: network, Err: syscall.ECONNREFUSED}
	}
	var d net.Dialer
	return d.DialContext(ctx, network, target)
}

// fakeGate records destinations and refuses some paths or everything.
type fakeGate struct {
	mu       sync.Mutex
	seen     []module.Destination
	denyPath map[string]error
	all      error
}

func (g *fakeGate) Allow(_ context.Context, dest module.Destination) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.seen = append(g.seen, dest)
	if g.all != nil {
		return g.all
	}
	return g.denyPath[dest.Path]
}

func (g *fakeGate) paths(port int) []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	var out []string
	for _, d := range g.seen {
		if d.Port == port {
			out = append(out, d.Host+d.Path)
		}
	}
	return out
}

// ---- Environment ----------------------------------------------------------

var (
	apexIP = netip.MustParseAddr("192.0.2.10")
	wwwIP  = netip.MustParseAddr("192.0.2.11")
)

type env struct {
	dns  *fakeDNS
	dial *fakeDialer
	gate *fakeGate
}

// newEnv: example.com resolves to apexIP, www.example.com does not resolve.
func newEnv() *env {
	return &env{
		dns:  &fakeDNS{ips: map[string][]netip.Addr{"example.com": {apexIP}}},
		dial: &fakeDialer{routes: map[string]string{}},
		gate: &fakeGate{},
	}
}

// serve starts handler on ip:port: TLS for 443, plain HTTP otherwise.
func (e *env) serve(t *testing.T, ip netip.Addr, port uint16, handler http.HandlerFunc) {
	t.Helper()
	var srv *httptest.Server
	if port == httpsPort {
		srv = httptest.NewTLSServer(handler)
	} else {
		srv = httptest.NewServer(handler)
	}
	t.Cleanup(srv.Close)
	e.dial.routes[netip.AddrPortFrom(ip, port).String()] = srv.Listener.Addr().String()
}

func (e *env) run(t *testing.T) (module.Result, error) {
	t.Helper()
	res, err := New(e.dns, e.dial).Run(context.Background(), module.Request{
		Target: module.Target{Domain: "example.com"},
		Gate:   e.gate,
	})
	// The worker sets the lifecycle fields; everything else is the module's.
	now := time.Now()
	for _, f := range res.Findings {
		f.FirstSeen, f.LastSeen, f.Status = now, now, finding.StatusOpen
		if err := f.Validate(); err != nil {
			t.Errorf("invalid finding %s: %v", f.CheckID, err)
		}
	}
	if _, evalErr := module.Evaluate(New(nil, nil).Info(), res); evalErr != nil {
		t.Errorf("Evaluate: %v", evalErr)
	}
	return res, err
}

func checkIDs(fs []finding.Finding) []string {
	ids := make([]string, 0, len(fs))
	for _, f := range fs {
		ids = append(ids, f.CheckID)
	}
	slices.Sort(ids)
	return ids
}

func sorted(ids ...string) []string {
	out := slices.Clone(ids)
	slices.Sort(out)
	return slices.Compact(out)
}

// goodHeaders is a well-configured site.
func goodHeaders(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
	h.Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'self'")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Server", "nginx")
	http.SetCookie(w, &http.Cookie{Name: "session", Value: "x", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
}

func redirectToHTTPS(w http.ResponseWriter, r *http.Request) {
	//nolint:gosec // G710: local test server; the redirect target is what the test is about
	http.Redirect(w, r, "https://"+r.Host+r.URL.RequestURI(), http.StatusMovedPermanently)
}

// ---- Tests ----------------------------------------------------------------

func TestWellConfiguredSite(t *testing.T) {
	e := newEnv()
	e.serve(t, apexIP, httpsPort, func(w http.ResponseWriter, r *http.Request) {
		goodHeaders(w)
		_, _ = w.Write([]byte("hello"))
	})
	e.serve(t, apexIP, httpPort, redirectToHTTPS)

	res, err := e.run(t)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 0 {
		t.Errorf("findings = %v, want none", checkIDs(res.Findings))
	}
	all := make([]string, len(Checks))
	for i, c := range Checks {
		all[i] = c.ID
	}
	if got := sorted(res.Evaluated...); !slices.Equal(got, sorted(all...)) {
		t.Errorf("evaluated = %v, want every check %v", got, sorted(all...))
	}
	if len(res.Assets) != 1 || res.Assets[0].Value != "example.com" {
		t.Errorf("assets = %+v, want the hostname example.com", res.Assets)
	}
}

func TestMisconfiguredSite(t *testing.T) {
	// What the lab server serves: no security headers, a version in Server,
	// a cookie without Secure, and plain HTTP serving the page.
	e := newEnv()
	page := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.24.0 (Ubuntu)")
		w.Header().Set("X-Powered-By", "PHP/8.1.2")
		http.SetCookie(w, &http.Cookie{Name: "PHPSESSID", Value: "x"}) //nolint:gosec // G124: the insecure cookie is the defect under test
		_, _ = w.Write([]byte("hello"))
	}
	e.serve(t, apexIP, httpsPort, page)
	e.serve(t, apexIP, httpPort, page)

	res, err := e.run(t)
	if err != nil {
		t.Fatal(err)
	}
	want := sorted(CheckHTTPNotRedirected, CheckHSTSMissing, CheckCSPMissing, CheckFramingAllowed,
		CheckNosniffMissing, CheckCookieNotSecure, CheckVersionDisclosed)
	if got := checkIDs(res.Findings); !slices.Equal(got, want) {
		t.Fatalf("findings = %v, want %v", got, want)
	}
	for _, f := range res.Findings {
		switch f.CheckID {
		case CheckHTTPNotRedirected:
			if f.Asset != "example.com:80" || f.Severity != finding.SeverityMedium {
				t.Errorf("redirect finding: asset %q severity %s", f.Asset, f.Severity)
			}
		case CheckVersionDisclosed:
			if f.Asset != "example.com" || !strings.Contains(f.Evidence, "server: nginx/1.24.0 (Ubuntu)") ||
				!strings.Contains(f.Evidence, "x-powered-by: PHP/8.1.2") {
				t.Errorf("version finding: asset %q evidence %q", f.Asset, f.Evidence)
			}
		case CheckCookieNotSecure:
			if !strings.Contains(f.Evidence, "PHPSESSID") {
				t.Errorf("cookie evidence %q does not name the cookie", f.Evidence)
			}
		default:
			if f.Asset != "example.com:443" {
				t.Errorf("%s asset = %q, want example.com:443", f.CheckID, f.Asset)
			}
		}
	}
}

func TestHTTPOnlySite(t *testing.T) {
	e := newEnv()
	e.serve(t, apexIP, httpPort, func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("hi")) })

	res, err := e.run(t)
	if err != nil {
		t.Fatal(err)
	}
	if got := checkIDs(res.Findings); !slices.Equal(got, []string{CheckHTTPNotRedirected}) {
		t.Fatalf("findings = %v, want only %s", got, CheckHTTPNotRedirected)
	}
	for _, f := range res.Findings {
		if f.CheckID == CheckHTTPNotRedirected && (f.Severity != finding.SeverityHigh || !strings.Contains(f.Title, "without encryption")) {
			t.Errorf("no HTTPS at all: severity %s title %q, want high and 'without encryption'", f.Severity, f.Title)
		}
	}
	if slices.Contains(res.Evaluated, CheckHSTSMissing) || slices.Contains(res.Evaluated, CheckCSPMissing) {
		t.Errorf("HTTPS checks evaluated without an HTTPS answer: %v", res.Evaluated)
	}
}

func TestSameHostRedirectIsFollowedThroughTheGate(t *testing.T) {
	e := newEnv()
	e.serve(t, apexIP, httpsPort, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		if r.URL.Path == "/" {
			http.Redirect(w, r, "/fr/", http.StatusFound)
			return
		}
		goodHeaders(w)
	})
	e.serve(t, apexIP, httpPort, redirectToHTTPS)

	res, err := e.run(t)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 0 {
		t.Errorf("findings = %v, want none (the page at /fr/ is well configured)", checkIDs(res.Findings))
	}
	if got := e.gate.paths(httpsPort); !slices.Equal(got, []string{"example.com/", "example.com/fr/"}) {
		t.Errorf("gated HTTPS requests = %v, want / then /fr/", got)
	}
}

func TestRedirectToOtherHostIsNotFollowed(t *testing.T) {
	// The apex sends everyone to www: the apex has no page of its own, www
	// is checked on its own.
	e := newEnv()
	e.dns.ips["www.example.com"] = []netip.Addr{wwwIP}
	e.serve(t, apexIP, httpsPort, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		http.Redirect(w, r, "https://www.example.com/", http.StatusMovedPermanently)
	})
	e.serve(t, apexIP, httpPort, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://www.example.com/", http.StatusMovedPermanently)
	})
	e.serve(t, wwwIP, httpsPort, func(w http.ResponseWriter, r *http.Request) { goodHeaders(w) })
	e.serve(t, wwwIP, httpPort, redirectToHTTPS)

	res, err := e.run(t)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 0 {
		t.Errorf("findings = %v, want none", checkIDs(res.Findings))
	}
	for _, p := range e.gate.paths(httpsPort) {
		if p != "example.com/" && p != "www.example.com/" {
			t.Errorf("unexpected request %s", p)
		}
	}
}

func TestRedirectsAreBounded(t *testing.T) {
	e := newEnv()
	n := 0
	e.serve(t, apexIP, httpsPort, func(w http.ResponseWriter, r *http.Request) {
		n++
		http.Redirect(w, r, fmt.Sprintf("/loop/%d", n), http.StatusFound)
	})
	if _, err := e.run(t); err != nil {
		t.Fatal(err)
	}
	if got := len(e.gate.paths(httpsPort)); got != maxRedirects+1 {
		t.Errorf("requests = %d, want %d (first + maxRedirects)", got, maxRedirects+1)
	}
}

func TestHSTSTooShort(t *testing.T) {
	e := newEnv()
	e.serve(t, apexIP, httpsPort, func(w http.ResponseWriter, r *http.Request) {
		goodHeaders(w)
		w.Header().Set("Strict-Transport-Security", "max-age=86400")
	})
	res, err := e.run(t)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 || res.Findings[0].Title != "HSTS lifetime is too short" {
		t.Fatalf("findings = %+v, want one 'HSTS lifetime is too short'", res.Findings)
	}
	if !strings.Contains(res.Findings[0].Description, "1 days") {
		t.Errorf("description %q does not give the lifetime", res.Findings[0].Description)
	}
}

func TestPathExclusionStopsTheRedirectChain(t *testing.T) {
	e := newEnv()
	e.gate.denyPath = map[string]error{"/admin/": fmt.Errorf("excluded: %w", module.ErrExcluded)}
	e.serve(t, apexIP, httpsPort, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/admin/" {
			t.Error("excluded path was requested")
		}
		goodHeaders(w)
		http.Redirect(w, r, "/admin/", http.StatusFound)
	})
	res, err := e.run(t)
	if err != nil {
		t.Fatal(err)
	}
	if slices.Contains(res.Evaluated, CheckCSPMissing) {
		t.Error("content checks evaluated on a redirect whose target was excluded")
	}
}

func TestRunErrors(t *testing.T) {
	refused := errors.New("rate limiter closed")
	tests := []struct {
		name string
		mod  func(*env)
	}{
		{"gate refusal stops the run", func(e *env) { e.gate.all = refused }},
		{"dns failure stops the run", func(e *env) { e.dns.err = errors.New("servfail") }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newEnv()
			e.serve(t, apexIP, httpsPort, func(w http.ResponseWriter, r *http.Request) {})
			tt.mod(e)
			if _, err := e.run(t); err == nil {
				t.Error("Run() = nil error, want one")
			}
		})
	}

	e := newEnv()
	if _, err := New(e.dns, e.dial).Run(context.Background(), module.Request{Target: module.Target{Domain: "bad domain"}, Gate: e.gate}); err == nil {
		t.Error("invalid domain: Run() = nil error")
	}
}

func TestNothingAnswers(t *testing.T) {
	res, err := newEnv().run(t)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings)+len(res.Evaluated)+len(res.Assets) != 0 {
		t.Errorf("no server: result = %+v, want empty", res)
	}
}

func TestHSTSMaxAge(t *testing.T) {
	tests := []struct {
		in  string
		age int64
		ok  bool
	}{
		{"max-age=31536000", 31536000, true},
		{"includeSubDomains; MAX-AGE=\"600\"; preload", 600, true},
		{"max-age=0", 0, true},
		{"", 0, false},
		{"max-age=abc", 0, false},
		{"max-age=-5", 0, false},
	}
	for _, tt := range tests {
		age, ok := hstsMaxAge(tt.in)
		if age != tt.age || ok != tt.ok {
			t.Errorf("hstsMaxAge(%q) = %d, %v; want %d, %v", tt.in, age, ok, tt.age, tt.ok)
		}
	}
}

func TestFramingProtected(t *testing.T) {
	tests := []struct {
		xfo, csp string
		want     bool
	}{
		{"DENY", "", true},
		{"sameorigin", "", true},
		{"ALLOW-FROM https://x", "", false},
		{"", "default-src 'self'; frame-ancestors 'none'", true},
		{"", "frame-ancestors *", false},
		{"", "default-src 'self'", false},
		{"", "", false},
	}
	for _, tt := range tests {
		if got := framingProtected(tt.xfo, tt.csp); got != tt.want {
			t.Errorf("framingProtected(%q, %q) = %v, want %v", tt.xfo, tt.csp, got, tt.want)
		}
	}
}

func TestVersionPattern(t *testing.T) {
	tests := []struct {
		in   string
		want bool
	}{
		{"nginx/1.24.0 (Ubuntu)", true},
		{"Apache/2.4.58 (Debian)", true},
		{"Microsoft-IIS/10.0", true},
		{"PHP/8.1.2", true},
		{"4.0.30319", true},
		{"nginx", false},
		{"cloudflare", false},
		{"Apache", false},
		{"AmazonS3", false},
	}
	for _, tt := range tests {
		if got := versionPattern.MatchString(tt.in); got != tt.want {
			t.Errorf("versionPattern(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}

func TestSanitize(t *testing.T) {
	if got := sanitize("ok\x1b[31mred\x00", 100); got != "ok.[31mred." {
		t.Errorf("sanitize control chars = %q", got)
	}
	if got := sanitize(strings.Repeat("a", 500), 10); len(got) != 10 {
		t.Errorf("sanitize bound: len = %d, want 10", len(got))
	}
}

func TestResolveLocation(t *testing.T) {
	base := &url.URL{Scheme: "https", Host: "example.com", Path: "/"}
	tests := []struct {
		loc  string
		want string // "" means rejected
	}{
		{"/fr/", "https://example.com/fr/"},
		{"https://www.example.com/", "https://www.example.com/"},
		{"http://example.com/x?y=1", "http://example.com/x?y=1"},
		{"javascript:alert(1)", ""},
		{"https://user@evil.example/", ""},
		{"", ""},
		{"/" + strings.Repeat("a", maxLocation), ""},
	}
	for _, tt := range tests {
		got := resolveLocation(base, tt.loc)
		if (got == nil) != (tt.want == "") || (got != nil && got.String() != tt.want) {
			t.Errorf("resolveLocation(%q) = %v, want %q", tt.loc, got, tt.want)
		}
	}
}
