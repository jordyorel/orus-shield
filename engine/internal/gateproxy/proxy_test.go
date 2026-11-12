package gateproxy

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/jordyorel/orus-shield/engine/internal/module"
	"github.com/jordyorel/orus-shield/engine/internal/resolver"
)

// The targets are local httptest servers; a fake resolver points the test
// names at 127.0.0.1, so nothing outside this machine is contacted (rule 6).

type fakeDNS struct{ hosts map[string]netip.Addr }

func (f fakeDNS) LookupTXT(context.Context, string) ([]string, error) {
	return nil, resolver.ErrNotFound
}
func (f fakeDNS) LookupMX(context.Context, string) ([]*net.MX, error) {
	return nil, resolver.ErrNotFound
}
func (f fakeDNS) LookupAddr(context.Context, netip.Addr) ([]string, error) {
	return nil, resolver.ErrNotFound
}
func (f fakeDNS) LookupIP(_ context.Context, host string) ([]netip.Addr, error) {
	if ip, ok := f.hosts[host]; ok {
		return []netip.Addr{ip}, nil
	}
	return nil, fmt.Errorf("lookup %s: %w", host, resolver.ErrNotFound)
}

// recordGate records every destination and refuses those deny matches.
type recordGate struct {
	mu   sync.Mutex
	seen []module.Destination
	deny func(module.Destination) error
}

func (g *recordGate) Allow(_ context.Context, d module.Destination) error {
	g.mu.Lock()
	g.seen = append(g.seen, d)
	g.mu.Unlock()
	if g.deny != nil {
		return g.deny(d)
	}
	return nil
}

func (g *recordGate) paths() []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	var out []string
	for _, d := range g.seen {
		if d.IP.IsValid() {
			out = append(out, fmt.Sprintf("%s:%d%s", d.Host, d.Port, d.Path))
		}
	}
	return out
}

var localhost = netip.MustParseAddr("127.0.0.1")

func dns() fakeDNS {
	return fakeDNS{hosts: map[string]netip.Addr{"example.com": localhost, "app.example.com": localhost, "other.test": localhost}}
}

func start(t *testing.T, g module.Gate) *Proxy {
	t.Helper()
	p, err := Start(context.Background(), Config{Domain: "example.com", Gate: g, DNS: dns(), Dial: &net.Dialer{}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Close() })
	return p
}

// client is the scanner's side: it trusts the proxy's throwaway
// certificate, like Nuclei which does not verify certificates.
func client(proxyURL string) *http.Client {
	u, _ := url.Parse(proxyURL)
	return &http.Client{Transport: &http.Transport{
		Proxy:           http.ProxyURL(u),
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // G402: test client of the proxy's throwaway certificate
	}}
}

func port(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	u, _ := url.Parse(srv.URL)
	return u.Port()
}

// target answers with the request line and whether a proxy credential leaked.
func target(t *testing.T, tlsOn bool) (*httptest.Server, *int) {
	t.Helper()
	hits := new(int)
	var mu sync.Mutex
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		*hits++
		mu.Unlock()
		w.Header().Set("X-Seen-Auth", r.Header.Get("Proxy-Authorization"))
		_, _ = fmt.Fprintf(w, "%s %s host=%s", r.Method, r.URL.RequestURI(), r.Host) //nolint:gosec // G705: test server echoing the request as plain text to the test client

	})
	var srv *httptest.Server
	if tlsOn {
		srv = httptest.NewTLSServer(h)
	} else {
		srv = httptest.NewServer(h)
	}
	t.Cleanup(srv.Close)
	return srv, hits
}

// answer is what get read: the response is closed already.
type answer struct {
	code   int
	header http.Header
	body   string
}

func get(t *testing.T, c *http.Client, u string) answer {
	t.Helper()
	resp, err := c.Get(u)
	if err != nil {
		t.Fatalf("GET %s: %v", u, err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return answer{resp.StatusCode, resp.Header, string(b)}
}

func TestForwardsThroughTheGate(t *testing.T) {
	for _, tlsOn := range []bool{false, true} {
		scheme := map[bool]string{false: "http", true: "https"}[tlsOn]
		t.Run(scheme, func(t *testing.T) {
			srv, _ := target(t, tlsOn)
			g := &recordGate{}
			p := start(t, g)
			c := client(p.URL())
			for _, path := range []string{"/.git/config?x=1", "/admin/login"} {
				u := scheme + "://app.example.com:" + port(t, srv) + path
				a := get(t, c, u)
				if a.code != 200 || !strings.HasPrefix(a.body, "GET "+path+" host=app.example.com") {
					t.Errorf("%s: %d %q", u, a.code, a.body)
				}
				if a.header.Get("X-Seen-Auth") != "" {
					t.Errorf("proxy credential reached the target")
				}
			}
			want := []string{"app.example.com:" + port(t, srv) + "/.git/config", "app.example.com:" + port(t, srv) + "/admin/login"}
			if got := g.paths(); strings.Join(got, " ") != strings.Join(want, " ") {
				t.Errorf("gate saw %v, want one approval per request %v", got, want)
			}
			if s := p.Stats(); s.Requests != 2 || s.Answered != 2 || s.Refused != 0 {
				t.Errorf("stats = %+v", s)
			}
		})
	}
}

func TestRefusals(t *testing.T) {
	srv, hits := target(t, false)
	tlsSrv, tlsHits := target(t, true)
	g := &recordGate{deny: func(d module.Destination) error {
		if strings.HasPrefix(d.Path, "/private") {
			return fmt.Errorf("path excluded: %w", module.ErrExcluded)
		}
		return nil
	}}
	p := start(t, g)
	c := client(p.URL())

	tests := []struct{ url, kind string }{
		{"http://other.test:" + port(t, srv) + "/", "scope"},
		{"http://evilexample.com:" + port(t, srv) + "/", "scope"},
		{"http://127.0.0.1:" + port(t, srv) + "/", "scope"},
		{"http://app.example.com:" + port(t, srv) + "/private/x", "excluded"},
		{"https://app.example.com:" + port(t, tlsSrv) + "/private/../private/y", "excluded"},
	}
	for _, tt := range tests {
		resp, err := c.Get(tt.url)
		if err != nil {
			// CONNECT refused for an out-of-scope host: the client
			// reports the proxy's answer as an error.
			if tt.kind == "scope" && strings.Contains(err.Error(), "Forbidden") {
				continue
			}
			t.Errorf("GET %s: %v", tt.url, err)
			continue
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden || resp.Header.Get(RefusedHeader) != tt.kind {
			t.Errorf("%s: %d %q, want 403 %s", tt.url, resp.StatusCode, resp.Header.Get(RefusedHeader), tt.kind)
		}
	}
	if *hits != 0 || *tlsHits != 0 {
		t.Errorf("refused requests reached the target: %d, %d", *hits, *tlsHits)
	}
}

func TestRequiresTheCredential(t *testing.T) {
	srv, hits := target(t, false)
	p := start(t, &recordGate{})
	u, _ := url.Parse(p.URL())
	u.User = url.UserPassword("orus", "wrong")
	for _, pu := range []*url.URL{{Scheme: "http", Host: u.Host}, u} {
		c := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(pu)}}
		resp, err := c.Get("http://app.example.com:" + port(t, srv) + "/")
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusProxyAuthRequired {
			t.Errorf("credential %v: status %d, want 407", pu.User, resp.StatusCode)
		}
	}
	if *hits != 0 {
		t.Error("unauthenticated request reached the target")
	}
}

func TestBoundsTheResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("a", maxResponseBody+1000)))
	}))
	t.Cleanup(srv.Close)
	p := start(t, &recordGate{})
	a := get(t, client(p.URL()), "http://example.com:"+port(t, srv)+"/")
	if len(a.body) != maxResponseBody {
		t.Errorf("relayed %d bytes, want the %d byte bound", len(a.body), maxResponseBody)
	}
}

func TestStoppedScanIsAnError(t *testing.T) {
	srv, hits := target(t, false)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var stop atomic.Bool
	g := &recordGate{deny: func(d module.Destination) error {
		if !d.IP.IsValid() {
			return nil // DNS lookups pass
		}
		if stop.Load() {
			cancel() // the scan ends while the request waits on the limiter
		}
		return errors.New("rate limiter stopped")
	}}
	p, err := Start(ctx, Config{Domain: "example.com", Gate: g, DNS: dns(), Dial: &net.Dialer{}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Close() })
	c := client(p.URL())

	// A limiter failure while the scan is alive: refused, not fatal.
	a := get(t, c, "http://example.com:"+port(t, srv)+"/")
	if a.code != http.StatusForbidden || p.Err() != nil {
		t.Errorf("status %d, err %v; want 403 and no fatal error", a.code, p.Err())
	}
	// The same failure once the scan is over: the run must fail.
	stop.Store(true)
	if resp, err := c.Get("http://example.com:" + port(t, srv) + "/again"); err == nil {
		_ = resp.Body.Close()
	}
	_ = p.Close()
	if p.Err() == nil {
		t.Error("stopped scan: Err() = nil")
	}
	if *hits != 0 {
		t.Error("request reached the target despite the gate")
	}
}

func TestStartValidates(t *testing.T) {
	if _, err := Start(context.Background(), Config{Domain: "example.com"}); err == nil {
		t.Error("no gate: nil error")
	}
	if _, err := Start(context.Background(), Config{Domain: "not a domain", Gate: &recordGate{}, DNS: dns(), Dial: &net.Dialer{}}); err == nil {
		t.Error("bad domain: nil error")
	}
}
