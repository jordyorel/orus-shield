package discovery

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jordyorel/orus-shield/engine/internal/module"
	"github.com/jordyorel/orus-shield/engine/internal/resolver"
)

type fakeCT struct {
	names []string
	err   error
}

func (f fakeCT) Names(context.Context, string) ([]string, error) { return f.names, f.err }

// fakeDNS answers from a map; with wildcard set, every other name under
// example.com resolves to it.
type fakeDNS struct {
	mu       sync.Mutex
	ips      map[string][]netip.Addr
	wildcard []netip.Addr
	fail     error
	asked    []string
}

func (f *fakeDNS) LookupIP(_ context.Context, host string) ([]netip.Addr, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.asked = append(f.asked, host)
	if f.fail != nil {
		return nil, f.fail
	}
	if a, ok := f.ips[host]; ok {
		return a, nil
	}
	if f.wildcard != nil && strings.HasSuffix(host, ".example.com") {
		return f.wildcard, nil
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

// fakeGate excludes some hosts.
type fakeGate struct{ excluded []string }

func (g fakeGate) Allow(_ context.Context, d module.Destination) error {
	if slices.Contains(g.excluded, d.Host) {
		return fmt.Errorf("host %s: %w", d.Host, module.ErrExcluded)
	}
	return nil
}

var (
	ip1 = netip.MustParseAddr("192.0.2.1")
	ip2 = netip.MustParseAddr("192.0.2.2")
	wc  = netip.MustParseAddr("198.51.100.99")
)

func run(t *testing.T, ct CTSource, dns *fakeDNS, g module.Gate) (map[string]string, error) {
	t.Helper()
	res, err := New(dns, ct).Run(context.Background(), module.Request{Target: module.Target{Domain: "example.com"}, Gate: g})
	found := make(map[string]string)
	for _, a := range res.Assets {
		if err := a.Validate("example.com"); err != nil {
			t.Errorf("invalid asset %+v: %v", a, err)
		}
		found[a.Value] = a.Details[DetailSource]
	}
	if len(res.Findings) != 0 || len(res.Evaluated) != 0 {
		t.Errorf("discovery returned findings or checks: %+v", res)
	}
	return found, err
}

func TestDiscoversFromCTAndDNS(t *testing.T) {
	ct := fakeCT{names: []string{
		"vpn.example.com", "*.example.com", "example.com", "www.example.com", // the last three are dropped
		"VPN.Example.com.", "old.example.com", // duplicate; a name that no longer resolves
		"mail.example.com",                             // also a common guess
		"evil.com", "example.com.evil.com", "bad name", // not ours or malformed
	}}
	dns := &fakeDNS{ips: map[string][]netip.Addr{
		"vpn.example.com":      {ip1},
		"mail.example.com":     {ip2},
		"extranet.example.com": {ip1},
		"evil.com":             {ip2},
	}}
	found, err := run(t, ct, dns, fakeGate{})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"vpn.example.com": "ct,dns", "old.example.com": "", "mail.example.com": "ct,dns", "extranet.example.com": "dns"}
	delete(want, "old.example.com") // in CT but no longer resolves
	if len(found) != len(want) {
		t.Fatalf("found %v, want %v", found, want)
	}
	for name, src := range want {
		if found[name] != src {
			t.Errorf("%s: source %q, want %q", name, found[name], src)
		}
	}
	if slices.Contains(dns.asked, "evil.com") {
		t.Error("looked up a name outside the domain")
	}
}

func TestWildcardGuessesAreDropped(t *testing.T) {
	// *.example.com resolves to wc. A guess landing there is not a server;
	// a CT name is kept (a certificate was issued for it); a guess with
	// its own address is kept.
	dns := &fakeDNS{
		ips:      map[string][]netip.Addr{"intranet.example.com": {ip1}},
		wildcard: []netip.Addr{wc},
	}
	found, err := run(t, fakeCT{names: []string{"pay.example.com"}}, dns, fakeGate{})
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 2 || found["pay.example.com"] != "ct" || found["intranet.example.com"] != "dns" {
		t.Errorf("found %v, want pay (ct) and intranet (dns) only", found)
	}
}

func TestExcludedHostsAreSkipped(t *testing.T) {
	dns := &fakeDNS{ips: map[string][]netip.Addr{"vpn.example.com": {ip1}, "dev.example.com": {ip2}}}
	found, err := run(t, fakeCT{names: []string{"vpn.example.com"}}, dns, fakeGate{excluded: []string{"dev.example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := found["dev.example.com"]; ok || len(found) != 1 {
		t.Errorf("found %v, want vpn only (dev is excluded)", found)
	}
}

func TestFailures(t *testing.T) {
	if _, err := run(t, fakeCT{err: errors.New("502")}, &fakeDNS{}, fakeGate{}); err == nil {
		t.Error("CT failure: nil error, want the run to fail (the inventory must not forget CT names)")
	}
	if _, err := run(t, fakeCT{}, &fakeDNS{fail: errors.New("servfail")}, fakeGate{}); err == nil {
		t.Error("DNS failure: nil error")
	}
	_, err := New(&fakeDNS{}, fakeCT{}).Run(context.Background(), module.Request{Target: module.Target{Domain: "not a domain"}, Gate: fakeGate{}})
	if err == nil {
		t.Error("invalid domain: nil error")
	}
}

func TestCandidatesAreBounded(t *testing.T) {
	var names []string
	for i := range 500 {
		names = append(names, fmt.Sprintf("h%03d.example.com", i))
	}
	dns := &fakeDNS{}
	if _, err := run(t, fakeCT{names: names}, dns, fakeGate{}); err != nil {
		t.Fatal(err)
	}
	// maxResolve candidates plus the wildcard probe.
	if got := len(dns.asked); got != maxResolve+1 {
		t.Errorf("DNS lookups = %d, want %d", got, maxResolve+1)
	}
}

func TestInfo(t *testing.T) {
	info := New(nil, nil).Info()
	if info.ID != ID || info.Kind != module.KindPassive || !info.ProvidesHosts {
		t.Errorf("Info = %+v", info)
	}
}

func TestCrtsh(t *testing.T) {
	var query string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query = r.URL.RawQuery
		_, _ = w.Write([]byte(`[{"name_value":"vpn.example.com\n*.example.com"},{"name_value":"VPN.example.com"},{"name_value":"mail.example.com","other":1}]`))
	}))
	defer srv.Close()

	names, err := Crtsh{BaseURL: srv.URL + "/", Client: srv.Client()}.Names(context.Background(), "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(names, []string{"vpn.example.com", "*.example.com", "mail.example.com"}) {
		t.Errorf("names = %v", names)
	}
	if query != "output=json&q=%25.example.com" {
		t.Errorf("query = %q", query)
	}
}

func TestCrtshErrors(t *testing.T) {
	tests := []struct {
		name    string
		handler http.HandlerFunc
	}{
		{"server error", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusBadGateway) }},
		{"not json", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("<html>busy</html>")) }},
		{"too big", func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`[{"name_value":"`))
			chunk := []byte(strings.Repeat("a", 1<<20))
			for range (maxCrtshBytes >> 20) + 1 {
				if _, err := w.Write(chunk); err != nil {
					return
				}
			}
			_, _ = w.Write([]byte(`"}]`))
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(tt.handler)
			defer srv.Close()
			if _, err := (Crtsh{BaseURL: srv.URL, Client: srv.Client(), RetryAfter: time.Millisecond}).Names(context.Background(), "example.com"); err == nil {
				t.Error("nil error")
			}
		})
	}
}

func TestCrtshRetriesOnce(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls == 1 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		_, _ = w.Write([]byte(`[{"name_value":"vpn.example.com"}]`))
	}))
	defer srv.Close()
	names, err := Crtsh{BaseURL: srv.URL, Client: srv.Client(), RetryAfter: time.Millisecond}.Names(context.Background(), "example.com")
	if err != nil || len(names) != 1 || calls != 2 {
		t.Errorf("names %v, err %v, calls %d; want the second attempt's answer", names, err, calls)
	}
}
