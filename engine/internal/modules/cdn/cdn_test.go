package cdn

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"syscall"
	"testing"

	"github.com/jordyorel/orus-shield/engine/internal/asset"
	"github.com/jordyorel/orus-shield/engine/internal/dialer"
	"github.com/jordyorel/orus-shield/engine/internal/module"
	"github.com/jordyorel/orus-shield/engine/internal/resolver"
)

// ---- Fakes (no real network: rule 6) ---------------------------------------

type fakeDNS struct {
	ips map[string][]netip.Addr
	err error
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

func (f *fakeDNS) LookupIP(_ context.Context, host string) ([]netip.Addr, error) {
	if f.err != nil {
		return nil, f.err
	}
	if ips, ok := f.ips[host]; ok {
		return ips, nil
	}
	return nil, fmt.Errorf("lookup %s: %w", host, resolver.ErrNotFound)
}

// fakeDialer routes "ip:443" to local test servers; anything else is
// refused like a closed port.
type fakeDialer struct {
	mu     sync.Mutex
	routes map[string]string
	dialed []string
}

func (f *fakeDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	f.mu.Lock()
	f.dialed = append(f.dialed, address)
	target, ok := f.routes[address]
	f.mu.Unlock()
	if !ok {
		return nil, &net.OpError{Op: "dial", Net: network, Err: syscall.ECONNREFUSED}
	}
	var d net.Dialer
	return d.DialContext(ctx, network, target)
}

type fakeGate struct {
	mu   sync.Mutex
	seen []module.Destination
	deny map[netip.Addr]error
}

func (g *fakeGate) Allow(_ context.Context, dest module.Destination) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.seen = append(g.seen, dest)
	return g.deny[dest.IP]
}

var (
	cloudflareIP = netip.MustParseAddr("104.16.1.1")
	fastlyIP     = netip.MustParseAddr("2a04:4e42::1")
	plainIP      = netip.MustParseAddr("192.0.2.10")
)

// serve starts a TLS server answering with the given headers and returns
// its address. It also records the requests it got.
func serve(t *testing.T, headers map[string]string, got *[]*http.Request) string {
	t.Helper()
	var mu sync.Mutex
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		if got != nil {
			*got = append(*got, r)
		}
		mu.Unlock()
		for k, v := range headers {
			w.Header().Set(k, v)
		}
	}))
	t.Cleanup(srv.Close)
	return srv.Listener.Addr().String()
}

func run(t *testing.T, dns *fakeDNS, dial *fakeDialer, g *fakeGate) (module.Result, error) {
	t.Helper()
	return New(dns, dial).Run(context.Background(), module.Request{Target: module.Target{Domain: "example.com"}, Gate: g})
}

func byKey(assets []asset.Asset) map[string]asset.Asset {
	out := make(map[string]asset.Asset)
	for _, a := range assets {
		out[a.Key()] = a
	}
	return out
}

func route(ip netip.Addr) string { return netip.AddrPortFrom(ip, 443).String() }

// ---- Tests ----------------------------------------------------------------

func TestRangesParse(t *testing.T) {
	if len(ranges) == 0 {
		t.Fatal("no ranges")
	}
	tests := []struct {
		ip   string
		want string // "" = no CDN
	}{
		{"104.16.1.1", "cloudflare"},
		{"2606:4700::1111", "cloudflare"},
		{"::ffff:104.16.1.1", "cloudflare"}, // IPv4-mapped
		{"151.101.1.69", "fastly"},
		{"2a04:4e43::1", "fastly"}, // inside 2a04:4e42::/31
		{"192.0.2.10", ""},
		{"8.8.8.8", ""},
	}
	for _, tt := range tests {
		got, _, ok := providerOf(netip.MustParseAddr(tt.ip))
		if ok != (tt.want != "") || got != tt.want {
			t.Errorf("providerOf(%s) = %q, %v; want %q", tt.ip, got, ok, tt.want)
		}
	}
}

func TestSignatures(t *testing.T) {
	tests := []struct {
		name    string
		headers map[string]string
		want    string
		waf     bool
	}{
		{"cloudflare ray", map[string]string{"Cf-Ray": "8a1b-CDG"}, "cloudflare", false},
		{"cloudflare server", map[string]string{"Server": "cloudflare"}, "cloudflare", false},
		{"cloudfront", map[string]string{"X-Amz-Cf-Id": "abc"}, "cloudfront", false},
		{"cloudfront via", map[string]string{"Via": "1.1 abc.cloudfront.net (CloudFront)"}, "cloudfront", false},
		{"fastly", map[string]string{"X-Fastly-Request-Id": "abc"}, "fastly", false},
		{"akamai", map[string]string{"Server": "AkamaiGHost"}, "akamai", false},
		{"azure", map[string]string{"X-Azure-Ref": "abc"}, "azure-front-door", false},
		{"vercel", map[string]string{"X-Vercel-Id": "cdg1::abc"}, "vercel", false},
		{"netlify", map[string]string{"X-Nf-Request-Id": "abc"}, "netlify", false},
		{"sucuri is a WAF", map[string]string{"X-Sucuri-Id": "1", "Cf-Ray": "x"}, "sucuri", true},
		{"imperva is a WAF", map[string]string{"X-Iinfo": "1-2-3"}, "imperva", true},
		{"plain nginx", map[string]string{"Server": "nginx"}, "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := http.Header{}
			for k, v := range tt.headers {
				h.Set(k, v)
			}
			sig, ev, ok := detect(h)
			if ok != (tt.want != "") || sig.provider != tt.want || sig.waf != tt.waf {
				t.Errorf("detect = %q (waf %v), %v; want %q (waf %v)", sig.provider, sig.waf, ok, tt.want, tt.waf)
			}
			if ok && !strings.HasPrefix(ev, "header ") {
				t.Errorf("evidence = %q, want the header that matched", ev)
			}
		})
	}
}

func TestBehindCloudflare(t *testing.T) {
	var requests []*http.Request
	dns := &fakeDNS{ips: map[string][]netip.Addr{"example.com": {cloudflareIP}}}
	dial := &fakeDialer{routes: map[string]string{route(cloudflareIP): serve(t, map[string]string{"Cf-Ray": "8a1b-CDG"}, &requests)}}
	res, err := run(t, dns, dial, &fakeGate{})
	if err != nil {
		t.Fatal(err)
	}
	assets := byKey(res.Assets)
	if d := assets["ip 104.16.1.1"].Details; d[DetailCDN] != "cloudflare" || !strings.Contains(d[DetailCDNEvidence], "104.16.0.0/13") {
		t.Errorf("ip details = %v", d)
	}
	if d := assets["hostname example.com"].Details; d[DetailCDN] != "cloudflare" || d[DetailWAF] != None || d[DetailCDNEvidence] != "header cf-ray" {
		t.Errorf("hostname details = %v", d)
	}
	if len(res.Findings) != 0 || len(res.Evaluated) != 0 {
		t.Errorf("result has findings or checks: %+v", res)
	}
	// One request, a HEAD, with the right Host.
	if len(requests) != 1 || requests[0].Method != http.MethodHead || requests[0].Host != "example.com" {
		t.Errorf("requests = %+v, want one HEAD for example.com", requests)
	}
	for _, a := range res.Assets {
		if err := a.Validate("example.com"); err != nil {
			t.Errorf("invalid asset %+v: %v", a, err)
		}
	}
}

func TestNoCDNIsSaidExplicitly(t *testing.T) {
	dns := &fakeDNS{ips: map[string][]netip.Addr{"example.com": {plainIP}, "www.example.com": {fastlyIP}}}
	dial := &fakeDialer{routes: map[string]string{route(plainIP): serve(t, map[string]string{"Server": "nginx"}, nil)}}
	res, err := run(t, dns, dial, &fakeGate{})
	if err != nil {
		t.Fatal(err)
	}
	assets := byKey(res.Assets)
	if d := assets["hostname example.com"].Details; d[DetailCDN] != None || d[DetailWAF] != None {
		t.Errorf("plain site details = %v, want cdn and waf none", d)
	}
	if d := assets["ip 192.0.2.10"].Details; d[DetailCDN] != None {
		t.Errorf("plain ip details = %v", d)
	}
	// www resolves to a Fastly address but nothing answers: the address is
	// still known to be Fastly's, the site itself is not described.
	if d := assets["ip 2a04:4e42::1"].Details; d[DetailCDN] != "fastly" {
		t.Errorf("fastly ip details = %v", d)
	}
	if _, ok := assets["hostname www.example.com"]; ok {
		t.Error("a site that did not answer is described")
	}
}

func TestTriesNextAddressAndRespectsExclusions(t *testing.T) {
	second := netip.MustParseAddr("192.0.2.20")
	dns := &fakeDNS{ips: map[string][]netip.Addr{"example.com": {plainIP, second}}}
	dial := &fakeDialer{routes: map[string]string{
		route(plainIP): serve(t, map[string]string{"Cf-Ray": "x"}, nil),
		route(second):  serve(t, map[string]string{"X-Vercel-Id": "x"}, nil),
	}}
	g := &fakeGate{deny: map[netip.Addr]error{plainIP: fmt.Errorf("rule 3: %w", module.ErrExcluded)}}
	res, err := run(t, dns, dial, g)
	if err != nil {
		t.Fatal(err)
	}
	if d := byKey(res.Assets)["hostname example.com"].Details; d[DetailCDN] != "vercel" {
		t.Errorf("details = %v, want the second, not excluded, address", d)
	}
	for _, a := range dial.dialed {
		if a == route(plainIP) {
			t.Error("connected to an excluded address")
		}
	}
	for _, d := range g.seen {
		if d.Port == 443 && d.Path != "/" {
			t.Errorf("HTTP destination %+v without its path: path exclusions could not apply", d)
		}
	}
}

func TestRunErrors(t *testing.T) {
	stop := errors.New("rate limiter closed")
	tests := []struct {
		name string
		dns  *fakeDNS
		gate *fakeGate
	}{
		{"DNS failure", &fakeDNS{err: errors.New("servfail")}, &fakeGate{}},
		{"gate failure", &fakeDNS{ips: map[string][]netip.Addr{"example.com": {plainIP}}},
			&fakeGate{deny: map[netip.Addr]error{plainIP: stop}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := run(t, tt.dns, &fakeDialer{routes: map[string]string{}}, tt.gate)
			if err == nil {
				t.Error("Run() = nil, want error")
			}
		})
	}
	// The gate refusal is a stop error, not a silent skip.
	_, err := run(t, &fakeDNS{ips: map[string][]netip.Addr{"example.com": {plainIP}}},
		&fakeDialer{routes: map[string]string{}}, &fakeGate{deny: map[netip.Addr]error{plainIP: stop}})
	if !errors.Is(err, dialer.ErrGateRefused) {
		t.Errorf("gate refusal = %v, want ErrGateRefused", err)
	}
}

func TestHeadersAreBounded(t *testing.T) {
	huge := strings.Repeat("x", maxHeaderBytes)
	dns := &fakeDNS{ips: map[string][]netip.Addr{"example.com": {plainIP}}}
	dial := &fakeDialer{routes: map[string]string{route(plainIP): serve(t, map[string]string{"X-Huge": huge, "Cf-Ray": "x"}, nil)}}
	res, err := run(t, dns, dial, &fakeGate{})
	if err != nil {
		t.Fatal(err)
	}
	// Headers over the limit are not read: the site is not described.
	if _, ok := byKey(res.Assets)["hostname example.com"]; ok {
		t.Error("oversized headers were accepted")
	}
}

func TestRegisters(t *testing.T) {
	m := New(&fakeDNS{}, &fakeDialer{})
	if info := m.Info(); info.ID != ID || info.Kind != module.KindPassive {
		t.Errorf("Info = %+v", info)
	}
	if err := module.NewRegistry().Register(m); err != nil {
		t.Fatal(err)
	}
}
