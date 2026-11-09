package ownership

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"

	"github.com/jordyorel/orus-shield/engine/internal/module"
)

var (
	vpsIP     = netip.MustParseAddr("192.0.2.10")
	sharedIP  = netip.MustParseAddr("198.51.100.20")
	vpsIPv6   = netip.MustParseAddr("2001:db8::10")
	unknownIP = netip.MustParseAddr("203.0.113.30")
)

// labDNS models a customer with one VPS of their own (PTR set to a name
// under their domain) and a website on shared hosting (PTR owned by the
// hosting provider).
func labDNS() *fakeDNS {
	return &fakeDNS{
		ips: map[string][]netip.Addr{
			"srv1.example.com":     {vpsIP, vpsIPv6},
			"www.example.com":      {sharedIP},
			"stale.example.com":    {vpsIP}, // PTR copied: the name points elsewhere
			"host.hosting.example": {sharedIP},
		},
		ptr: map[netip.Addr][]string{
			vpsIP:     {"srv1.example.com"},
			vpsIPv6:   {"SRV1.Example.com."}, // case and trailing dot ignored
			sharedIP:  {"host.hosting.example"},
			unknownIP: {"stale.example.com", "evilexample.com"},
		},
	}
}

func TestCheckIP(t *testing.T) {
	tests := []struct {
		name   string
		dns    func(d *fakeDNS)
		ip     netip.Addr
		want   bool
		reason string // expected in the reason when refused
	}{
		{"own VPS", nil, vpsIP, true, ""},
		{"own VPS, IPv6, case and trailing dot", nil, vpsIPv6, true, ""},
		{"IPv4-mapped form of own VPS", nil, netip.AddrFrom16(vpsIP.As16()), true, ""},
		{"shared hosting: PTR belongs to the provider", nil, sharedIP, false, "not a name under example.com"},
		{"no PTR at all", nil, netip.MustParseAddr("203.0.113.99"), false, "no reverse DNS"},
		{"PTR under domain but not resolving back", nil, unknownIP, false, "does not resolve back"},
		{"suffix trick evilexample.com", func(d *fakeDNS) {
			d.ptr[unknownIP] = []string{"evilexample.com"}
			d.ips["evilexample.com"] = []netip.Addr{unknownIP}
		}, unknownIP, false, "not a name under example.com"},
		{"PTR is the apex itself", func(d *fakeDNS) {
			d.ptr[unknownIP] = []string{"example.com"}
			d.ips["example.com"] = []netip.Addr{unknownIP}
		}, unknownIP, true, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := labDNS()
			if tt.dns != nil {
				tt.dns(d)
			}
			ok, reason, err := CheckIP(context.Background(), d, "example.com", tt.ip)
			if err != nil {
				t.Fatalf("CheckIP error = %v", err)
			}
			if ok != tt.want {
				t.Errorf("CheckIP = %v (%s), want %v", ok, reason, tt.want)
			}
			if !ok && !strings.Contains(reason, tt.reason) {
				t.Errorf("reason = %q, want it to mention %q", reason, tt.reason)
			}
		})
	}
}

func TestCheckIPDNSFailure(t *testing.T) {
	d := labDNS()
	d.err = &net.DNSError{Err: "server misbehaving"}
	ok, _, err := CheckIP(context.Background(), d, "example.com", vpsIP)
	if ok || err == nil {
		t.Errorf("CheckIP = %v, %v; want false with an error", ok, err)
	}
}

// countingGate allows everything and records what it saw.
type countingGate struct {
	mu   sync.Mutex
	seen []module.Destination
}

func (g *countingGate) Allow(ctx context.Context, dest module.Destination) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.seen = append(g.seen, dest)
	return nil
}

func newIPGate(d *fakeDNS) (module.Gate, *countingGate, *[]string) {
	inner := &countingGate{}
	var refused []string
	v := New(&fakeStore{}, d)
	g := v.IPGate(inner, "example.com", func(ip netip.Addr, reason string) {
		refused = append(refused, ip.String())
	})
	return g, inner, &refused
}

func TestIPGate(t *testing.T) {
	ctx := context.Background()
	d := labDNS()
	g, inner, refused := newIPGate(d)

	// Own VPS: allowed, and the connection reaches the inner gate.
	conn := module.Destination{Host: "srv1.example.com", IP: vpsIP, Port: 22}
	if err := g.Allow(ctx, conn); err != nil {
		t.Fatalf("Allow(own VPS) = %v", err)
	}

	// Shared hosting: refused like an exclusion, reported once.
	shared := module.Destination{Host: "www.example.com", IP: sharedIP, Port: 22}
	for range 3 {
		err := g.Allow(ctx, shared)
		if !errors.Is(err, module.ErrExcluded) || !errors.Is(err, ErrIPNotVerified) {
			t.Fatalf("Allow(shared IP) = %v, want ErrExcluded and ErrIPNotVerified", err)
		}
	}
	if len(*refused) != 1 || (*refused)[0] != sharedIP.String() {
		t.Errorf("refusals reported = %v, want one for %s", *refused, sharedIP)
	}

	// Requests without an IP (DNS by name) are not IP-checked.
	if err := g.Allow(ctx, module.Destination{Host: "example.com"}); err != nil {
		t.Errorf("Allow(name only) = %v", err)
	}

	// Results are cached: each IP was checked once (one PTR lookup each).
	ptr := 0
	for _, c := range d.calls {
		if strings.HasPrefix(c, "PTR ") {
			ptr++
		}
	}
	if ptr != 2 {
		t.Errorf("%d PTR lookups, want 2 (cached per IP): %v", ptr, d.calls)
	}

	// The gate's own DNS lookups went through the inner gate (rate limit,
	// exclusions), as did the allowed connection; the refused one did not.
	var sawConn, sawShared bool
	for _, s := range inner.seen {
		sawConn = sawConn || (s == conn)
		sawShared = sawShared || (s == shared)
	}
	if !sawConn || sawShared {
		t.Errorf("inner gate saw allowed=%v refused=%v, want true/false", sawConn, sawShared)
	}
	if len(inner.seen) < 4 { // PTR + A for the VPS, PTR for shared, the connection...
		t.Errorf("inner gate saw only %d requests; DNS checks must go through it", len(inner.seen))
	}
}

// A DNS failure refuses the IP (fail closed).
func TestIPGateFailsClosed(t *testing.T) {
	d := labDNS()
	d.err = &net.DNSError{Err: "i/o timeout", IsTimeout: true}
	g, _, refused := newIPGate(d)
	err := g.Allow(context.Background(), module.Destination{IP: vpsIP, Port: 22})
	if !errors.Is(err, module.ErrExcluded) {
		t.Errorf("Allow during DNS outage = %v, want a refusal", err)
	}
	if len(*refused) != 1 || !strings.Contains(err.Error(), "could not verify") {
		t.Errorf("refusal = %v, reported %v", err, *refused)
	}
}

func TestIPGateCancelledScan(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	g, _, refused := newIPGate(labDNS())
	err := g.Allow(ctx, module.Destination{IP: vpsIP, Port: 22})
	if !errors.Is(err, context.Canceled) {
		t.Errorf("Allow on cancelled scan = %v, want context.Canceled", err)
	}
	if len(*refused) != 0 {
		t.Error("a cancelled scan reported a refusal")
	}
}
