package resolver

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"testing"
)

// fakeAuthority answers from maps: no real DNS (security rule 6).
type fakeAuthority struct {
	ns    map[string][]string
	ips   map[string][]netip.Addr
	txt   map[netip.Addr][]string // per server; nil value: "does not exist"
	down  map[netip.Addr]bool     // servers that do not answer
	asked []string
}

func (f *fakeAuthority) authority() authority {
	return authority{
		lookupNS: func(_ context.Context, zone string) ([]string, error) {
			f.asked = append(f.asked, "NS "+zone)
			if ns, ok := f.ns[zone]; ok {
				return ns, nil
			}
			return nil, fmt.Errorf("lookup %s: %w", zone, ErrNotFound)
		},
		lookupIP: func(_ context.Context, host string) ([]netip.Addr, error) {
			if a, ok := f.ips[host]; ok {
				return a, nil
			}
			return nil, fmt.Errorf("lookup %s: %w", host, ErrNotFound)
		},
		txtAt: func(_ context.Context, server netip.AddrPort, name string) ([]string, error) {
			f.asked = append(f.asked, "TXT "+name+" @"+server.String())
			if f.down[server.Addr()] {
				return nil, errors.New("i/o timeout")
			}
			r, ok := f.txt[server.Addr()]
			if !ok || r == nil {
				return nil, fmt.Errorf("lookup %s: %w", name, ErrNotFound)
			}
			return r, nil
		},
	}
}

var (
	ns1 = netip.MustParseAddr("192.0.2.1")
	ns2 = netip.MustParseAddr("192.0.2.2")
)

func TestAuthoritativeTXT(t *testing.T) {
	ctx := context.Background()
	newFake := func() *fakeAuthority {
		return &fakeAuthority{
			ns:  map[string][]string{"example.com": {"ns1.host.example", "ns2.host.example"}},
			ips: map[string][]netip.Addr{"ns1.host.example": {ns1}, "ns2.host.example": {ns2}},
			txt: map[netip.Addr][]string{ns1: {"orus-verify=new"}, ns2: {"orus-verify=new"}},
		}
	}

	// A subdomain without its own name servers: the parent zone's answer.
	f := newFake()
	got, err := f.authority().lookupTXT(ctx, "_orus-verify.shop.example.com", "shop.example.com")
	if err != nil || !slices.Equal(got, []string{"orus-verify=new"}) {
		t.Fatalf("lookupTXT = %v, %v", got, err)
	}
	if !slices.Equal(f.asked, []string{"NS shop.example.com", "NS example.com", "TXT _orus-verify.shop.example.com @192.0.2.1:53"}) {
		t.Errorf("asked %v", f.asked)
	}

	// The first name server is down: the second answers.
	f = newFake()
	f.down = map[netip.Addr]bool{ns1: true}
	if got, err := f.authority().lookupTXT(ctx, "_orus-verify.example.com", "example.com"); err != nil || len(got) != 1 {
		t.Errorf("with a server down = %v, %v", got, err)
	}

	// "Does not exist" from a name server is an answer: no other is asked.
	f = newFake()
	f.txt[ns1] = nil
	if _, err := f.authority().lookupTXT(ctx, "_orus-verify.example.com", "example.com"); !errors.Is(err, ErrNotFound) {
		t.Errorf("record absent = %v, want ErrNotFound", err)
	}
	if n := len(f.asked); n != 2 {
		t.Errorf("asked %v, want the first server only", f.asked)
	}

	// Every server down, or no name server at all: ErrNoAuthority, so the
	// caller falls back to an ordinary lookup.
	f = newFake()
	f.down = map[netip.Addr]bool{ns1: true, ns2: true}
	if _, err := f.authority().lookupTXT(ctx, "_orus-verify.example.com", "example.com"); !errors.Is(err, ErrNoAuthority) {
		t.Errorf("all servers down = %v, want ErrNoAuthority", err)
	}
	f = newFake()
	f.ns = nil
	if _, err := f.authority().lookupTXT(ctx, "_orus-verify.example.com", "example.com"); !errors.Is(err, ErrNoAuthority) {
		t.Errorf("no name servers = %v, want ErrNoAuthority", err)
	}
	// The walk stops before the top-level domain.
	if slices.Contains(f.asked, "NS com") {
		t.Errorf("asked the TLD: %v", f.asked)
	}
}
