package ownership

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"

	"github.com/jordyorel/orus-shield/engine/internal/module"
	"github.com/jordyorel/orus-shield/engine/internal/resolver"
)

// maxPTRNames bounds how many reverse names of one IP we try to confirm.
const maxPTRNames = 5

// ErrIPNotVerified is returned (wrapped with module.ErrExcluded) when an
// active module tries to reach an IP whose ownership is not proven.
var ErrIPNotVerified = errors.New("IP ownership not verified")

// CheckIP tells whether ip belongs to the owner of domain, using
// forward-confirmed reverse DNS:
//
//  1. the PTR record of ip names a host under domain (only the holder of an
//     IP can set its PTR, through their hosting provider's panel);
//  2. that host resolves back to ip (so the PTR is not a stale or copied
//     name).
//
// A shared host, a CDN or a parking page fails step 1: their PTR belongs to
// the provider. That is the point: verifying a domain must not let anyone
// actively scan someone else's servers.
//
// ok is false with a human-readable reason when the IP is not verified. err
// is set only when DNS failed; the IP must then be treated as unverified.
func CheckIP(ctx context.Context, dns resolver.Resolver, domain string, ip netip.Addr) (ok bool, reason string, err error) {
	ip = ip.Unmap()
	names, err := dns.LookupAddr(ctx, ip)
	if errors.Is(err, resolver.ErrNotFound) || (err == nil && len(names) == 0) {
		return false, fmt.Sprintf("%s has no reverse DNS (PTR) record", ip), nil
	}
	if err != nil {
		return false, "", fmt.Errorf("reverse lookup of %s: %w", ip, err)
	}
	if len(names) > maxPTRNames {
		names = names[:maxPTRNames]
	}

	var under []string
	for _, n := range names {
		n = strings.TrimSuffix(strings.ToLower(n), ".")
		// "." before the domain: "evilorushield.xyz" is not under
		// "orushield.xyz".
		if n == domain || strings.HasSuffix(n, "."+domain) {
			under = append(under, n)
		}
	}
	if len(under) == 0 {
		return false, fmt.Sprintf("reverse DNS of %s is %s, not a name under %s",
			ip, strings.Join(names, ", "), domain), nil
	}

	for _, n := range under {
		addrs, err := dns.LookupIP(ctx, n)
		if errors.Is(err, resolver.ErrNotFound) {
			continue
		}
		if err != nil {
			return false, "", fmt.Errorf("forward lookup of %s: %w", n, err)
		}
		for _, a := range addrs {
			if a.Unmap() == ip {
				return true, "", nil
			}
		}
	}
	return false, fmt.Sprintf("reverse DNS of %s is %s, but that name does not resolve back to %s",
		ip, strings.Join(under, ", "), ip), nil
}

// RefuseFunc is called once per IP refused by an IPGate, so the caller can
// log and audit it.
type RefuseFunc func(ip netip.Addr, reason string)

// IPGate wraps the scan's gate for active modules. Before any connection to
// an IP, it checks that the IP is verified (CheckIP); unverified IPs are
// refused with module.ErrExcluded, so modules skip them like a customer
// exclusion. Requests without an IP (DNS lookups by name) go straight to the
// inner gate.
//
// Results are cached for the lifetime of the gate, which is one scan:
// nothing is kept between scans. Safe for concurrent use.
type IPGate struct {
	inner    module.Gate
	dns      resolver.Resolver // already gated by inner
	domain   string
	onRefuse RefuseFunc

	mu      sync.Mutex
	checked map[netip.Addr]error // nil error: verified
}

// IPGate returns the gate active modules must use for target domain. Its own
// DNS lookups go through inner, so they respect exclusions and the rate
// limit like everything else.
func (v *Verifier) IPGate(inner module.Gate, domain string, onRefuse RefuseFunc) module.Gate {
	return &IPGate{
		inner:    inner,
		dns:      resolver.Gated{Gate: inner, Inner: v.dns},
		domain:   domain,
		onRefuse: onRefuse,
		checked:  make(map[netip.Addr]error),
	}
}

// Allow implements module.Gate.
func (g *IPGate) Allow(ctx context.Context, dest module.Destination) error {
	if dest.IP.IsValid() {
		if err := g.verify(ctx, dest.IP.Unmap()); err != nil {
			return err
		}
	}
	return g.inner.Allow(ctx, dest)
}

func (g *IPGate) verify(ctx context.Context, ip netip.Addr) error {
	// The lock is held during the check so two modules asking for the same
	// IP at once trigger one lookup, not two. Checks are short and scans
	// are sequential, so this does not slow anything down in practice.
	g.mu.Lock()
	defer g.mu.Unlock()
	if err, done := g.checked[ip]; done {
		return err
	}

	ok, reason, err := CheckIP(ctx, g.dns, g.domain, ip)
	if ctx.Err() != nil {
		return ctx.Err() // cancelled scan: do not cache, do not report
	}
	if err != nil {
		// Fail closed: a DNS failure is not proof of ownership.
		reason = fmt.Sprintf("could not verify %s: %v", ip, err)
	}
	var result error
	if !ok {
		result = fmt.Errorf("%s: %w: %w", reason, ErrIPNotVerified, module.ErrExcluded)
		if g.onRefuse != nil {
			g.onRefuse(ip, reason)
		}
	}
	g.checked[ip] = result
	return result
}
