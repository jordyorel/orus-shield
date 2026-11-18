package resolver

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
)

// AuthoritativeTXT is implemented by resolvers that can read a TXT record
// from the zone's own name servers, past every cache.
//
// Ownership verification uses it: a customer who just published the record
// must not wait for a resolver's cache to expire (the local network's
// resolver kept the previous token for over ten minutes on 2026-11-17), and
// a removed record must not survive in a cache either.
type AuthoritativeTXT interface {
	// LookupTXTAuthoritative returns the TXT records of name as the name
	// servers of zone (or of its closest parent with name servers) answer
	// them. ErrNotFound is their answer that it does not exist; any other
	// error means no name server could be asked, and the caller may fall
	// back to an ordinary lookup.
	LookupTXTAuthoritative(ctx context.Context, name, zone string) ([]string, error)
}

// Bounds on what one authoritative lookup tries: name servers come from
// DNS answers (untrusted, security rule 7).
const (
	maxNameServers = 4
	maxServerAddrs = 2
)

// ErrNoAuthority means no name server of the zone could be found or asked.
var ErrNoAuthority = errors.New("no authoritative name server answered")

// authority holds the lookups an authoritative read needs, as functions so
// tests can replace them (no real DNS in tests, security rule 6).
type authority struct {
	// lookupNS returns the name servers of zone (recursive, cached is fine:
	// delegations change rarely).
	lookupNS func(ctx context.Context, zone string) ([]string, error)
	// lookupIP returns the addresses of a name server.
	lookupIP func(ctx context.Context, host string) ([]netip.Addr, error)
	// txtAt asks one server directly for the TXT records of name.
	txtAt func(ctx context.Context, server netip.AddrPort, name string) ([]string, error)
}

// lookupTXT walks up from zone to the closest name with name servers, then
// asks them in turn. The first answer wins, including "does not exist".
func (a authority) lookupTXT(ctx context.Context, name, zone string) ([]string, error) {
	servers, err := a.nameServers(ctx, zone)
	if err != nil {
		return nil, err
	}
	var last error
	for _, host := range servers {
		addrs, err := a.lookupIP(ctx, host)
		if err != nil {
			last = err
			continue
		}
		if len(addrs) > maxServerAddrs {
			addrs = addrs[:maxServerAddrs]
		}
		for _, ip := range addrs {
			records, err := a.txtAt(ctx, netip.AddrPortFrom(ip, 53), name)
			if err == nil || errors.Is(err, ErrNotFound) {
				return limit(records), err
			}
			last = err
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
		}
	}
	return nil, fmt.Errorf("%w for %s: %w", ErrNoAuthority, name, last)
}

// nameServers returns the name servers of zone or of its closest parent
// that has some, stopping before the top-level domain.
func (a authority) nameServers(ctx context.Context, zone string) ([]string, error) {
	z := strings.TrimSuffix(strings.ToLower(zone), ".")
	for strings.Contains(z, ".") {
		ns, err := a.lookupNS(ctx, z)
		if err == nil && len(ns) > 0 {
			if len(ns) > maxNameServers {
				ns = ns[:maxNameServers]
			}
			return ns, nil
		}
		if err != nil && !errors.Is(err, ErrNotFound) {
			return nil, fmt.Errorf("%w for %s: %w", ErrNoAuthority, zone, err)
		}
		z = z[strings.IndexByte(z, '.')+1:]
	}
	return nil, fmt.Errorf("%w: no name servers found for %s", ErrNoAuthority, zone)
}

// LookupTXTAuthoritative implements AuthoritativeTXT with the System
// resolver for the name servers and their addresses, and Go's DNS client
// sent straight to each name server for the record.
func (s *System) LookupTXTAuthoritative(ctx context.Context, name, zone string) ([]string, error) {
	a := authority{
		lookupNS: func(ctx context.Context, zone string) ([]string, error) {
			ctx, cancel := context.WithTimeout(ctx, s.timeout)
			defer cancel()
			ns, err := s.r.LookupNS(ctx, zone)
			if err != nil {
				return nil, wrapError(zone, err)
			}
			out := make([]string, 0, len(ns))
			for _, n := range ns {
				out = append(out, strings.TrimSuffix(n.Host, "."))
			}
			return out, nil
		},
		lookupIP: s.LookupIP,
		txtAt: func(ctx context.Context, server netip.AddrPort, name string) ([]string, error) {
			at := &net.Resolver{
				PreferGo: true,
				Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
					var d net.Dialer
					return d.DialContext(ctx, network, server.String())
				},
			}
			ctx, cancel := context.WithTimeout(ctx, s.timeout)
			defer cancel()
			records, err := at.LookupTXT(ctx, name)
			if err != nil {
				return nil, wrapError(name, err)
			}
			return records, nil
		},
	}
	return a.lookupTXT(ctx, name, zone)
}

// LookupTXTAuthoritative applies the gate to name, like every lookup, then
// reads it from the zone's name servers when the inner resolver can, or
// with an ordinary lookup otherwise.
func (g Gated) LookupTXTAuthoritative(ctx context.Context, name, zone string) ([]string, error) {
	inner, ok := g.Inner.(AuthoritativeTXT)
	if !ok {
		return g.LookupTXT(ctx, name)
	}
	if err := g.allow(ctx, name); err != nil {
		return nil, err
	}
	return inner.LookupTXTAuthoritative(ctx, name, zone)
}
