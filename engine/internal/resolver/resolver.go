// Package resolver provides the DNS lookups modules use.
//
// Modules never call net.Resolver directly. They receive a Gated resolver,
// which calls the scan's Gate (exclusions + rate limiting) before every
// lookup. The rule is therefore enforced by construction, not by convention.
package resolver

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/jordyorel/orus-shield/engine/internal/module"
)

// Resolver is the set of DNS lookups modules need. Tests replace it with an
// in-memory fake, so no real DNS server is ever queried (security rule 6).
type Resolver interface {
	LookupTXT(ctx context.Context, name string) ([]string, error)
	LookupMX(ctx context.Context, name string) ([]*net.MX, error)
	LookupIP(ctx context.Context, host string) ([]netip.Addr, error)
}

var (
	// ErrNotFound means the name or the record type does not exist. It is an
	// answer, not a failure: callers usually turn it into a "missing" finding.
	ErrNotFound = errors.New("dns record not found")
	// ErrNoGate is returned by a Gated resolver that has no Gate. Without a
	// gate we cannot apply exclusions or rate limits, so we refuse.
	ErrNoGate = errors.New("dns lookup without a gate")
)

// MaxRecords bounds how many records of one lookup we keep. DNS answers come
// from the target and are untrusted input (security rule 7).
const MaxRecords = 32

// DefaultTimeout bounds a single lookup, on top of the caller's context.
const DefaultTimeout = 5 * time.Second

// System resolves names with Go's own DNS client.
type System struct {
	r       *net.Resolver
	timeout time.Duration
}

// NewSystem returns a System resolver.
//
// PreferGo selects Go's built-in DNS client instead of the C library one, so
// behavior, timeouts and cancellation are the same on every platform.
func NewSystem() *System {
	return &System{r: &net.Resolver{PreferGo: true}, timeout: DefaultTimeout}
}

// LookupTXT returns the TXT records of name. Go joins the strings of a
// multi-string TXT record into one string, which is what SPF and DKIM need.
func (s *System) LookupTXT(ctx context.Context, name string) ([]string, error) {
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()
	records, err := s.r.LookupTXT(ctx, name)
	if err != nil {
		return nil, wrapError(name, err)
	}
	return limit(records), nil
}

// LookupMX returns the MX records of name.
func (s *System) LookupMX(ctx context.Context, name string) ([]*net.MX, error) {
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()
	records, err := s.r.LookupMX(ctx, name)
	if err != nil {
		return nil, wrapError(name, err)
	}
	return limit(records), nil
}

// LookupIP returns the IPv4 and IPv6 addresses of host. IPv4 addresses are
// returned in their 4-byte form, never as IPv4-mapped IPv6.
func (s *System) LookupIP(ctx context.Context, host string) ([]netip.Addr, error) {
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()
	addrs, err := s.r.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, wrapError(host, err)
	}
	for i := range addrs {
		addrs[i] = addrs[i].Unmap()
	}
	return limit(addrs), nil
}

// Gated wraps a Resolver and calls Gate before every lookup.
type Gated struct {
	Gate  module.Gate
	Inner Resolver
}

// LookupTXT asks the gate, then looks up the TXT records of name.
func (g Gated) LookupTXT(ctx context.Context, name string) ([]string, error) {
	if err := g.allow(ctx, name); err != nil {
		return nil, err
	}
	return g.Inner.LookupTXT(ctx, name)
}

// LookupMX asks the gate, then looks up the MX records of name.
func (g Gated) LookupMX(ctx context.Context, name string) ([]*net.MX, error) {
	if err := g.allow(ctx, name); err != nil {
		return nil, err
	}
	return g.Inner.LookupMX(ctx, name)
}

// LookupIP asks the gate, then looks up the addresses of host.
func (g Gated) LookupIP(ctx context.Context, host string) ([]netip.Addr, error) {
	if err := g.allow(ctx, host); err != nil {
		return nil, err
	}
	return g.Inner.LookupIP(ctx, host)
}

func (g Gated) allow(ctx context.Context, name string) error {
	if g.Gate == nil {
		return fmt.Errorf("lookup %s: %w", name, ErrNoGate)
	}
	// Stop a cancelled scan here, whatever the gate and resolver do with ctx.
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("lookup %s: %w", name, err)
	}
	if err := g.Gate.Allow(ctx, module.Destination{Host: name}); err != nil {
		return fmt.Errorf("lookup %s: gate refused: %w", name, err)
	}
	return nil
}

// wrapError adds the name to err and marks "does not exist" answers with
// ErrNotFound, while keeping the original error reachable with errors.Is/As.
func wrapError(name string, err error) error {
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
		return fmt.Errorf("lookup %s: %w: %w", name, ErrNotFound, err)
	}
	return fmt.Errorf("lookup %s: %w", name, err)
}

// limit keeps at most MaxRecords elements.
func limit[T any](records []T) []T {
	if len(records) > MaxRecords {
		return records[:MaxRecords]
	}
	return records
}
