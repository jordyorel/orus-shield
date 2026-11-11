// Package gate implements module.Gate for one scan: customer exclusions
// (security rule 2) and the outbound rate limit (rule 3).
//
// A Gate is built per scan from the target's settings and is shared by all
// modules of that scan. Rate limiting is local to the worker for now; a
// limiter shared between workers (Redis or Valkey) comes later.
package gate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jordyorel/orus-shield/engine/internal/module"
)

// maxEntries bounds each exclusion list.
const maxEntries = 1000

// Exclusions is the JSON stored with a target, for example:
//
//	{"ips": ["192.0.2.10", "198.51.100.0/24"], "ports": [8443],
//	 "paths": ["/admin"], "hosts": ["staging.example.com"]}
type Exclusions struct {
	IPs   []string `json:"ips"`   // addresses or CIDR prefixes
	Ports []int    `json:"ports"` // TCP ports
	Paths []string `json:"paths"` // URL path prefixes
	Hosts []string `json:"hosts"` // host names; also excludes their subdomains
}

// Rules are parsed, validated exclusions.
type Rules struct {
	prefixes []netip.Prefix
	ports    map[int]bool
	paths    []string
	hosts    []string
}

// ParseExclusions parses and validates a target's exclusions. Unknown fields
// are rejected: a typo such as "ip" instead of "ips" would otherwise
// silently disable an exclusion, which is a security bug, not a detail.
func ParseExclusions(raw json.RawMessage) (Rules, error) {
	var ex Exclusions
	if len(raw) > 0 {
		dec := json.NewDecoder(strings.NewReader(string(raw)))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&ex); err != nil {
			return Rules{}, fmt.Errorf("parse exclusions: %w", err)
		}
	}
	for name, n := range map[string]int{"ips": len(ex.IPs), "ports": len(ex.Ports), "paths": len(ex.Paths), "hosts": len(ex.Hosts)} {
		if n > maxEntries {
			return Rules{}, fmt.Errorf("parse exclusions: %d %s, limit is %d", n, name, maxEntries)
		}
	}

	r := Rules{ports: make(map[int]bool)}
	for _, s := range ex.IPs {
		p, err := parsePrefix(s)
		if err != nil {
			return Rules{}, fmt.Errorf("parse exclusions: ip %q: %w", s, err)
		}
		r.prefixes = append(r.prefixes, p)
	}
	for _, port := range ex.Ports {
		if port < 1 || port > 65535 {
			return Rules{}, fmt.Errorf("parse exclusions: port %d out of range", port)
		}
		r.ports[port] = true
	}
	for _, p := range ex.Paths {
		if !strings.HasPrefix(p, "/") {
			return Rules{}, fmt.Errorf("parse exclusions: path %q must start with /", p)
		}
		r.paths = append(r.paths, cleanPath(p))
	}
	for _, h := range ex.Hosts {
		host, err := module.NormalizeDomain(h)
		if err != nil {
			return Rules{}, fmt.Errorf("parse exclusions: host: %w", err)
		}
		r.hosts = append(r.hosts, host)
	}
	return r, nil
}

// parsePrefix accepts "192.0.2.10" (a single address) or "192.0.2.0/24".
func parsePrefix(s string) (netip.Prefix, error) {
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return netip.Prefix{}, err
		}
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	a = a.Unmap()
	return netip.PrefixFrom(a, a.BitLen()), nil
}

// cleanPath resolves "." and ".." so "/public/../admin" cannot slip past an
// exclusion of "/admin".
func cleanPath(p string) string {
	return path.Clean("/" + p)
}

// Match returns why dest is excluded, or "" if it is not.
func (r Rules) Match(dest module.Destination) string {
	if dest.IP.IsValid() {
		ip := dest.IP.Unmap()
		for _, p := range r.prefixes {
			if p.Contains(ip) {
				return fmt.Sprintf("ip %s excluded by %s", ip, p)
			}
		}
	}
	if dest.Port != 0 && r.ports[dest.Port] {
		return fmt.Sprintf("port %d excluded", dest.Port)
	}
	if dest.Host != "" {
		host := strings.TrimSuffix(strings.ToLower(dest.Host), ".")
		for _, h := range r.hosts {
			if host == h || strings.HasSuffix(host, "."+h) {
				return fmt.Sprintf("host %s excluded by %s", host, h)
			}
		}
	}
	if dest.Path != "" {
		p := cleanPath(dest.Path)
		for _, ex := range r.paths {
			// "/admin" excludes "/admin" and "/admin/...", not "/administrator".
			if p == ex || strings.HasPrefix(p, strings.TrimSuffix(ex, "/")+"/") {
				return fmt.Sprintf("path %s excluded by %s", p, ex)
			}
		}
	}
	return ""
}

// Covers reports whether an exclusion applies to value, the asset of a
// finding or an inventory asset value: "203.0.113.5", "203.0.113.5:8080",
// "203.0.113.5:8080/tcp", "www.example.com:443" or "www.example.com".
//
// The worker uses it after a scan: a module that skipped an excluded
// destination did not observe it, so findings and assets on it must not be
// marked fixed or gone. Path exclusions cannot be matched this way (assets
// carry no path); see the worker for that limit.
func (r Rules) Covers(value string) bool {
	dest, ok := destinationOf(value)
	return ok && r.Match(dest) != ""
}

// destinationOf parses an asset value into the destination it designates.
func destinationOf(value string) (module.Destination, bool) {
	v := strings.TrimSuffix(value, "/tcp")
	if ap, err := netip.ParseAddrPort(v); err == nil {
		return module.Destination{IP: ap.Addr(), Port: int(ap.Port())}, true
	}
	if a, err := netip.ParseAddr(v); err == nil {
		return module.Destination{IP: a}, true
	}
	if host, port, err := net.SplitHostPort(v); err == nil {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return module.Destination{}, false
		}
		return module.Destination{Host: host, Port: n}, true
	}
	if v == "" || strings.ContainsAny(v, "/: ") {
		return module.Destination{}, false
	}
	return module.Destination{Host: v}, true
}

// Limiter spaces requests evenly: at most one every 1/rate seconds. It is
// safe for concurrent use; concurrent callers are served in turn.
type Limiter struct {
	mu       sync.Mutex
	interval time.Duration
	next     time.Time // earliest time the next request may start
}

// maxRatePerSec is a hard ceiling, whatever the configuration says. It also
// rejects +Inf, which would make the interval zero and disable limiting.
const maxRatePerSec = 1000

// NewLimiter returns a limiter allowing ratePerSec requests per second.
func NewLimiter(ratePerSec float64) (*Limiter, error) {
	if !(ratePerSec > 0 && ratePerSec <= maxRatePerSec) { // also rejects NaN
		return nil, fmt.Errorf("rate %v must be in (0, %d]", ratePerSec, maxRatePerSec)
	}
	return &Limiter{interval: time.Duration(float64(time.Second) / ratePerSec)}, nil
}

// Wait blocks until the caller may send one request, or ctx is done.
//
// Each caller reserves the next free slot, then sleeps until it starts. If
// ctx ends first, the slot is wasted: the next request waits a little more,
// which errs on the safe side.
func (l *Limiter) Wait(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	l.mu.Lock()
	now := time.Now()
	slot := l.next
	if slot.Before(now) {
		slot = now
	}
	l.next = slot.Add(l.interval)
	l.mu.Unlock()

	delay := slot.Sub(now)
	if delay <= 0 {
		return nil
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// Gate is the module.Gate of one scan.
type Gate struct {
	rules   Rules
	limiter *Limiter
}

// New returns a gate applying rules and limiting requests to ratePerSec.
func New(rules Rules, ratePerSec float64) (*Gate, error) {
	l, err := NewLimiter(ratePerSec)
	if err != nil {
		return nil, fmt.Errorf("new gate: %w", err)
	}
	return &Gate{rules: rules, limiter: l}, nil
}

// Covers reports whether the gate's exclusions apply to an asset value; see
// Rules.Covers.
func (g *Gate) Covers(value string) bool { return g.rules.Covers(value) }

// ErrRateLimitWait wraps a context error that interrupted the rate limiter.
var ErrRateLimitWait = errors.New("waiting for rate limiter")

// Allow implements module.Gate. Exclusions are checked first, so an excluded
// destination never consumes a slot of the rate limit.
func (g *Gate) Allow(ctx context.Context, dest module.Destination) error {
	if reason := g.rules.Match(dest); reason != "" {
		return fmt.Errorf("%s: %w", reason, module.ErrExcluded)
	}
	if err := g.limiter.Wait(ctx); err != nil {
		return fmt.Errorf("%w: %w", ErrRateLimitWait, err)
	}
	return nil
}

// FromTarget builds the gate of a target from its stored exclusions and
// rate. It fails closed: unreadable exclusions or an invalid rate are an
// error, never "no exclusions".
func FromTarget(exclusions json.RawMessage, ratePerSec float64) (*Gate, error) {
	rules, err := ParseExclusions(exclusions)
	if err != nil {
		return nil, err
	}
	return New(rules, ratePerSec)
}
