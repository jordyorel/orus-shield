package gate

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jordyorel/orus-shield/engine/internal/module"
)

func TestParseExclusionsRejects(t *testing.T) {
	tests := []struct {
		name string
		raw  string
	}{
		{"not JSON", `{`},
		{"typo in field name", `{"ip": ["192.0.2.1"]}`},
		{"bad IP", `{"ips": ["192.0.2.300"]}`},
		{"bad CIDR", `{"ips": ["192.0.2.0/33"]}`},
		{"port 0", `{"ports": [0]}`},
		{"port too high", `{"ports": [70000]}`},
		{"relative path", `{"paths": ["admin"]}`},
		{"bad host", `{"hosts": ["not a host"]}`},
		{"too many entries", `{"ports": [` + strings.Repeat("1,", maxEntries) + `1]}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := ParseExclusions(json.RawMessage(tt.raw)); err == nil {
				t.Errorf("ParseExclusions(%s) = nil, want error", tt.raw)
			}
		})
	}
}

func TestParseExclusionsEmpty(t *testing.T) {
	for _, raw := range []string{"", "{}", `{"ips": []}`} {
		r, err := ParseExclusions(json.RawMessage(raw))
		if err != nil {
			t.Errorf("ParseExclusions(%q) = %v", raw, err)
		}
		if reason := r.Match(module.Destination{Host: "example.com", IP: netip.MustParseAddr("192.0.2.1"), Port: 443, Path: "/"}); reason != "" {
			t.Errorf("empty rules matched: %s", reason)
		}
	}
}

func TestMatch(t *testing.T) {
	rules, err := ParseExclusions(json.RawMessage(`{
		"ips":   ["192.0.2.10", "198.51.100.0/24", "2001:db8:1::/48"],
		"ports": [8443],
		"paths": ["/admin", "/private/"],
		"hosts": ["Staging.Example.com"]
	}`))
	if err != nil {
		t.Fatalf("ParseExclusions: %v", err)
	}
	ip := netip.MustParseAddr

	tests := []struct {
		name     string
		dest     module.Destination
		excluded bool
	}{
		{"unrelated", module.Destination{Host: "www.example.com", IP: ip("192.0.2.11"), Port: 443, Path: "/"}, false},
		{"exact IP", module.Destination{IP: ip("192.0.2.10"), Port: 443}, true},
		{"IP in CIDR", module.Destination{IP: ip("198.51.100.77"), Port: 443}, true},
		{"IPv4-mapped IPv6", module.Destination{IP: ip("::ffff:192.0.2.10"), Port: 443}, true},
		{"IPv6 in CIDR", module.Destination{IP: ip("2001:db8:1:2::5"), Port: 443}, true},
		{"IPv6 outside CIDR", module.Destination{IP: ip("2001:db8:2::5"), Port: 443}, false},
		{"excluded port", module.Destination{IP: ip("192.0.2.11"), Port: 8443}, true},
		{"excluded host", module.Destination{Host: "staging.example.com"}, true},
		{"subdomain of excluded host", module.Destination{Host: "api.staging.example.com."}, true},
		{"host that only ends the same", module.Destination{Host: "mystaging.example.com"}, false},
		{"parent of excluded host", module.Destination{Host: "example.com"}, false},
		{"excluded path", module.Destination{Path: "/admin"}, true},
		{"below excluded path", module.Destination{Path: "/admin/users"}, true},
		{"similar path", module.Destination{Path: "/administrator"}, false},
		{"dot-dot bypass attempt", module.Destination{Path: "/public/../admin/x"}, true},
		{"trailing slash rule", module.Destination{Path: "/private/file"}, true},
		{"trailing slash rule, exact", module.Destination{Path: "/private"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reason := rules.Match(tt.dest)
			if (reason != "") != tt.excluded {
				t.Errorf("Match(%+v) = %q, want excluded=%v", tt.dest, reason, tt.excluded)
			}
		})
	}
}

func TestNewLimiterRejectsBadRate(t *testing.T) {
	for _, rate := range []float64{0, -1, math.NaN(), math.Inf(1), maxRatePerSec + 1} {
		if _, err := NewLimiter(rate); err == nil {
			t.Errorf("NewLimiter(%v) = nil, want error", rate)
		}
	}
}

func TestLimiterSpacesRequests(t *testing.T) {
	l, err := NewLimiter(20) // one request every 50ms
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	for range 5 {
		if err := l.Wait(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	// The first request is immediate, the four others wait 50ms each.
	if elapsed := time.Since(start); elapsed < 190*time.Millisecond {
		t.Errorf("5 requests at 20/s took %v, want at least 200ms", elapsed)
	}
}

func TestLimiterConcurrentCallersShareTheRate(t *testing.T) {
	l, err := NewLimiter(20)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	var wg sync.WaitGroup
	for range 6 {
		wg.Go(func() {
			if err := l.Wait(context.Background()); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if elapsed := time.Since(start); elapsed < 240*time.Millisecond {
		t.Errorf("6 concurrent requests at 20/s took %v, want at least 250ms", elapsed)
	}
}

func TestLimiterRespectsContext(t *testing.T) {
	l, err := NewLimiter(0.1) // one request every 10s
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Wait(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	if err := l.Wait(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("Wait = %v, want DeadlineExceeded", err)
	}
	if time.Since(start) > time.Second {
		t.Error("Wait ignored the context deadline")
	}
}

func TestGate(t *testing.T) {
	rules, err := ParseExclusions(json.RawMessage(`{"ips": ["192.0.2.10"]}`))
	if err != nil {
		t.Fatal(err)
	}
	g, err := New(rules, 0.1) // slow: a second allowed request would block
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	excluded := module.Destination{Host: "example.com", IP: netip.MustParseAddr("192.0.2.10"), Port: 443}
	allowed := module.Destination{Host: "example.com", IP: netip.MustParseAddr("192.0.2.11"), Port: 443}

	// Excluded destinations are refused with module.ErrExcluded, without
	// consuming the rate limit: the allowed request below is not delayed.
	for range 3 {
		if err := g.Allow(ctx, excluded); !errors.Is(err, module.ErrExcluded) {
			t.Fatalf("Allow(excluded) = %v, want ErrExcluded", err)
		}
	}
	start := time.Now()
	if err := g.Allow(ctx, allowed); err != nil {
		t.Fatalf("Allow(allowed) = %v", err)
	}
	if time.Since(start) > 100*time.Millisecond {
		t.Error("excluded requests consumed the rate limit")
	}

	// The next allowed request has to wait 10s; a short deadline interrupts it.
	short, cancel := context.WithTimeout(ctx, 20*time.Millisecond)
	defer cancel()
	err = g.Allow(short, allowed)
	if !errors.Is(err, ErrRateLimitWait) || !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("Allow while rate limited = %v, want ErrRateLimitWait wrapping DeadlineExceeded", err)
	}
	if errors.Is(err, module.ErrExcluded) {
		t.Error("a rate limit wait must not look like an exclusion")
	}
}

func TestGateImplementsModuleGate(t *testing.T) {
	var _ module.Gate = (*Gate)(nil)
	if _, err := New(Rules{}, 0); err == nil {
		t.Error("New with rate 0 = nil, want error")
	}
}

func TestFromTarget(t *testing.T) {
	if _, err := FromTarget(json.RawMessage(`{"ports": [8443]}`), 5); err != nil {
		t.Errorf("FromTarget(valid) = %v", err)
	}
	if _, err := FromTarget(json.RawMessage(`{"ip": []}`), 5); err == nil {
		t.Error("FromTarget(bad exclusions) = nil, want error")
	}
	if _, err := FromTarget(json.RawMessage(`{}`), 0); err == nil {
		t.Error("FromTarget(rate 0) = nil, want error")
	}
}

func TestCovers(t *testing.T) {
	rules, err := ParseExclusions(json.RawMessage(`{"ips": ["198.51.100.0/24"], "ports": [8080], "hosts": ["staging.example.com"], "paths": ["/admin"]}`))
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		value string
		want  bool
	}{
		{"203.0.113.5:8080", true},            // finding asset of the ports module
		{"203.0.113.5:8080/tcp", true},        // service asset
		{"203.0.113.5:8443/tcp", false},       // another port
		{"198.51.100.7", true},                // ip asset in an excluded range
		{"198.51.100.7:22", true},             // any port of an excluded ip
		{"[2001:db8::1]:8080", true},          // IPv6 with port
		{"api.staging.example.com:443", true}, // subdomain of an excluded host
		{"staging.example.com", true},
		{"www.example.com:443", false},
		{"www.example.com", false},
		{"_dmarc.example.com", false},
		{"www.example.com:99999", false}, // not a valid port: not covered
		{"", false},
		{"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", false}, // certificate hash
	}
	for _, tt := range tests {
		if got := rules.Covers(tt.value); got != tt.want {
			t.Errorf("Covers(%q) = %v, want %v", tt.value, got, tt.want)
		}
	}
}
