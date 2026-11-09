package resolver

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"testing"

	"github.com/jordyorel/orus-shield/engine/internal/module"
)

// stubResolver records the names it is asked for and returns fixed answers.
type stubResolver struct {
	calls []string
}

func (s *stubResolver) LookupTXT(ctx context.Context, name string) ([]string, error) {
	s.calls = append(s.calls, "TXT "+name)
	return []string{"v=spf1 -all"}, nil
}

func (s *stubResolver) LookupMX(ctx context.Context, name string) ([]*net.MX, error) {
	s.calls = append(s.calls, "MX "+name)
	return []*net.MX{{Host: "mx.example.com.", Pref: 10}}, nil
}

func (s *stubResolver) LookupIP(ctx context.Context, host string) ([]netip.Addr, error) {
	s.calls = append(s.calls, "IP "+host)
	return []netip.Addr{netip.MustParseAddr("192.0.2.1")}, nil
}

// stubGate records destinations and can refuse every request.
type stubGate struct {
	allowed []module.Destination
	deny    error
}

func (g *stubGate) Allow(ctx context.Context, dest module.Destination) error {
	if g.deny != nil {
		return g.deny
	}
	g.allowed = append(g.allowed, dest)
	return nil
}

func TestGatedCallsGateBeforeEveryLookup(t *testing.T) {
	inner := &stubResolver{}
	gate := &stubGate{}
	g := Gated{Gate: gate, Inner: inner}

	if _, err := g.LookupTXT(context.Background(), "example.com"); err != nil {
		t.Fatalf("LookupTXT: %v", err)
	}
	if _, err := g.LookupMX(context.Background(), "example.org"); err != nil {
		t.Fatalf("LookupMX: %v", err)
	}
	if _, err := g.LookupIP(context.Background(), "www.example.net"); err != nil {
		t.Fatalf("LookupIP: %v", err)
	}

	want := []module.Destination{{Host: "example.com"}, {Host: "example.org"}, {Host: "www.example.net"}}
	if len(gate.allowed) != len(want) {
		t.Fatalf("gate saw %d requests, want %d", len(gate.allowed), len(want))
	}
	for i := range want {
		if gate.allowed[i] != want[i] {
			t.Errorf("gate request %d = %+v, want %+v", i, gate.allowed[i], want[i])
		}
	}
	if len(inner.calls) != 3 {
		t.Errorf("inner resolver saw %d lookups, want 3", len(inner.calls))
	}
}

func TestGatedRefusalBlocksLookup(t *testing.T) {
	errExcluded := errors.New("excluded by customer")
	inner := &stubResolver{}
	g := Gated{Gate: &stubGate{deny: errExcluded}, Inner: inner}

	_, errTXT := g.LookupTXT(context.Background(), "example.com")
	_, errMX := g.LookupMX(context.Background(), "example.com")
	_, errIP := g.LookupIP(context.Background(), "example.com")

	for _, err := range []error{errTXT, errMX, errIP} {
		if !errors.Is(err, errExcluded) {
			t.Errorf("lookup error = %v, want it to wrap the gate error", err)
		}
	}
	if len(inner.calls) != 0 {
		t.Errorf("inner resolver was called %d times after a refusal, want 0", len(inner.calls))
	}
}

func TestGatedWithoutGateFailsClosed(t *testing.T) {
	inner := &stubResolver{}
	g := Gated{Inner: inner}

	if _, err := g.LookupTXT(context.Background(), "example.com"); !errors.Is(err, ErrNoGate) {
		t.Errorf("LookupTXT error = %v, want ErrNoGate", err)
	}
	if _, err := g.LookupMX(context.Background(), "example.com"); !errors.Is(err, ErrNoGate) {
		t.Errorf("LookupMX error = %v, want ErrNoGate", err)
	}
	if len(inner.calls) != 0 {
		t.Errorf("inner resolver was called without a gate")
	}
}

func TestGatedStopsOnCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	inner := &stubResolver{}
	gate := &stubGate{}
	g := Gated{Gate: gate, Inner: inner}

	if _, err := g.LookupTXT(ctx, "example.com"); !errors.Is(err, context.Canceled) {
		t.Errorf("LookupTXT error = %v, want context.Canceled", err)
	}
	if len(gate.allowed) != 0 || len(inner.calls) != 0 {
		t.Errorf("gate saw %d requests and resolver %d lookups after cancel, want 0",
			len(gate.allowed), len(inner.calls))
	}
}

func TestWrapError(t *testing.T) {
	tests := []struct {
		name         string
		err          error
		wantNotFound bool
	}{
		{"nxdomain", &net.DNSError{Err: "no such host", Name: "x.example.com", IsNotFound: true}, true},
		{"timeout", &net.DNSError{Err: "i/o timeout", Name: "x.example.com", IsTimeout: true}, false},
		{"servfail", &net.DNSError{Err: "server misbehaving", Name: "x.example.com"}, false},
		{"wrapped nxdomain", fmt.Errorf("outer: %w", &net.DNSError{IsNotFound: true}), true},
		{"other error", errors.New("boom"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := wrapError("x.example.com", tt.err)
			if got := errors.Is(err, ErrNotFound); got != tt.wantNotFound {
				t.Errorf("errors.Is(err, ErrNotFound) = %v, want %v (err: %v)", got, tt.wantNotFound, err)
			}
			if !errors.Is(err, tt.err) {
				t.Errorf("wrapped error lost the original: %v", err)
			}
		})
	}
}

func TestLimit(t *testing.T) {
	many := make([]string, MaxRecords+10)
	if got := len(limit(many)); got != MaxRecords {
		t.Errorf("len(limit(%d records)) = %d, want %d", len(many), got, MaxRecords)
	}
	few := []string{"a", "b"}
	if got := len(limit(few)); got != 2 {
		t.Errorf("len(limit(2 records)) = %d, want 2", got)
	}
}
