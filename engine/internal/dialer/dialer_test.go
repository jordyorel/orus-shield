package dialer

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"

	"github.com/jordyorel/orus-shield/engine/internal/module"
)

// stubDialer records addresses and returns one end of an in-memory pipe.
type stubDialer struct {
	addrs []string
}

func (s *stubDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	s.addrs = append(s.addrs, network+" "+address)
	client, server := net.Pipe()
	_ = server.Close()
	return client, nil
}

type stubGate struct {
	seen []module.Destination
	deny error
}

func (g *stubGate) Allow(ctx context.Context, dest module.Destination) error {
	g.seen = append(g.seen, dest)
	return g.deny
}

func TestGatedDialsTheApprovedIP(t *testing.T) {
	tests := []struct {
		name string
		dest module.Destination
		want string
	}{
		{"ipv4", module.Destination{Host: "example.com", IP: netip.MustParseAddr("192.0.2.10"), Port: 443}, "tcp 192.0.2.10:443"},
		{"ipv6", module.Destination{Host: "example.com", IP: netip.MustParseAddr("2001:db8::1"), Port: 443}, "tcp [2001:db8::1]:443"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inner := &stubDialer{}
			gate := &stubGate{}
			conn, err := Gated{Gate: gate, Inner: inner}.Dial(context.Background(), tt.dest)
			if err != nil {
				t.Fatalf("Dial: %v", err)
			}
			_ = conn.Close()
			if len(gate.seen) != 1 || gate.seen[0] != tt.dest {
				t.Errorf("gate saw %+v, want exactly %+v", gate.seen, tt.dest)
			}
			if len(inner.addrs) != 1 || inner.addrs[0] != tt.want {
				t.Errorf("dialed %v, want %q", inner.addrs, tt.want)
			}
		})
	}
}

func TestGatedRefusals(t *testing.T) {
	errLimiter := errors.New("rate limiter stopped")
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	valid := module.Destination{Host: "example.com", IP: netip.MustParseAddr("192.0.2.10"), Port: 443}

	tests := []struct {
		name    string
		ctx     context.Context
		gate    module.Gate
		dest    module.Destination
		wantErr error
	}{
		{"no gate", context.Background(), nil, valid, ErrNoGate},
		{"no IP", context.Background(), &stubGate{}, module.Destination{Host: "example.com", Port: 443}, ErrInvalidDestination},
		{"port 0", context.Background(), &stubGate{}, module.Destination{IP: valid.IP, Port: 0}, ErrInvalidDestination},
		{"port too high", context.Background(), &stubGate{}, module.Destination{IP: valid.IP, Port: 70000}, ErrInvalidDestination},
		{"cancelled context", cancelled, &stubGate{}, valid, context.Canceled},
		{"excluded", context.Background(), &stubGate{deny: module.ErrExcluded}, valid, module.ErrExcluded},
		{"gate error is marked", context.Background(), &stubGate{deny: errLimiter}, valid, ErrGateRefused},
		{"gate error is kept", context.Background(), &stubGate{deny: errLimiter}, valid, errLimiter},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inner := &stubDialer{}
			_, err := Gated{Gate: tt.gate, Inner: inner}.Dial(tt.ctx, tt.dest)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("Dial error = %v, want %v", err, tt.wantErr)
			}
			if len(inner.addrs) != 0 {
				t.Errorf("dialed %v despite the refusal", inner.addrs)
			}
		})
	}
}
