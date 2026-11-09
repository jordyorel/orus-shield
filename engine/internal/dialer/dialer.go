// Package dialer opens TCP connections for modules.
//
// Modules never call net.Dial directly. They resolve a name with the gated
// resolver, then call Gated.Dial with the chosen IP. The gate approves that
// exact IP and port (exclusions + rate limiting), and the connection goes to
// that IP, never to a name that could resolve somewhere else in between.
package dialer

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/jordyorel/orus-shield/engine/internal/module"
)

// Dialer is the low-level connection opener. *net.Dialer implements it;
// tests replace it so no real third-party system is contacted (rule 6).
type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// DefaultTimeout bounds connection establishment.
const DefaultTimeout = 10 * time.Second

// NewSystem returns a real dialer with DefaultTimeout.
func NewSystem() Dialer {
	return &net.Dialer{Timeout: DefaultTimeout}
}

var (
	// ErrNoGate is returned by a Gated dialer that has no Gate.
	ErrNoGate = errors.New("dial without a gate")
	// ErrInvalidDestination is returned when the destination has no IP or
	// an invalid port. Gated.Dial only connects to explicit IP addresses.
	ErrInvalidDestination = errors.New("invalid dial destination")
	// ErrGateRefused marks every refusal by the gate. Callers use it to tell
	// "we were not allowed to connect" (stop or skip) from "the target did
	// not answer" (a fact about the target).
	ErrGateRefused = errors.New("gate refused connection")
)

// Gated opens connections approved by Gate.
type Gated struct {
	Gate  module.Gate
	Inner Dialer
}

// Dial checks dest with the gate, then opens a TCP connection to dest.IP on
// dest.Port. dest.Host is passed to the gate for host-based exclusions and
// for logs; it is not resolved again.
func (g Gated) Dial(ctx context.Context, dest module.Destination) (net.Conn, error) {
	if g.Gate == nil {
		return nil, ErrNoGate
	}
	if !dest.IP.IsValid() || dest.Port < 1 || dest.Port > 65535 {
		return nil, fmt.Errorf("dial %s (ip %v, port %d): %w", dest.Host, dest.IP, dest.Port, ErrInvalidDestination)
	}
	addr := netip.AddrPortFrom(dest.IP, uint16(dest.Port)).String()
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("dial %s: %w", addr, err)
	}
	if err := g.Gate.Allow(ctx, dest); err != nil {
		return nil, fmt.Errorf("dial %s (%s): %w: %w", addr, dest.Host, ErrGateRefused, err)
	}
	return g.Inner.DialContext(ctx, "tcp", addr)
}
