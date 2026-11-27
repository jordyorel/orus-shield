package gateproxy

import (
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"strconv"
	"strings"
	"syscall"
)

// Ports is the range of TCP ports a proxy may listen on, on 127.0.0.1. The
// zero value lets the kernel pick any free port.
//
// Why a range: in production the scanners run in a sandbox whose firewall
// lets them reach the loopback on these ports only (deploy/prod). Ports
// the kernel picks come from the ephemeral range, where other local
// daemons may listen too; a range above it (61000-61999 with Linux's
// default 32768-60999) holds nothing but our proxies.
type Ports struct {
	First, Last int
}

// ParsePorts reads "FIRST-LAST" ("": the zero value). Both ends are
// unprivileged ports, FIRST <= LAST.
func ParsePorts(s string) (Ports, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return Ports{}, nil
	}
	first, last, ok := strings.Cut(s, "-")
	if !ok {
		return Ports{}, fmt.Errorf("port range %q: want FIRST-LAST, such as 61000-61999", s)
	}
	f, err1 := strconv.Atoi(first)
	l, err2 := strconv.Atoi(last)
	if err1 != nil || err2 != nil || f < 1024 || l > 65535 || f > l {
		return Ports{}, fmt.Errorf("port range %q: want FIRST-LAST with 1024 <= FIRST <= LAST <= 65535", s)
	}
	return Ports{First: f, Last: l}, nil
}

// listen opens the proxy's listener on 127.0.0.1, in p. It starts at a
// random port of the range (so concurrent scans rarely collide) and tries
// each port once.
func listen(p Ports) (net.Listener, error) {
	if p == (Ports{}) {
		return net.Listen("tcp", "127.0.0.1:0")
	}
	n := p.Last - p.First + 1
	start := rand.IntN(n) //nolint:gosec // G404: spreads ports, not a secret
	for i := range n {
		port := p.First + (start+i)%n
		ln, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
		if err == nil {
			return ln, nil
		}
		if !errors.Is(err, syscall.EADDRINUSE) {
			return nil, err
		}
	}
	return nil, fmt.Errorf("no free port in %d-%d", p.First, p.Last)
}
