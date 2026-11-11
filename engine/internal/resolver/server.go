package resolver

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
)

// NewWithServer returns a resolver that sends every query to one DNS
// server, instead of the servers of the machine's network (resolv.conf).
//
// Workers should use a resolver we control (Unbound on the host, or a
// trusted public resolver): the network's resolver may keep stale answers
// far longer than their TTL (a mobile operator kept an NXDOMAIN for over
// an hour during the ports module's real test), which makes ownership
// checks refuse a valid IP, or worse, accept one we no longer own.
//
// addr is "ip:port" or a bare IP (port 53). It must be an IP address: a
// name would need DNS to find the DNS server.
func NewWithServer(addr string) (*System, error) {
	ap, err := parseServer(addr)
	if err != nil {
		return nil, err
	}
	server := ap.String()
	r := &net.Resolver{
		PreferGo: true,
		// Go asks for "udp", and "tcp" for truncated answers: both go to
		// the configured server, whatever address Go had in mind.
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, server)
		},
	}
	return &System{r: r, timeout: DefaultTimeout}, nil
}

func parseServer(addr string) (netip.AddrPort, error) {
	addr = strings.TrimSpace(addr)
	if ap, err := netip.ParseAddrPort(addr); err == nil {
		return ap, nil
	}
	if ip, err := netip.ParseAddr(strings.Trim(addr, "[]")); err == nil {
		return netip.AddrPortFrom(ip, 53), nil
	}
	return netip.AddrPort{}, fmt.Errorf("DNS server %q: want an IP address, optionally with a port (1.1.1.1, 127.0.0.1:53, [2606:4700::1111]:53)", addr)
}

// FromEnv returns the resolver named by ORUS_DNS_SERVER, or the system
// resolver when it is unset. Used by the worker, the API and orusctl, so
// that every DNS decision (modules, ownership) uses the same server.
func FromEnv(getenv func(string) string) (*System, error) {
	if s := strings.TrimSpace(getenv("ORUS_DNS_SERVER")); s != "" {
		return NewWithServer(s)
	}
	return NewSystem(), nil
}
