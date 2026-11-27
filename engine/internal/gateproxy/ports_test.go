package gateproxy

import (
	"context"
	"net"
	"net/url"
	"strconv"
	"testing"
)

func TestParsePorts(t *testing.T) {
	for in, want := range map[string]Ports{"": {}, " 61000-61999 ": {61000, 61999}, "62000-62000": {62000, 62000}} {
		if got, err := ParsePorts(in); err != nil || got != want {
			t.Errorf("ParsePorts(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	for _, in := range []string{"61000", "61999-61000", "80-90", "61000-70000", "a-b", "-1-5"} {
		if _, err := ParsePorts(in); err == nil {
			t.Errorf("ParsePorts(%q): nil error", in)
		}
	}
}

// freeRange finds n consecutive free ports, for a range the test owns.
func freeRange(t *testing.T, n int) Ports {
	t.Helper()
	for first := 61000; first+n <= 65000; first += n {
		ok := true
		var lns []net.Listener
		for p := first; p < first+n; p++ {
			ln, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(p))
			if err != nil {
				ok = false
				break
			}
			lns = append(lns, ln)
		}
		for _, ln := range lns {
			_ = ln.Close()
		}
		if ok {
			return Ports{First: first, Last: first + n - 1}
		}
	}
	t.Skip("no free port range")
	return Ports{}
}

func TestListensInItsRange(t *testing.T) {
	r := freeRange(t, 3)
	cfg := Config{Domain: "example.com", Gate: &recordGate{}, DNS: dns(), Dial: &net.Dialer{}, Ports: r}
	var proxies []*Proxy
	defer func() {
		for _, p := range proxies {
			_ = p.Close()
		}
	}()
	// Three proxies fill the range: each takes a free port of it.
	seen := map[int]bool{}
	for range 3 {
		p, err := Start(context.Background(), cfg)
		if err != nil {
			t.Fatalf("Start: %v", err)
		}
		proxies = append(proxies, p)
		u, err := url.Parse(p.URL())
		if err != nil {
			t.Fatal(err)
		}
		port, _ := strconv.Atoi(u.Port())
		if port < r.First || port > r.Last || seen[port] || u.Hostname() != "127.0.0.1" {
			t.Errorf("proxy at %s, want a new port of %d-%d on 127.0.0.1", u.Host, r.First, r.Last)
		}
		seen[port] = true
	}
	// A fourth finds the range full: an error, never a port outside it.
	if p, err := Start(context.Background(), cfg); err == nil {
		proxies = append(proxies, p)
		t.Errorf("range full, yet a proxy at %s", p.URL())
	}
}
