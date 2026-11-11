package resolver

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestParseServer(t *testing.T) {
	for in, want := range map[string]string{
		"1.1.1.1": "1.1.1.1:53", "127.0.0.1:5353": "127.0.0.1:5353", "[2606:4700::1111]:53": "[2606:4700::1111]:53",
		"2606:4700::1111": "[2606:4700::1111]:53", " 9.9.9.9 ": "9.9.9.9:53",
	} {
		got, err := parseServer(in)
		if err != nil || got.String() != want {
			t.Errorf("parseServer(%q) = %v, %v; want %s", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "dns.google", "dns.google:53", "1.1.1.1:dns"} {
		if _, err := parseServer(bad); err == nil {
			t.Errorf("parseServer(%q) accepted", bad)
		}
	}
}

// The queries go to the configured server, not to resolv.conf. The fake
// server only counts packets: the lookup itself fails, which is fine.
func TestQueriesGoToTheConfiguredServer(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = pc.Close() }()
	got := make(chan int, 1)
	go func() {
		buf := make([]byte, 512)
		n, _, err := pc.ReadFrom(buf)
		if err == nil {
			got <- n
		}
	}()

	r, err := NewWithServer(pc.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	r.timeout = 300 * time.Millisecond
	_, _ = r.LookupIP(context.Background(), "example.com")
	select {
	case n := <-got:
		if n < 12 { // a DNS header is 12 bytes
			t.Errorf("received %d bytes, not a DNS query", n)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no query reached the configured server")
	}
}

func TestFromEnv(t *testing.T) {
	if r, err := FromEnv(func(string) string { return "" }); err != nil || r == nil || r.r.Dial != nil {
		t.Errorf("unset: %+v, %v; want the system resolver", r, err)
	}
	if r, err := FromEnv(func(string) string { return "127.0.0.1:53" }); err != nil || r.r.Dial == nil {
		t.Errorf("set: %+v, %v", r, err)
	}
	if _, err := FromEnv(func(string) string { return "resolver.local" }); err == nil {
		t.Error("a name instead of an IP: nil error")
	}
}
