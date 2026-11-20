package api

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
)

// The client's address comes from X-Forwarded-For only when a trusted
// proxy sent the request, and only the entry that proxy added: a client
// cannot pick its own address to escape a per-address limit.
func TestRealClient(t *testing.T) {
	proxies := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")}
	for _, tc := range []struct {
		name, peer, xff, want string
	}{
		{"no proxy header", "203.0.113.7:5000", "", "203.0.113.7:5000"},
		{"untrusted peer forges the header", "203.0.113.7:5000", "198.51.100.1", "203.0.113.7:5000"},
		{"through the proxy", "10.0.0.2:443", "198.51.100.1", "198.51.100.1:0"},
		{"client forges entries to the left", "10.0.0.2:443", "1.1.1.1, 198.51.100.1", "198.51.100.1:0"},
		{"two of our proxies", "10.0.0.2:443", "198.51.100.1, 10.0.0.3", "198.51.100.1:0"},
		{"malformed entry", "10.0.0.2:443", "1.1.1.1, nonsense", "10.0.0.2:443"},
		{"ipv6 client", "10.0.0.2:443", "2001:db8::5", "[2001:db8::5]:0"},
	} {
		var got string
		h := realClient(proxies, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { got = r.RemoteAddr }))
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = tc.peer
		if tc.xff != "" {
			r.Header.Set("X-Forwarded-For", tc.xff)
		}
		h.ServeHTTP(httptest.NewRecorder(), r)
		if got != tc.want {
			t.Errorf("%s: RemoteAddr = %q, want %q", tc.name, got, tc.want)
		}
	}
	// Without trusted proxies, the header is never read.
	var got string
	h := realClient(nil, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { got = r.RemoteAddr }))
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "10.0.0.2:443"
	r.Header.Set("X-Forwarded-For", "198.51.100.1")
	h.ServeHTTP(httptest.NewRecorder(), r)
	if got != "10.0.0.2:443" {
		t.Errorf("no proxies configured: RemoteAddr = %q", got)
	}
}
