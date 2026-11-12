package zap

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jordyorel/orus-shield/engine/internal/dialer"
)

// TestRealZAP runs the pinned image against a local application with a
// reflected XSS, through gateproxy. It runs when ORUS_ZAP_IMAGE is set
// (and Docker is available): a few minutes.
func TestRealZAP(t *testing.T) {
	image := os.Getenv("ORUS_ZAP_IMAGE")
	if image == "" {
		t.Skip("ORUS_ZAP_IMAGE is not set")
	}
	app := http.NewServeMux()
	app.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = fmt.Fprint(w, `<html><body><a href="/hello?name=guest">hello</a></body></html>`)
	})
	app.HandleFunc("/hello", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		// Deliberately vulnerable: the name is echoed unescaped, for ZAP to find.
		_, _ = fmt.Fprintf(w, "<html><body>Hello %s</body></html>", r.URL.Query().Get("name")) //nolint:gosec // G705: the XSS this test expects ZAP to find
	})
	srv := httptest.NewServer(app)
	defer srv.Close()
	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())

	gate := &allowGate{}
	m := New(fakeDNS{ips: map[string][]netip.Addr{"example.com": {netip.MustParseAddr("127.0.0.1")}}}, dialer.NewSystem(),
		Config{Image: image, ProxyHost: os.Getenv("ORUS_ZAP_PROXY_HOST"), Network: os.Getenv("ORUS_ZAP_NETWORK"), WorkDir: os.Getenv("ORUS_ZAP_WORKDIR")})
	m.urls = func(h string) []string { return []string{"http://" + h + ":" + port} }

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()
	res, err := m.Run(ctx, deepReq(gate))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Evaluated) != len(Checks) {
		t.Errorf("evaluated = %v: no request reached the application through the proxy", res.Evaluated)
	}
	var xss bool
	for _, f := range res.Findings {
		t.Logf("%s %s %s", f.Severity, f.CheckID, f.Title)
		if f.CheckID == CheckXSS && strings.Contains(f.Asset, "/hello#zap-") {
			xss = true
		}
	}
	if !xss {
		t.Error("the reflected XSS of /hello was not found")
	}
	// Every request went through the gate, with its path.
	var paths int
	gate.mu.Lock()
	for _, d := range gate.seen {
		if d.Path != "" {
			paths++
		}
	}
	gate.mu.Unlock()
	if paths == 0 {
		t.Error("the gate saw no HTTP request")
	}
}
