package zap

import (
	"context"
	"encoding/json"
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
	"github.com/jordyorel/orus-shield/engine/internal/module"
)

// authApp has a reflected XSS that only a logged-in client reaches: behind
// a bearer token (/secret) and behind a login form with a session cookie
// (/account).
func authApp() http.Handler {
	mux := http.NewServeMux()
	page := func(w http.ResponseWriter, body string) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = fmt.Fprint(w, "<html><body>"+body+"</body></html>") //nolint:gosec // G705: the deliberately vulnerable test app
	}
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		page(w, `<a href="/secret?name=guest">secret</a> <a href="/login">login</a> <a href="/account?name=guest">account</a>`)
	})
	mux.HandleFunc("/secret", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		page(w, "Hello "+r.URL.Query().Get("name")) //nolint:gosec // G705: the XSS this test expects ZAP to find
	})
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.FormValue("username") == "tester" && r.FormValue("password") == "pw" {
			http.SetCookie(w, &http.Cookie{Name: "session", Value: "ok", Path: "/"}) //nolint:gosec // G124: a local HTTP test server
			page(w, `Welcome <a href="/account?name=tester">your account</a> <a href="/logout">logout</a>`)
			return
		}
		page(w, `<form method="post" action="/login"><input name="username"><input name="password" type="password"><button>Login</button></form>`)
	})
	mux.HandleFunc("/account", func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie("session"); err != nil || c.Value != "ok" {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		page(w, `Account of `+r.URL.Query().Get("name")+` <a href="/logout">logout</a>`) //nolint:gosec // G705: as above
	})
	return mux
}

// TestRealAuthenticatedScan runs the real image with each kind of test
// account (ORUS_ZAP_IMAGE set) and expects the XSS behind the login.
func TestRealAuthenticatedScan(t *testing.T) {
	image := os.Getenv("ORUS_ZAP_IMAGE")
	if image == "" {
		t.Skip("ORUS_ZAP_IMAGE is not set")
	}
	srv := httptest.NewServer(authApp())
	defer srv.Close()
	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	base := "http://example.com:" + port

	for _, tt := range []struct {
		name string
		auth module.ScanAuth
		path string
	}{
		{"header", module.ScanAuth{Kind: "header", HeaderName: "Authorization", Secret: "Bearer test-token"}, "/secret#zap-"},
		{"form", module.ScanAuth{Kind: "form", LoginURL: base + "/login", Username: "tester", Secret: "pw"}, "/account#zap-"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			m := New(fakeDNS{ips: map[string][]netip.Addr{"example.com": {netip.MustParseAddr("127.0.0.1")}}}, dialer.NewSystem(),
				Config{Image: image, ProxyHost: os.Getenv("ORUS_ZAP_PROXY_HOST"), Network: os.Getenv("ORUS_ZAP_NETWORK"), WorkDir: os.Getenv("ORUS_ZAP_WORKDIR")})
			m.urls = func(h string) []string { return []string{"http://" + h + ":" + port} }
			auth := tt.auth
			cfg, _ := json.Marshal(module.RunConfig{Deep: true, Auth: &auth})
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
			defer cancel()
			res, err := m.Run(ctx, module.Request{Target: module.Target{Domain: "example.com", Verified: true}, Gate: &allowGate{}, Config: cfg})
			if err != nil {
				t.Fatal(err)
			}
			var found bool
			for _, f := range res.Findings {
				t.Logf("%s %s %s", f.Severity, f.CheckID, f.Asset)
				if f.CheckID == CheckXSS && strings.Contains(f.Asset, tt.path) {
					found = true
				}
			}
			if !found {
				t.Errorf("the XSS behind the login (%s) was not found", tt.path)
			}
		})
	}
}
