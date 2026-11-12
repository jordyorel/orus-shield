package zap

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"github.com/jordyorel/orus-shield/engine/internal/dialer"
	"github.com/jordyorel/orus-shield/engine/internal/gateproxy"
	"github.com/jordyorel/orus-shield/engine/internal/module"
)

func TestLoginForm(t *testing.T) {
	page := `<script>var x = "<form><input type=password></form>";</script>
	<form action="/search"><input name="q"></form>
	<form method="post" action="/session?next=%2F"><input type="hidden" name="csrf" value="t&amp;k"><input name="email"><input type="password" name="pw"></form>`
	action, hidden, ok := loginForm(page)
	if !ok || action != "/session?next=%2F" || hidden.Get("csrf") != "t&k" {
		t.Errorf("loginForm = %q %v %v", action, hidden, ok)
	}
	if _, _, ok := loginForm(`<form><input name="q"></form>`); ok {
		t.Error("a form without a password field is not a login form")
	}
}

// formLogin through a real gateproxy, against a local site.
func TestFormLogin(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			if r.FormValue("csrf") == "tok" && r.FormValue("username") == "tester" && r.FormValue("password") == "pw" {
				http.SetCookie(w, &http.Cookie{Name: "session", Value: "ok", Path: "/"}) //nolint:gosec // G124: a local HTTP test server
				http.Redirect(w, r, "/home", http.StatusFound)
				return
			}
		}
		_, _ = fmt.Fprint(w, `<form method="post"><input type="hidden" name="csrf" value="tok"><input name="username"><input name="password" type="password"></form>`)
	})
	mux.HandleFunc("/evil", func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, `<form method="post" action="https://collector.example.org/steal"><input name="username"><input name="password" type="password"></form>`)
	})
	mux.HandleFunc("/home", func(w http.ResponseWriter, r *http.Request) { _, _ = fmt.Fprint(w, "welcome") })
	srv := httptest.NewServer(mux)
	defer srv.Close()
	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())

	proxy, err := gateproxy.Start(context.Background(), gateproxy.Config{Domain: "example.com", Gate: &allowGate{},
		DNS: fakeDNS{ips: map[string][]netip.Addr{"example.com": {netip.MustParseAddr("127.0.0.1")}}}, Dial: dialer.NewSystem()})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = proxy.Close() }()
	login := "http://example.com:" + port

	auth, err := sessionAuth(context.Background(), proxy.URL(), "example.com", &module.ScanAuth{Kind: "form", LoginURL: login + "/login", Username: "tester", Secret: "pw"})
	if err != nil || auth.Kind != "header" || auth.HeaderName != "Cookie" || auth.Secret != "session=ok" {
		t.Fatalf("login = %+v, %v", auth, err)
	}
	for name, a := range map[string]*module.ScanAuth{
		"wrong password":  {Kind: "form", LoginURL: login + "/login", Username: "tester", Secret: "nope"},
		"posts elsewhere": {Kind: "form", LoginURL: login + "/evil", Username: "tester", Secret: "pw"},
		"no login form":   {Kind: "form", LoginURL: login + "/home", Username: "tester", Secret: "pw"},
	} {
		if _, err := sessionAuth(context.Background(), proxy.URL(), "example.com", a); !errors.Is(err, ErrLoginFailed) {
			t.Errorf("%s = %v, want ErrLoginFailed", name, err)
		} else if strings.Contains(err.Error(), a.Secret) {
			t.Errorf("%s: the error shows the password", name)
		}
	}
}
