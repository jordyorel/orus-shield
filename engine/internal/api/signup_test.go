package api

import (
	"net/http"
	"strings"
	"testing"
)

func TestSignup(t *testing.T) {
	e := newEnv(t)
	const pw = "my own long passphrase"

	// The form: 202, and a confirmation email. No account yet.
	if r := e.do("POST", "/api/v1/auth/signup", "", signupRequest{Email: "Founder@Startup.example", Organization: " Startup SA "}); r.status != http.StatusAccepted {
		t.Fatalf("signup = %d %s", r.status, r.body)
	}
	m := e.nextMail()
	if m.To != "founder@startup.example" || !strings.Contains(m.Subject, "Confirmez") || !strings.Contains(m.Text, "« Startup SA »") {
		t.Fatalf("email %q to %q:\n%s", m.Subject, m.To, m.Text)
	}
	const prefix = "https://app.example/signup/complete#token="
	i := strings.Index(m.Text, prefix)
	if i < 0 {
		t.Fatalf("no link in:\n%s", m.Text)
	}
	token := strings.Fields(m.Text[i+len(prefix):])[0]
	if r := e.do("POST", "/api/v1/auth/login", "", loginRequest{Email: "founder@startup.example", Password: pw}); r.status != http.StatusUnauthorized {
		t.Errorf("login before confirmation = %d, want 401", r.status)
	}

	// A weak password is refused and the link still works afterwards.
	if r := e.do("POST", "/api/v1/auth/signup/complete", "", setupPasswordRequest{Token: token, Password: "short"}); r.status != http.StatusBadRequest {
		t.Errorf("short password = %d, want 400", r.status)
	}
	if r := e.do("POST", "/api/v1/auth/signup/complete", "", setupPasswordRequest{Token: token, Password: pw}); r.status != http.StatusNoContent {
		t.Fatalf("complete = %d %s", r.status, r.body)
	}
	if r := e.do("POST", "/api/v1/auth/signup/complete", "", setupPasswordRequest{Token: token, Password: pw}); r.status != http.StatusBadRequest {
		t.Errorf("link reused = %d, want 400", r.status)
	}

	// Signed in, they are the admin of their new organization, and must
	// enable the second factor before anything else.
	r := e.do("POST", "/api/v1/auth/login", "", loginRequest{Email: "founder@startup.example", Password: pw})
	if r.status != http.StatusOK {
		t.Fatalf("login = %d %s", r.status, r.body)
	}
	session := r.cookie(sessionCookie).Value
	var me meResponse
	e.do("GET", "/api/v1/auth/me", session, nil).json(t, &me)
	if len(me.Orgs) != 1 || me.Orgs[0].OrgName != "Startup SA" || me.Orgs[0].Role != "admin" {
		t.Fatalf("me = %+v", me)
	}
	if r := e.do("GET", "/api/v1/orgs/"+me.Orgs[0].OrgID+"/targets", session, nil); r.status != http.StatusForbidden {
		t.Errorf("admin without MFA = %d, want 403 mfa_required", r.status)
	}

	// Signing up again with the address: the same 202, an email that says
	// to sign in, and no second organization.
	if r := e.do("POST", "/api/v1/auth/signup", "", signupRequest{Email: "founder@startup.example", Organization: "Again"}); r.status != http.StatusAccepted {
		t.Errorf("existing address = %d", r.status)
	}
	if m := e.nextMail(); !strings.Contains(m.Subject, "déjà un compte") || !strings.Contains(m.Text, "https://app.example/forgot-password") {
		t.Errorf("existing address email %q:\n%s", m.Subject, m.Text)
	}

	for name, body := range map[string]signupRequest{
		"bad email":   {Email: "nope", Organization: "X"},
		"no org name": {Email: "a@example.com", Organization: "  "},
	} {
		if r := e.do("POST", "/api/v1/auth/signup", "", body); r.status != http.StatusBadRequest {
			t.Errorf("%s = %d, want 400", name, r.status)
		}
	}
}

func TestSignupRateLimit(t *testing.T) {
	e := newEnv(t)
	for i := range 5 {
		email := "user" + string(rune('a'+i)) + "@example.com"
		if r := e.do("POST", "/api/v1/auth/signup", "", signupRequest{Email: email, Organization: "Org"}); r.status != http.StatusAccepted {
			t.Fatalf("request %d = %d", i+1, r.status)
		}
		e.nextMail()
	}
	r := e.do("POST", "/api/v1/auth/signup", "", signupRequest{Email: "another@example.com", Organization: "Org"})
	if r.status != http.StatusTooManyRequests || r.header.Get("Retry-After") != "3600" {
		t.Errorf("6th request from one address = %d (Retry-After %q), want 429", r.status, r.header.Get("Retry-After"))
	}
}
