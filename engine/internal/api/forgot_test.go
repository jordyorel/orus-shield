package api

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/jordyorel/orus-shield/engine/internal/mailer"
)

// nextMail waits for an email sent in the background, or fails.
func (e *env) nextMail() mailer.Message {
	e.t.Helper()
	select {
	case m := <-e.mail.sent:
		return m
	case <-time.After(5 * time.Second):
		e.t.Fatal("no email sent")
		return mailer.Message{}
	}
}

// noMail checks that nothing is sent.
func (e *env) noMail() {
	e.t.Helper()
	select {
	case m := <-e.mail.sent:
		e.t.Errorf("unexpected email to %s: %s", m.To, m.Subject)
	case <-time.After(200 * time.Millisecond):
	}
}

func TestForgotPassword(t *testing.T) {
	e := newEnv(t)
	e.user("alice@example.com", e.org("Acme"), "viewer")
	const path = "/api/v1/auth/forgot-password"

	// Known address, typed with capitals: 202 and an email with a link.
	if r := e.do("POST", path, "", forgotPasswordRequest{Email: " Alice@Example.com "}); r.status != http.StatusAccepted {
		t.Fatalf("forgot = %d %s", r.status, r.body)
	}
	m := e.nextMail()
	if m.To != "alice@example.com" || !strings.Contains(m.Subject, "mot de passe") {
		t.Fatalf("email to %q, subject %q", m.To, m.Subject)
	}
	const prefix = "https://app.example/setup-password#token="
	i := strings.Index(m.Text, prefix)
	if i < 0 {
		t.Fatalf("no link in:\n%s", m.Text)
	}
	raw := strings.Fields(m.Text[i+len(prefix):])[0]
	token, err := url.QueryUnescape(raw)
	if err != nil {
		t.Fatal(err)
	}

	// The link's token sets a new password, once.
	const newPassword = "a brand new passphrase"
	if r := e.do("POST", "/api/v1/auth/setup-password", "", setupPasswordRequest{Token: token, Password: newPassword}); r.status != http.StatusNoContent {
		t.Fatalf("setup with emailed token = %d %s", r.status, r.body)
	}
	if r := e.do("POST", "/api/v1/auth/login", "", loginRequest{Email: "alice@example.com", Password: newPassword}); r.status != http.StatusOK {
		t.Errorf("login with the new password = %d", r.status)
	}
	if r := e.do("POST", "/api/v1/auth/setup-password", "", setupPasswordRequest{Token: token, Password: "another passphrase here"}); r.status != http.StatusBadRequest {
		t.Errorf("token reused = %d, want 400", r.status)
	}

	// Unknown and malformed addresses: the same 202, and no email.
	for _, email := range []string{"nobody@example.com", "not an address"} {
		if r := e.do("POST", path, "", forgotPasswordRequest{Email: email}); r.status != http.StatusAccepted {
			t.Errorf("%q = %d, want the same 202", email, r.status)
		}
	}
	e.noMail()
}

func TestForgotPasswordRateLimit(t *testing.T) {
	e := newEnv(t)
	e.user("bob@example.com", e.org("Acme"), "viewer")
	const path = "/api/v1/auth/forgot-password"
	for i := range 3 {
		if r := e.do("POST", path, "", forgotPasswordRequest{Email: "bob@example.com"}); r.status != http.StatusAccepted {
			t.Fatalf("request %d = %d", i+1, r.status)
		}
		e.nextMail()
	}
	r := e.do("POST", path, "", forgotPasswordRequest{Email: "bob@example.com"})
	if r.status != http.StatusTooManyRequests || r.header.Get("Retry-After") != "3600" {
		t.Errorf("4th request = %d, Retry-After %q; want 429 and 3600", r.status, r.header.Get("Retry-After"))
	}
	e.noMail()
}
