package api

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jordyorel/orus-shield/engine/internal/password"
	"github.com/jordyorel/orus-shield/engine/internal/store"
	"github.com/jordyorel/orus-shield/engine/internal/store/storetest"
)

const testPassword = "correct horse battery staple"

// env is an API server on a fresh database.
type env struct {
	t       *testing.T
	st      *store.Store
	handler http.Handler
	now     time.Time
}

func newEnv(t *testing.T) *env {
	t.Helper()
	st := storetest.New(t)
	e := &env{t: t, st: st, now: time.Now()}
	srv, err := New(st, Config{Now: func() time.Time { return e.now }}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	if e.handler, err = srv.Handler(); err != nil {
		t.Fatal(err)
	}
	return e
}

// org creates an organization and returns its ID.
func (e *env) org(name string) string {
	e.t.Helper()
	o, err := e.st.CreateOrganization(context.Background(), name, "test")
	if err != nil {
		e.t.Fatal(err)
	}
	return o.ID
}

// user creates an account with testPassword and the given role in orgID.
func (e *env) user(email, orgID, role string) store.User {
	e.t.Helper()
	ctx := context.Background()
	u, err := e.st.CreateUser(ctx, email)
	if err != nil {
		e.t.Fatal(err)
	}
	if orgID != "" {
		if err := e.st.SetMembership(ctx, u.ID, orgID, role, "test"); err != nil {
			e.t.Fatal(err)
		}
	}
	token, err := e.st.IssueSetupToken(ctx, u.ID, time.Hour, "test")
	if err != nil {
		e.t.Fatal(err)
	}
	hash, err := password.Hash(testPassword)
	if err != nil {
		e.t.Fatal(err)
	}
	if _, err := e.st.Auth().SetPasswordWithToken(ctx, token, hash, "test"); err != nil {
		e.t.Fatal(err)
	}
	return u
}

// response is a recorded answer.
type response struct {
	status int
	header http.Header
	body   []byte
}

func (r response) json(t *testing.T, v any) {
	t.Helper()
	if err := json.Unmarshal(r.body, v); err != nil {
		t.Fatalf("decode %s: %v", r.body, err)
	}
}

func (r response) cookie(name string) *http.Cookie {
	for _, c := range (&http.Response{Header: r.header}).Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// do sends a request as the API's own dashboard would: same origin.
func (e *env) do(method, path, session string, body any) response {
	e.t.Helper()
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			e.t.Fatal(err)
		}
		rd = bytes.NewReader(b)
	}
	req := httptest.NewRequest(method, path, rd)
	req.RemoteAddr = "192.0.2.1:4000"
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	if session != "" {
		req.Header.Set("Cookie", sessionCookie+"="+session) // what a browser sends back
	}
	rec := httptest.NewRecorder()
	e.handler.ServeHTTP(rec, req)
	return response{status: rec.Code, header: rec.Header(), body: rec.Body.Bytes()}
}

// login returns a session token for email.
func (e *env) login(email string) string {
	e.t.Helper()
	r := e.do("POST", "/api/v1/auth/login", "", loginRequest{Email: email, Password: testPassword})
	if r.status != http.StatusOK {
		e.t.Fatalf("login %s = %d %s", email, r.status, r.body)
	}
	c := r.cookie(sessionCookie)
	if c == nil {
		e.t.Fatal("no session cookie")
	}
	return c.Value
}

func TestLoginAndMe(t *testing.T) {
	e := newEnv(t)
	orgID := e.org("Acme")
	e.user("alice@example.com", orgID, store.RoleAdmin)

	r := e.do("POST", "/api/v1/auth/login", "", loginRequest{Email: "Alice@Example.com", Password: testPassword})
	if r.status != http.StatusOK {
		t.Fatalf("login = %d %s", r.status, r.body)
	}
	c := r.cookie(sessionCookie)
	if c == nil || !c.Secure || !c.HttpOnly || c.SameSite != http.SameSiteLaxMode || c.Path != "/" || c.Domain != "" {
		t.Fatalf("session cookie = %+v, want __Host- rules (Secure, HttpOnly, Lax, Path=/, no Domain)", c)
	}
	var me meResponse
	r.json(t, &me)
	if me.Email != "alice@example.com" || len(me.Orgs) != 1 || me.Orgs[0].OrgID != orgID || me.Orgs[0].Role != "admin" {
		t.Errorf("login body = %+v", me)
	}

	r = e.do("GET", "/api/v1/auth/me", c.Value, nil)
	if r.status != http.StatusOK {
		t.Errorf("me = %d %s", r.status, r.body)
	}
	if r.header.Get("Cache-Control") != "no-store" || r.header.Get("X-Content-Type-Options") != "nosniff" {
		t.Errorf("security headers missing: %v", r.header)
	}
	if strings.Contains(string(r.body), "password") || strings.Contains(string(r.body), "argon2") {
		t.Errorf("me leaks password data: %s", r.body)
	}
}

func TestLoginFailuresAreIndistinguishable(t *testing.T) {
	e := newEnv(t)
	orgID := e.org("Acme")
	e.user("alice@example.com", orgID, store.RoleAdmin)
	// bob has an account but never set a password.
	if _, err := e.st.CreateUser(context.Background(), "bob@example.com"); err != nil {
		t.Fatal(err)
	}
	var first string
	for name, req := range map[string]loginRequest{
		"wrong password": {Email: "alice@example.com", Password: "wrong password!!"},
		"unknown email":  {Email: "nobody@example.com", Password: testPassword},
		"no password":    {Email: "bob@example.com", Password: testPassword},
		"invalid email":  {Email: "not an email", Password: testPassword},
	} {
		r := e.do("POST", "/api/v1/auth/login", "", req)
		if r.status != http.StatusUnauthorized || r.cookie(sessionCookie) != nil {
			t.Errorf("%s = %d, cookie %v; want 401 without session", name, r.status, r.cookie(sessionCookie))
		}
		if first == "" {
			first = string(r.body)
		} else if string(r.body) != first {
			t.Errorf("%s answers %s, others %s: the reason leaks", name, r.body, first)
		}
	}
}

func TestLoginRateLimit(t *testing.T) {
	e := newEnv(t)
	e.user("alice@example.com", e.org("Acme"), store.RoleAdmin)
	for range maxFailuresPerKey {
		e.do("POST", "/api/v1/auth/login", "", loginRequest{Email: "alice@example.com", Password: "wrong password!!"})
	}
	// Even the right password is refused while the limit holds.
	r := e.do("POST", "/api/v1/auth/login", "", loginRequest{Email: "alice@example.com", Password: testPassword})
	if r.status != http.StatusTooManyRequests || r.header.Get("Retry-After") == "" {
		t.Errorf("after %d failures = %d, want 429 with Retry-After", maxFailuresPerKey, r.status)
	}
	// The window passes.
	e.now = e.now.Add(loginWindow + time.Minute)
	if r := e.do("POST", "/api/v1/auth/login", "", loginRequest{Email: "alice@example.com", Password: testPassword}); r.status != http.StatusOK {
		t.Errorf("after the window = %d, want 200", r.status)
	}
}

func TestLogout(t *testing.T) {
	e := newEnv(t)
	e.user("alice@example.com", e.org("Acme"), store.RoleViewer)
	session := e.login("alice@example.com")
	r := e.do("POST", "/api/v1/auth/logout", session, nil)
	if r.status != http.StatusNoContent {
		t.Fatalf("logout = %d", r.status)
	}
	if c := r.cookie(sessionCookie); c == nil || c.MaxAge >= 0 {
		t.Errorf("logout cookie = %+v, want deletion", c)
	}
	if r := e.do("GET", "/api/v1/auth/me", session, nil); r.status != http.StatusUnauthorized {
		t.Errorf("me after logout = %d, want 401", r.status)
	}
}

func TestSessionRequired(t *testing.T) {
	e := newEnv(t)
	for name, token := range map[string]string{"no cookie": "", "forged": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"} {
		if r := e.do("GET", "/api/v1/auth/me", token, nil); r.status != http.StatusUnauthorized {
			t.Errorf("%s: me = %d, want 401", name, r.status)
		}
	}
}

func TestSetupPassword(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	u, err := e.st.CreateUser(ctx, "carol@example.com")
	if err != nil {
		t.Fatal(err)
	}
	token, err := e.st.IssueSetupToken(ctx, u.ID, time.Hour, "test")
	if err != nil {
		t.Fatal(err)
	}
	if r := e.do("POST", "/api/v1/auth/setup-password", "", setupPasswordRequest{Token: token, Password: "short"}); r.status != http.StatusBadRequest {
		t.Errorf("short password = %d, want 400", r.status)
	}
	if r := e.do("POST", "/api/v1/auth/setup-password", "", setupPasswordRequest{Token: token, Password: testPassword}); r.status != http.StatusNoContent {
		t.Fatalf("setup = %d %s", r.status, r.body)
	}
	if r := e.do("POST", "/api/v1/auth/setup-password", "", setupPasswordRequest{Token: token, Password: testPassword}); r.status != http.StatusBadRequest {
		t.Errorf("token reused = %d, want 400", r.status)
	}
	e.login("carol@example.com")
}

func TestCrossOriginWritesAreRefused(t *testing.T) {
	e := newEnv(t)
	body := `{"email":"alice@example.com","password":"x"}`
	for name, set := range map[string]func(*http.Request){
		"cross-site fetch": func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "cross-site") },
		"foreign origin":   func(r *http.Request) { r.Header.Set("Origin", "https://evil.example") },
	} {
		req := httptest.NewRequest("POST", "/api/v1/auth/login", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		set(req)
		rec := httptest.NewRecorder()
		e.handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Errorf("%s: login = %d, want 403", name, rec.Code)
		}
	}
}

func TestBodyValidation(t *testing.T) {
	e := newEnv(t)
	send := func(contentType, body string) int {
		req := httptest.NewRequest("POST", "/api/v1/auth/login", strings.NewReader(body))
		req.Header.Set("Content-Type", contentType)
		rec := httptest.NewRecorder()
		e.handler.ServeHTTP(rec, req)
		return rec.Code
	}
	tests := []struct {
		name, contentType, body string
		want                    int
	}{
		{"not JSON content type", "text/plain", `{}`, http.StatusUnsupportedMediaType},
		{"unknown field", "application/json", `{"email":"a@b.c","password":"x","admin":true}`, http.StatusBadRequest},
		{"two objects", "application/json", `{"email":"a@b.c"}{"email":"d@e.f"}`, http.StatusBadRequest},
		{"too large", "application/json", `{"email":"` + strings.Repeat("a", maxBodyBytes) + `"}`, http.StatusRequestEntityTooLarge},
	}
	for _, tt := range tests {
		if got := send(tt.contentType, tt.body); got != tt.want {
			t.Errorf("%s = %d, want %d", tt.name, got, tt.want)
		}
	}
	if r := e.do("GET", "/api/v1/nothing-here", "", nil); r.status != http.StatusNotFound {
		t.Errorf("unknown route = %d, want 404", r.status)
	}
}
