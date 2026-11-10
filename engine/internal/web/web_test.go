package web

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"html/template"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/jordyorel/orus-shield/engine/internal/account"
	"github.com/jordyorel/orus-shield/engine/internal/password"
	"github.com/jordyorel/orus-shield/engine/internal/seal"
	"github.com/jordyorel/orus-shield/engine/internal/store"
	"github.com/jordyorel/orus-shield/engine/internal/store/storetest"
	"github.com/jordyorel/orus-shield/engine/internal/totp"
)

const testPassword = "correct horse battery staple"

// env is a dashboard on a fresh database.
type env struct {
	t       *testing.T
	st      *store.Store
	srv     *Server
	handler http.Handler
	now     time.Time
}

func newEnv(t *testing.T) *env {
	t.Helper()
	st := storetest.New(t)
	e := &env{t: t, st: st, now: time.Now()}
	key := make([]byte, seal.KeyLen)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	acct, err := account.New(st.Auth(), account.Config{Now: func() time.Time { return e.now }, MFAKey: key})
	if err != nil {
		t.Fatal(err)
	}
	if e.srv, err = New(acct, slog.New(slog.NewTextHandler(io.Discard, nil))); err != nil {
		t.Fatal(err)
	}
	e.handler = e.srv.Handler()
	return e
}

func (e *env) org(name string) string {
	e.t.Helper()
	o, err := e.st.CreateOrganization(context.Background(), name, "test")
	if err != nil {
		e.t.Fatal(err)
	}
	return o.ID
}

// user creates an account with testPassword and role in orgID.
func (e *env) user(email, orgID, role string) {
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
	token := e.setupToken(u.ID)
	hash, err := password.Hash(testPassword)
	if err != nil {
		e.t.Fatal(err)
	}
	if _, err := e.st.Auth().SetPasswordWithToken(ctx, token, hash, "test"); err != nil {
		e.t.Fatal(err)
	}
}

func (e *env) setupToken(userID string) string {
	e.t.Helper()
	token, err := e.st.IssueSetupToken(context.Background(), userID, time.Hour, "test")
	if err != nil {
		e.t.Fatal(err)
	}
	return token
}

// response is a recorded answer.
type response struct {
	status int
	header http.Header
	body   string
}

func (r response) cookie(name string) *http.Cookie {
	for _, c := range (&http.Response{Header: r.header}).Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

func (r response) location() string { return r.header.Get("Location") }

// do sends a request as a browser on the dashboard would: same origin,
// form-encoded body for posts.
func (e *env) do(method, target, session string, form url.Values) response {
	e.t.Helper()
	return e.doFrom("same-origin", method, target, session, form)
}

func (e *env) doFrom(site, method, target, session string, form url.Values) response {
	e.t.Helper()
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req := httptest.NewRequest(method, target, body)
	req.RemoteAddr = "192.0.2.1:4000"
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	req.Header.Set("Sec-Fetch-Site", site)
	if session != "" {
		req.Header.Set("Cookie", account.SessionCookie+"="+session)
	}
	rec := httptest.NewRecorder()
	e.handler.ServeHTTP(rec, req)
	return response{status: rec.Code, header: rec.Header(), body: rec.Body.String()}
}

// login signs in with the password only and returns the session token.
func (e *env) login(email string) string {
	e.t.Helper()
	r := e.do("POST", "/login", "", url.Values{"email": {email}, "password": {testPassword}})
	c := r.cookie(account.SessionCookie)
	if r.status != http.StatusSeeOther || c == nil {
		e.t.Fatalf("login %s = %d, cookie %v\n%s", email, r.status, c, r.body)
	}
	return c.Value
}

var (
	secretRe = regexp.MustCompile(`<p class="secret"[^>]*>([A-Z2-7 ]+)</p>`)
	tokenRe  = regexp.MustCompile(`name="mfa_token" value="([^"]+)"`)
	// inlineCode finds what the CSP would block: style attributes, script
	// elements, event handler attributes (onclick=...).
	inlineCode = regexp.MustCompile(`style=|<script|\son[a-z]+=`)
	codeRe     = regexp.MustCompile(`<li>([A-Z2-7]{4}-[A-Z2-7]{4}-[A-Z2-7]{4}-[A-Z2-7]{4})</li>`)
)

// enrol runs the enrolment pages for session and returns the TOTP secret
// and the recovery codes.
func (e *env) enrol(session string) ([]byte, []string) {
	e.t.Helper()
	r := e.do("POST", "/mfa/setup", session, url.Values{"password": {testPassword}})
	m := secretRe.FindStringSubmatch(r.body)
	if r.status != http.StatusOK || m == nil {
		e.t.Fatalf("mfa setup = %d, no secret\n%s", r.status, r.body)
	}
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ReplaceAll(m[1], " ", ""))
	if err != nil {
		e.t.Fatal(err)
	}
	r = e.do("POST", "/mfa/confirm", session, url.Values{"code": {e.code(secret)}})
	codes := codeRe.FindAllStringSubmatch(r.body, -1)
	if r.status != http.StatusOK || len(codes) != store.RecoveryCodeCount {
		e.t.Fatalf("mfa confirm = %d, %d codes\n%s", r.status, len(codes), r.body)
	}
	var out []string
	for _, c := range codes {
		out = append(out, c[1])
	}
	e.now = e.now.Add(totp.Period) // the next code is a new one
	return secret, out
}

func (e *env) code(secret []byte) string {
	return totp.Code(secret, totp.Step(e.now), totp.Digits)
}

func contains(t *testing.T, r response, want ...string) {
	t.Helper()
	for _, w := range want {
		// Text from Go is escaped in the page: an apostrophe becomes &#39;.
		if !strings.Contains(r.body, w) && !strings.Contains(r.body, template.HTMLEscapeString(w)) {
			t.Errorf("page does not contain %q\n%s", w, r.body)
		}
	}
}

func TestPagesHaveSecurityHeaders(t *testing.T) {
	e := newEnv(t)
	r := e.do("GET", "/login", "", nil)
	if r.status != http.StatusOK {
		t.Fatalf("GET /login = %d", r.status)
	}
	for name, want := range map[string]string{
		"Content-Security-Policy": csp,
		"X-Content-Type-Options":  "nosniff",
		"X-Frame-Options":         "DENY",
		"Cache-Control":           "no-store",
		"Content-Type":            "text/html; charset=utf-8",
	} {
		if got := r.header.Get(name); got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}
	if strings.Contains(csp, "unsafe-inline") || strings.Contains(csp, "unsafe-eval") {
		t.Errorf("CSP allows inline code: %s", csp)
	}
	// The CSP forbids inline styles and scripts: no page may use them.
	for name := range pageLayouts {
		b, err := files.ReadFile("templates/" + name + ".html")
		if err != nil {
			t.Fatal(err)
		}
		if inlineCode.Match(b) {
			t.Errorf("template %s has inline style or script", name)
		}
	}
	contains(t, r, `href="`+e.srv.assetURL("app.css")+`"`, `name="email"`, `autocomplete="current-password"`)
}

func TestLoginWithPassword(t *testing.T) {
	e := newEnv(t)
	orgID := e.org("Acme")
	e.user("viewer@example.com", orgID, store.RoleViewer)

	r := e.do("POST", "/login", "", url.Values{"email": {"Viewer@Example.com"}, "password": {testPassword}})
	c := r.cookie(account.SessionCookie)
	if r.status != http.StatusSeeOther || r.location() != "/" || c == nil {
		t.Fatalf("login = %d to %q, cookie %v", r.status, r.location(), c)
	}
	if !c.Secure || !c.HttpOnly || c.SameSite != http.SameSiteLaxMode || c.Path != "/" {
		t.Errorf("cookie = %+v, want Secure HttpOnly Lax Path=/", c)
	}

	r = e.do("GET", "/", c.Value, nil)
	if r.status != http.StatusSeeOther || r.location() != "/orgs/"+orgID {
		t.Fatalf("GET / = %d to %q", r.status, r.location())
	}
	r = e.do("GET", "/orgs/"+orgID, c.Value, nil)
	if r.status != http.StatusOK {
		t.Fatalf("overview = %d\n%s", r.status, r.body)
	}
	contains(t, r, "Acme", "viewer@example.com", "Lecteur", `aria-current="page"`)

	// Signed in: the login page sends you home.
	if r := e.do("GET", "/login", c.Value, nil); r.status != http.StatusSeeOther {
		t.Errorf("GET /login signed in = %d, want 303", r.status)
	}
}

func TestLoginFailures(t *testing.T) {
	e := newEnv(t)
	e.user("alice@example.com", e.org("Acme"), store.RoleViewer)

	// Unknown email and wrong password get the same page: no account
	// enumeration. The email typed back is escaped by html/template.
	evil := `"><b>x</b>@example.com`
	for _, f := range []url.Values{
		{"email": {"alice@example.com"}, "password": {"wrong password!!"}},
		{"email": {evil}, "password": {testPassword}},
	} {
		r := e.do("POST", "/login", "", f)
		if r.status != http.StatusUnauthorized || r.cookie(account.SessionCookie) != nil {
			t.Fatalf("bad login = %d, cookie %v", r.status, r.cookie(account.SessionCookie))
		}
		contains(t, r, msgBadCredentials)
		if strings.Contains(r.body, "<b>x</b>") {
			t.Errorf("typed email rendered as markup:\n%s", r.body)
		}
	}

	// The shared rate limit applies to the dashboard too.
	for range account.MaxFailuresPerKey {
		e.do("POST", "/login", "", url.Values{"email": {"alice@example.com"}, "password": {"wrong password!!"}})
	}
	r := e.do("POST", "/login", "", url.Values{"email": {"alice@example.com"}, "password": {testPassword}})
	if r.status != http.StatusTooManyRequests || r.header.Get("Retry-After") == "" || r.cookie(account.SessionCookie) != nil {
		t.Fatalf("rate-limited login = %d, Retry-After %q", r.status, r.header.Get("Retry-After"))
	}
	contains(t, r, msgRateLimited)
}

func TestCrossOriginPostIsRefused(t *testing.T) {
	e := newEnv(t)
	e.user("alice@example.com", e.org("Acme"), store.RoleViewer)
	r := e.doFrom("cross-site", "POST", "/login", "", url.Values{"email": {"alice@example.com"}, "password": {testPassword}})
	if r.status != http.StatusForbidden || r.cookie(account.SessionCookie) != nil {
		t.Fatalf("cross-site login = %d, want 403 without session", r.status)
	}
	contains(t, r, "Requête refusée")
}

func TestAdminMustEnrolThenLogsInWithCode(t *testing.T) {
	e := newEnv(t)
	orgID := e.org("Acme")
	e.user("admin@example.com", orgID, store.RoleAdmin)
	session := e.login("admin@example.com")

	// No second factor yet: the organization is out of reach.
	r := e.do("GET", "/orgs/"+orgID, session, nil)
	if r.status != http.StatusSeeOther || r.location() != "/mfa/setup?reason=admin" {
		t.Fatalf("admin without MFA = %d to %q", r.status, r.location())
	}
	contains(t, e.do("GET", "/mfa/setup?reason=admin", session, nil), msgAdminNeedsMFA)

	// Enrolment asks for the password again.
	r = e.do("POST", "/mfa/setup", session, url.Values{"password": {"wrong password!!"}})
	if r.status != http.StatusForbidden || secretRe.MatchString(r.body) {
		t.Fatalf("setup with wrong password = %d", r.status)
	}
	// A wrong first code does not reveal the secret again.
	r = e.do("POST", "/mfa/setup", session, url.Values{"password": {testPassword}})
	if !secretRe.MatchString(r.body) {
		t.Fatalf("no secret on the enrolment page\n%s", r.body)
	}
	contains(t, r, `href="otpauth://totp/`)
	r = e.do("POST", "/mfa/confirm", session, url.Values{"code": {"000000"}})
	if r.status != http.StatusBadRequest || secretRe.MatchString(r.body) {
		t.Fatalf("wrong first code = %d, secret shown again: %v", r.status, secretRe.MatchString(r.body))
	}
	contains(t, r, msgBadCode)

	secret, codes := e.enrol(session)
	// Enrolment upgraded this session: the organization opens.
	if r := e.do("GET", "/orgs/"+orgID, session, nil); r.status != http.StatusOK {
		t.Fatalf("overview after enrolment = %d", r.status)
	}

	// Next login: password, then code.
	r = e.do("POST", "/login", "", url.Values{"email": {"admin@example.com"}, "password": {testPassword}})
	m := tokenRe.FindStringSubmatch(r.body)
	if r.status != http.StatusOK || m == nil || r.cookie(account.SessionCookie) != nil {
		t.Fatalf("password step = %d, token %v", r.status, m)
	}
	mfaToken := m[1]
	r = e.do("POST", "/login/mfa", "", url.Values{"mfa_token": {mfaToken}, "code": {"000000"}})
	if r.status != http.StatusUnauthorized || r.cookie(account.SessionCookie) != nil || !strings.Contains(r.body, mfaToken) {
		t.Fatalf("wrong code = %d, the form must stay usable", r.status)
	}
	r = e.do("POST", "/login/mfa", "", url.Values{"mfa_token": {mfaToken}, "code": {e.code(secret)}})
	if r.status != http.StatusSeeOther || r.cookie(account.SessionCookie) == nil {
		t.Fatalf("right code = %d", r.status)
	}
	if r := e.do("GET", "/orgs/"+orgID, r.cookie(account.SessionCookie).Value, nil); r.status != http.StatusOK {
		t.Fatalf("overview after MFA login = %d", r.status)
	}

	// A used challenge is gone: back to the password.
	r = e.do("POST", "/login/mfa", "", url.Values{"mfa_token": {mfaToken}, "code": {e.code(secret)}})
	if r.status != http.StatusUnauthorized {
		t.Fatalf("reused challenge = %d", r.status)
	}
	contains(t, r, msgLoginExpired)

	// A recovery code works once, typed in lowercase.
	r = e.do("POST", "/login", "", url.Values{"email": {"admin@example.com"}, "password": {testPassword}})
	mfaToken = tokenRe.FindStringSubmatch(r.body)[1]
	r = e.do("POST", "/login/mfa", "", url.Values{"mfa_token": {mfaToken}, "code": {strings.ToLower(codes[0])}})
	if r.status != http.StatusSeeOther {
		t.Fatalf("recovery code = %d\n%s", r.status, r.body)
	}
}

func TestNonMemberGets404(t *testing.T) {
	e := newEnv(t)
	e.user("alice@example.com", e.org("Acme"), store.RoleViewer)
	other := e.org("Other")
	session := e.login("alice@example.com")
	for _, path := range []string{"/orgs/" + other, "/orgs/not-a-uuid", "/nowhere"} {
		r := e.do("GET", path, session, nil)
		if r.status != http.StatusNotFound || strings.Contains(r.body, "Other") {
			t.Errorf("GET %s = %d", path, r.status)
		}
	}
}

func TestSignedOutIsSentToLogin(t *testing.T) {
	e := newEnv(t)
	orgID := e.org("Acme")
	for _, path := range []string{"/", "/orgs/" + orgID, "/mfa/setup"} {
		r := e.do("GET", path, "", nil)
		if r.status != http.StatusSeeOther || r.location() != "/login" {
			t.Errorf("GET %s signed out = %d to %q", path, r.status, r.location())
		}
		if r := e.do("GET", path, "forged-token", nil); r.location() != "/login" {
			t.Errorf("GET %s with a forged cookie = %d to %q", path, r.status, r.location())
		}
	}
}

func TestLogout(t *testing.T) {
	e := newEnv(t)
	orgID := e.org("Acme")
	e.user("alice@example.com", orgID, store.RoleViewer)
	session := e.login("alice@example.com")

	r := e.do("POST", "/logout", session, url.Values{})
	c := r.cookie(account.SessionCookie)
	if r.status != http.StatusSeeOther || r.location() != "/login?ok=logout" || c == nil || c.MaxAge >= 0 {
		t.Fatalf("logout = %d to %q, cookie %v", r.status, r.location(), c)
	}
	if r := e.do("GET", "/orgs/"+orgID, session, nil); r.location() != "/login" {
		t.Errorf("old session still works: %d", r.status)
	}
	contains(t, e.do("GET", "/login?ok=logout", "", nil), notices["logout"])
}

func TestSetupPassword(t *testing.T) {
	e := newEnv(t)
	orgID := e.org("Acme")
	u, err := e.st.CreateUser(context.Background(), "new@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if err := e.st.SetMembership(context.Background(), u.ID, orgID, store.RoleViewer, "test"); err != nil {
		t.Fatal(err)
	}
	token := e.setupToken(u.ID)
	phrase := "a long and new passphrase"

	for name, tc := range map[string]struct {
		form url.Values
		msg  string
	}{
		"mismatch":  {url.Values{"token": {token}, "password": {phrase}, "confirm": {phrase + "x"}}, msgPasswordMatch},
		"too short": {url.Values{"token": {token}, "password": {"short"}, "confirm": {"short"}}, msgPasswordShort},
		"bad token": {url.Values{"token": {"nope"}, "password": {phrase}, "confirm": {phrase}}, msgSetupToken},
	} {
		r := e.do("POST", "/setup-password", "", tc.form)
		if r.status != http.StatusBadRequest {
			t.Errorf("%s = %d", name, r.status)
		}
		contains(t, r, tc.msg)
		if strings.Contains(r.body, tc.form.Get("password")) && tc.form.Get("password") != "" {
			t.Errorf("%s: password echoed back in the page", name)
		}
	}

	r := e.do("POST", "/setup-password", "", url.Values{"token": {token}, "password": {phrase}, "confirm": {phrase}})
	if r.status != http.StatusSeeOther || r.location() != "/login?ok=password" {
		t.Fatalf("setup = %d to %q\n%s", r.status, r.location(), r.body)
	}
	r = e.do("POST", "/login", "", url.Values{"email": {"new@example.com"}, "password": {phrase}})
	if r.status != http.StatusSeeOther {
		t.Fatalf("login with the new password = %d", r.status)
	}
	// The token was single-use.
	r = e.do("POST", "/setup-password", "", url.Values{"token": {token}, "password": {phrase}, "confirm": {phrase}})
	if r.status != http.StatusBadRequest {
		t.Errorf("token reused = %d", r.status)
	}
}

func TestStaticFiles(t *testing.T) {
	e := newEnv(t)
	r := e.do("GET", e.srv.assetURL("app.css"), "", nil)
	if r.status != http.StatusOK || !strings.HasPrefix(r.header.Get("Content-Type"), "text/css") ||
		!strings.Contains(r.header.Get("Cache-Control"), "immutable") {
		t.Fatalf("css = %d %v", r.status, r.header)
	}
	if r := e.do("GET", "/static/app.css?v=old", "", nil); r.header.Get("Cache-Control") != "no-cache" {
		t.Errorf("stale version cached: %q", r.header.Get("Cache-Control"))
	}
	for _, path := range []string{"/static/web.go", "/static/../web.go", "/static/templates"} {
		if r := e.do("GET", path, "", nil); r.status == http.StatusOK {
			t.Errorf("GET %s = 200", path)
		}
	}
}

func TestGroups(t *testing.T) {
	for in, want := range map[string]string{
		"":          "",
		"ABCD":      "ABCD",
		"ABCDEFGHI": "ABCD EFGH I",
	} {
		if got := groups(in); got != want {
			t.Errorf("groups(%q) = %q, want %q", in, got, want)
		}
	}
}
