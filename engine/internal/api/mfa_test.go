package api

import (
	"encoding/base32"
	"net/http"
	"strings"
	"testing"

	"github.com/jordyorel/orus-shield/engine/internal/store"
	"github.com/jordyorel/orus-shield/engine/internal/totp"
)

// code is the user's current TOTP code, as their phone shows it.
func (e *env) code(email string) string {
	e.t.Helper()
	secret, ok := e.secrets[email]
	if !ok {
		e.t.Fatalf("%s is not enrolled", email)
	}
	return totp.Code(secret, totp.Step(e.now), totp.Digits)
}

// tick moves the clock to the next time step, so the next code differs
// (an accepted code cannot be used twice).
func (e *env) tick() { e.now = e.now.Add(totp.Period) }

// enrol sets up MFA through the API with session and returns the recovery
// codes.
func (e *env) enrol(email, session string) []string {
	e.t.Helper()
	r := e.do("POST", "/api/v1/auth/mfa/setup", session, passwordRequest{Password: testPassword})
	if r.status != http.StatusOK {
		e.t.Fatalf("mfa setup = %d %s", r.status, r.body)
	}
	var setup mfaSetupResponse
	r.json(e.t, &setup)
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(setup.Secret)
	if err != nil {
		e.t.Fatal(err)
	}
	e.secrets[email] = secret
	r = e.do("POST", "/api/v1/auth/mfa/confirm", session, codeRequest{Code: e.code(email)})
	if r.status != http.StatusOK {
		e.t.Fatalf("mfa confirm = %d %s", r.status, r.body)
	}
	var rc recoveryCodesResponse
	r.json(e.t, &rc)
	e.tick()
	return rc.RecoveryCodes
}

// adminSession logs in and enrols MFA: what an admin needs to reach their
// organization.
func (e *env) adminSession(email string) string {
	e.t.Helper()
	session := e.login(email)
	e.enrol(email, session)
	return session
}

// challenge logs in an enrolled user with their password and returns the
// MFA token.
func (e *env) challenge(email string) string {
	e.t.Helper()
	r := e.do("POST", "/api/v1/auth/login", "", loginRequest{Email: email, Password: testPassword})
	var ch mfaChallengeResponse
	r.json(e.t, &ch)
	if r.status != http.StatusOK || !ch.MFARequired || ch.MFAToken == "" || r.cookie(sessionCookie) != nil {
		e.t.Fatalf("login of an enrolled user = %d %s, cookie %v; want an MFA challenge and no session", r.status, r.body, r.cookie(sessionCookie))
	}
	return ch.MFAToken
}

func (e *env) loginMFA(mfaToken, code string) response {
	e.t.Helper()
	return e.do("POST", "/api/v1/auth/login/mfa", "", loginMFARequest{MFAToken: mfaToken, Code: code})
}

func TestAdminsNeedMFA(t *testing.T) {
	e := newEnv(t)
	orgID := e.org("Acme")
	e.user("alice@example.com", orgID, store.RoleAdmin)
	overview := "/api/v1/orgs/" + orgID + "/overview"

	// A password alone gives an admin nothing in their organization, not
	// even reads.
	session := e.login("alice@example.com")
	r := e.do("GET", overview, session, nil)
	var eb errorBody
	r.json(t, &eb)
	if r.status != http.StatusForbidden || eb.Code != "mfa_required" {
		t.Fatalf("admin without MFA = %d %s, want 403 mfa_required", r.status, r.body)
	}
	var me meResponse
	e.do("GET", "/api/v1/auth/me", session, nil).json(t, &me)
	if me.MFAEnabled || me.MFASession {
		t.Errorf("me before enrolment = %+v", me)
	}

	// Enrolment needs the password again: a stolen cookie cannot bind a phone.
	if r := e.do("POST", "/api/v1/auth/mfa/setup", session, passwordRequest{Password: "wrong password!!"}); r.status != http.StatusForbidden {
		t.Errorf("setup with a wrong password = %d, want 403", r.status)
	}
	if r := e.do("POST", "/api/v1/auth/mfa/confirm", session, codeRequest{Code: "123456"}); r.status != http.StatusConflict {
		t.Errorf("confirm before setup = %d, want 409", r.status)
	}
	r = e.do("POST", "/api/v1/auth/mfa/setup", session, passwordRequest{Password: testPassword})
	var setup mfaSetupResponse
	r.json(t, &setup)
	if r.status != http.StatusOK || !strings.HasPrefix(setup.URI, "otpauth://totp/Orus%20Shield:alice@example.com?") ||
		!strings.Contains(setup.URI, "secret="+setup.Secret) {
		t.Fatalf("setup = %d %+v", r.status, setup)
	}
	if r := e.do("POST", "/api/v1/auth/mfa/confirm", session, codeRequest{Code: "000000"}); r.status != http.StatusBadRequest {
		t.Errorf("confirm with a wrong code = %d, want 400", r.status)
	}
	// Still locked until confirmed.
	if r := e.do("GET", overview, session, nil); r.status != http.StatusForbidden {
		t.Errorf("admin with unconfirmed MFA = %d, want 403", r.status)
	}

	codes := e.enrol("alice@example.com", session)
	if len(codes) != store.RecoveryCodeCount {
		t.Errorf("%d recovery codes", len(codes))
	}
	// The enrolling session is upgraded: no need to sign in again.
	if r := e.do("GET", overview, session, nil); r.status != http.StatusOK {
		t.Errorf("admin after enrolment = %d %s, want 200", r.status, r.body)
	}
	e.do("GET", "/api/v1/auth/me", session, nil).json(t, &me)
	if !me.MFAEnabled || !me.MFASession {
		t.Errorf("me after enrolment = %+v", me)
	}
	if r := e.do("POST", "/api/v1/auth/mfa/setup", session, passwordRequest{Password: testPassword}); r.status != http.StatusConflict {
		t.Errorf("second setup = %d, want 409", r.status)
	}
}

func TestMFALogin(t *testing.T) {
	e := newEnv(t)
	orgID := e.org("Acme")
	e.user("alice@example.com", orgID, store.RoleAdmin)
	codes := e.enrol("alice@example.com", e.login("alice@example.com"))

	mfaToken := e.challenge("alice@example.com")
	if r := e.loginMFA(mfaToken, "000000"); r.status != http.StatusUnauthorized || r.cookie(sessionCookie) != nil {
		t.Errorf("wrong code = %d, want 401 without session", r.status)
	}
	if r := e.loginMFA("forged-token", e.code("alice@example.com")); r.status != http.StatusUnauthorized {
		t.Errorf("forged MFA token = %d, want 401", r.status)
	}
	code := e.code("alice@example.com")
	r := e.loginMFA(mfaToken, code)
	c := r.cookie(sessionCookie)
	if r.status != http.StatusOK || c == nil {
		t.Fatalf("MFA login = %d %s", r.status, r.body)
	}
	if r := e.do("GET", "/api/v1/orgs/"+orgID+"/overview", c.Value, nil); r.status != http.StatusOK {
		t.Errorf("admin with an MFA login = %d, want 200", r.status)
	}
	// The MFA token works once.
	if r := e.loginMFA(mfaToken, code); r.status != http.StatusUnauthorized {
		t.Errorf("MFA token reused = %d, want 401", r.status)
	}
	// An observed code cannot be replayed, even with a fresh password login
	// and within its 30 seconds.
	if r := e.loginMFA(e.challenge("alice@example.com"), code); r.status != http.StatusUnauthorized {
		t.Errorf("replayed code = %d, want 401", r.status)
	}
	e.tick()
	if r := e.loginMFA(e.challenge("alice@example.com"), e.code("alice@example.com")); r.status != http.StatusOK {
		t.Errorf("next step's code = %d %s, want 200", r.status, r.body)
	}

	// A recovery code, as typed from paper, works once.
	typed := strings.ToLower(codes[0])
	if r := e.loginMFA(e.challenge("alice@example.com"), typed); r.status != http.StatusOK {
		t.Errorf("recovery code = %d %s, want 200", r.status, r.body)
	}
	if r := e.loginMFA(e.challenge("alice@example.com"), typed); r.status != http.StatusUnauthorized {
		t.Errorf("recovery code reused = %d, want 401", r.status)
	}
}

// Wrong codes count like wrong passwords: 5 in 15 minutes block the
// account, so the 10^6 codes cannot be tried.
func TestMFACodeGuessingIsRateLimited(t *testing.T) {
	e := newEnv(t)
	e.user("alice@example.com", e.org("Acme"), store.RoleViewer)
	e.enrol("alice@example.com", e.login("alice@example.com"))

	mfaToken := e.challenge("alice@example.com")
	for range maxFailuresPerKey {
		if r := e.loginMFA(mfaToken, "000000"); r.status != http.StatusUnauthorized {
			t.Fatalf("wrong code = %d, want 401", r.status)
		}
	}
	if r := e.loginMFA(mfaToken, e.code("alice@example.com")); r.status != http.StatusTooManyRequests {
		t.Errorf("right code after %d failures = %d, want 429", maxFailuresPerKey, r.status)
	}
	if r := e.do("POST", "/api/v1/auth/login", "", loginRequest{Email: "alice@example.com", Password: testPassword}); r.status != http.StatusTooManyRequests {
		t.Errorf("password login after code failures = %d, want 429", r.status)
	}
}

func TestMFADisable(t *testing.T) {
	e := newEnv(t)
	orgID := e.org("Acme")
	e.user("alice@example.com", orgID, store.RoleAdmin)
	session := e.adminSession("alice@example.com")

	for name, req := range map[string]disableMFARequest{
		"wrong password": {Password: "wrong password!!", Code: e.code("alice@example.com")},
		"wrong code":     {Password: testPassword, Code: "000000"},
		"no code":        {Password: testPassword},
	} {
		if r := e.do("POST", "/api/v1/auth/mfa/disable", session, req); r.status != http.StatusForbidden {
			t.Errorf("%s: disable = %d, want 403", name, r.status)
		}
	}
	r := e.do("POST", "/api/v1/auth/mfa/disable", session, disableMFARequest{Password: testPassword, Code: e.code("alice@example.com")})
	if r.status != http.StatusNoContent {
		t.Fatalf("disable = %d %s", r.status, r.body)
	}
	// Without MFA, the admin is locked out of the organization again.
	if r := e.do("GET", "/api/v1/orgs/"+orgID+"/overview", session, nil); r.status != http.StatusForbidden {
		t.Errorf("admin after disabling MFA = %d, want 403", r.status)
	}
	// And the password alone opens a session again.
	if s := e.login("alice@example.com"); s == "" {
		t.Error("no session after disabling MFA")
	}
	if r := e.do("POST", "/api/v1/auth/mfa/disable", session, disableMFARequest{Password: testPassword, Code: "123456"}); r.status != http.StatusConflict {
		t.Errorf("disable without MFA = %d, want 409", r.status)
	}
}

// Viewers may use MFA but do not need it.
func TestViewersDoNotNeedMFA(t *testing.T) {
	e := newEnv(t)
	orgID := e.org("Acme")
	e.user("victor@example.com", orgID, store.RoleViewer)
	if r := e.do("GET", "/api/v1/orgs/"+orgID+"/overview", e.login("victor@example.com"), nil); r.status != http.StatusOK {
		t.Errorf("viewer without MFA = %d, want 200", r.status)
	}
}
