// Package account holds the authentication flows shared by the JSON API
// (package api) and the web dashboard (package web): login with or without
// a second factor, sessions, password setup, TOTP enrolment, and access to
// an organization.
//
// Every security decision lives here, once: the rate limit on failed
// logins, the identical answer for every bad credential, the password
// re-check before enrolment, the mandatory second factor for admins. The
// two front ends only translate the typed errors below into a JSON status
// or a French message. A rule changed here applies to both.
package account

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/jordyorel/orus-shield/engine/internal/password"
	"github.com/jordyorel/orus-shield/engine/internal/seal"
	"github.com/jordyorel/orus-shield/engine/internal/store"
	"github.com/jordyorel/orus-shield/engine/internal/totp"
)

// SessionCookie is the session cookie's name. The __Host- prefix makes
// browsers refuse it unless it is Secure, has Path=/ and no Domain: a
// subdomain cannot set or overwrite it.
const SessionCookie = "__Host-orus_session"

// Login rate limit: failures (passwords and codes alike) counted over
// LoginWindow.
const (
	LoginWindow       = 15 * time.Minute
	MaxFailuresPerKey = 5  // per email
	MaxFailuresPerIP  = 20 // per client address
)

const (
	// mfaChallengeTTL is how long the user has to type the code after the
	// password.
	mfaChallengeTTL = 5 * time.Minute
	// mfaIssuer is the name authenticator apps show.
	mfaIssuer = "Orus Shield"
)

// Errors returned by the flows. Their messages are the API's English
// answers; the dashboard maps them to its own wording. Anything else is an
// internal error, never shown to the user.
var (
	// ErrBadCredentials is the only answer to a failed password check,
	// whatever the reason (unknown email, no password set, wrong password,
	// disabled account): nobody learns whether an account exists.
	ErrBadCredentials = errors.New("invalid email or password")
	// ErrRateLimited means too many recent failures for the email or the
	// client address; retry after LoginWindow.
	ErrRateLimited = errors.New("too many failed attempts, try again later")
	// ErrBadCode is a wrong, expired or replayed TOTP or recovery code.
	ErrBadCode = errors.New("invalid code")
	// ErrChallengeExpired means the MFA login token is unknown, expired or
	// used: the user signs in again from the password.
	ErrChallengeExpired = errors.New("login expired, sign in again")
	// ErrNoSession means no valid session (missing, expired or revoked).
	ErrNoSession = errors.New("not logged in")
	// ErrInvalidSetupToken is an unknown, expired or used setup token.
	ErrInvalidSetupToken = errors.New("invalid or expired setup token")
	// ErrMFAEnabled: the action needs MFA to be off (enrolment).
	ErrMFAEnabled = errors.New("two-factor authentication is already enabled")
	// ErrMFANotEnabled: the action needs MFA to be on (disable).
	ErrMFANotEnabled = errors.New("two-factor authentication is not enabled")
	// ErrNoMFASetup: confirm called before setup.
	ErrNoMFASetup = errors.New("start two-factor setup first")
	// ErrNotMember: the organization does not exist or the user is not a
	// member. Callers answer 404, as if it did not exist.
	ErrNotMember = errors.New("not found")
	// ErrMFARequired: an admin whose session has no second factor.
	ErrMFARequired = errors.New("two-factor authentication is required for administrators: enable it first")
	// ErrNeedAdmin: a viewer attempting an admin action.
	ErrNeedAdmin = errors.New("this action needs the admin role")
)

// Config tunes the service. Zero durations and a nil clock get defaults.
type Config struct {
	// SessionIdle closes a session unused for this long.
	SessionIdle time.Duration
	// SessionMax closes a session this long after login, used or not.
	SessionMax time.Duration
	// Now is the clock; tests replace it.
	Now func() time.Time
	// MFAKey encrypts TOTP secrets in the database (seal.KeyLen bytes,
	// from ORUS_MFA_KEY). Required.
	MFAKey []byte
}

const (
	defaultSessionIdle = 12 * time.Hour
	defaultSessionMax  = 7 * 24 * time.Hour
)

// Service runs the flows on the authentication handle of the store. It
// never sees organization data: access checks only read memberships.
type Service struct {
	auth *store.Auth
	key  *seal.Key
	cfg  Config
}

// New returns the service.
func New(auth *store.Auth, cfg Config) (*Service, error) {
	if cfg.SessionIdle <= 0 {
		cfg.SessionIdle = defaultSessionIdle
	}
	if cfg.SessionMax <= 0 {
		cfg.SessionMax = defaultSessionMax
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	key, err := seal.NewKey(cfg.MFAKey)
	if err != nil {
		return nil, fmt.Errorf("account: MFA key: %w", err)
	}
	return &Service{auth: auth, key: key, cfg: cfg}, nil
}

// Client identifies the caller, for the auth log and the rate limit.
type Client struct {
	IP        string
	UserAgent string
}

// ClientFrom reads the client of an HTTP request. The address is the TCP
// peer's: headers such as X-Forwarded-For are ignored, because anyone can
// set them. Behind a reverse proxy, the proxy must be configured to pass
// the real address (to add when we deploy one).
func ClientFrom(r *http.Request) Client {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	return Client{IP: host, UserAgent: r.UserAgent()}
}

// NewSession is a session just opened: the token goes into the cookie.
type NewSession struct {
	Token   string
	Expires time.Time
	Session store.Session
}

// LoginResult is the outcome of a correct password: either a session, or,
// for a user with MFA, a challenge token to exchange with a code in
// LoginMFA.
type LoginResult struct {
	Session  *NewSession
	MFAToken string
}

// Login checks an email and password under the login rate limit.
func (s *Service) Login(ctx context.Context, email, pw string, c Client) (LoginResult, error) {
	u, err := s.authenticate(ctx, email, pw, c)
	if err != nil {
		return LoginResult{}, err
	}
	if u.MFAEnabled {
		// The password is right, but no session yet: the client sends the
		// code with this token.
		challenge, err := s.auth.CreateMFAChallenge(ctx, u.ID, c.IP, s.cfg.Now().Add(mfaChallengeTTL))
		if err != nil {
			return LoginResult{}, err
		}
		if err := s.auth.Log(ctx, store.AuthEvent{UserID: u.ID, Email: u.Email, Action: store.AuthMFAChallenge, IP: c.IP}); err != nil {
			return LoginResult{}, err
		}
		return LoginResult{MFAToken: challenge}, nil
	}

	// A new token on every login: a token known before login (session
	// fixation) is worthless.
	expires := s.cfg.Now().Add(s.cfg.SessionMax)
	token, err := s.auth.CreateSession(ctx, u.ID, c.IP, c.UserAgent, expires)
	if err != nil {
		return LoginResult{}, err
	}
	if err := s.auth.Log(ctx, store.AuthEvent{UserID: u.ID, Email: u.Email, Action: store.AuthLoginOK, IP: c.IP}); err != nil {
		return LoginResult{}, err
	}
	return LoginResult{Session: &NewSession{
		Token: token, Expires: expires,
		Session: store.Session{UserID: u.ID, Email: u.Email, ExpiresAt: expires},
	}}, nil
}

// LoginMFA exchanges an MFA challenge token and a code (TOTP or recovery)
// for a session.
func (s *Service) LoginMFA(ctx context.Context, mfaToken, code string, c Client) (NewSession, error) {
	u, err := s.auth.MFAChallengeUser(ctx, mfaToken)
	if errors.Is(err, store.ErrInvalidToken) {
		return NewSession{}, ErrChallengeExpired
	}
	if err != nil {
		return NewSession{}, err
	}
	if err := s.underLoginLimit(ctx, u.Email, c); err != nil {
		return NewSession{}, err
	}
	method, ok, err := s.checkSecondFactor(ctx, u.ID, code)
	if err != nil {
		return NewSession{}, err
	}
	if !ok {
		return NewSession{}, s.loginFailed(ctx, u, "wrong mfa code", c, ErrBadCode)
	}
	expires := s.cfg.Now().Add(s.cfg.SessionMax)
	token, err := s.auth.CompleteMFALogin(ctx, mfaToken, u.ID, c.IP, c.UserAgent, expires)
	if errors.Is(err, store.ErrInvalidToken) { // expired or used meanwhile
		return NewSession{}, ErrChallengeExpired
	}
	if err != nil {
		return NewSession{}, err
	}
	if err := s.auth.Log(ctx, store.AuthEvent{UserID: u.ID, Email: u.Email, Action: store.AuthLoginOK, IP: c.IP,
		Details: map[string]any{"mfa": method}}); err != nil {
		return NewSession{}, err
	}
	return NewSession{Token: token, Expires: expires, Session: store.Session{
		UserID: u.ID, Email: u.Email, ExpiresAt: expires, MFA: true, MFAEnabled: true,
	}}, nil
}

// Session returns the session of a cookie value, or ErrNoSession.
func (s *Service) Session(ctx context.Context, token string) (store.Session, error) {
	if token == "" {
		return store.Session{}, ErrNoSession
	}
	sess, err := s.auth.SessionUser(ctx, token, s.cfg.SessionIdle)
	if errors.Is(err, store.ErrInvalidToken) {
		return store.Session{}, ErrNoSession
	}
	return sess, err
}

// SessionFrom reads the session cookie of r.
func (s *Service) SessionFrom(r *http.Request) (sess store.Session, token string, err error) {
	ck, err := r.Cookie(SessionCookie)
	if err != nil {
		return store.Session{}, "", ErrNoSession
	}
	sess, err = s.Session(r.Context(), ck.Value)
	return sess, ck.Value, err
}

// Logout closes the session.
func (s *Service) Logout(ctx context.Context, sess store.Session, token string, c Client) error {
	if err := s.auth.DeleteSession(ctx, token); err != nil {
		return err
	}
	return s.auth.Log(ctx, store.AuthEvent{UserID: sess.UserID, Email: sess.Email, Action: store.AuthLogout, IP: c.IP})
}

// Memberships lists the user's organizations and roles.
func (s *Service) Memberships(ctx context.Context, userID string) ([]store.Membership, error) {
	return s.auth.Memberships(ctx, userID)
}

// SetupPassword sets a password with a one-time token from orusctl (first
// setup or reset). It closes every session of the user. A password that
// breaks the policy returns the password package's error (ErrTooShort,
// ErrTooLong).
func (s *Service) SetupPassword(ctx context.Context, token, pw string, c Client) error {
	if err := password.Check(pw); err != nil {
		return err
	}
	hash, err := password.Hash(pw)
	if err != nil {
		return err
	}
	_, err = s.auth.SetPasswordWithToken(ctx, token, hash, c.IP)
	if errors.Is(err, store.ErrInvalidToken) {
		return ErrInvalidSetupToken
	}
	return err
}

// Access returns the user's role in orgID, if it allows minRole. A
// non-member gets ErrNotMember. An admin whose session was not opened with
// a second factor gets ErrMFARequired on every route of the organization,
// reads included: MFA is mandatory for admins, and a stolen admin password
// alone must not reach their data.
func (s *Service) Access(ctx context.Context, sess store.Session, orgID, minRole string) (string, error) {
	role, err := s.auth.Role(ctx, sess.UserID, orgID)
	if errors.Is(err, store.ErrNotFound) {
		return "", ErrNotMember
	}
	if err != nil {
		return "", err
	}
	if role == store.RoleAdmin && !sess.MFA {
		return "", ErrMFARequired
	}
	if minRole == store.RoleAdmin && role != store.RoleAdmin {
		return "", ErrNeedAdmin
	}
	return role, nil
}

// authenticate checks an email and password under the login rate limit,
// for a login or to confirm a sensitive action.
func (s *Service) authenticate(ctx context.Context, rawEmail, pw string, c Client) (store.User, error) {
	email, err := store.NormalizeEmail(rawEmail)
	if err != nil {
		return store.User{}, ErrBadCredentials
	}
	if err := s.underLoginLimit(ctx, email, c); err != nil {
		return store.User{}, err
	}
	u, err := s.auth.UserByEmail(ctx, email)
	switch {
	case errors.Is(err, store.ErrNotFound):
		password.VerifyDummy(pw) // same time as a real check
		return store.User{}, s.loginFailed(ctx, store.User{Email: email}, "unknown email", c, ErrBadCredentials)
	case err != nil:
		return store.User{}, err
	}
	if u.PasswordHash == "" || u.DisabledAt != nil {
		password.VerifyDummy(pw)
		return store.User{}, s.loginFailed(ctx, u, "no password or disabled", c, ErrBadCredentials)
	}
	ok, err := password.Verify(pw, u.PasswordHash)
	if err != nil {
		return store.User{}, err
	}
	if !ok {
		return store.User{}, s.loginFailed(ctx, u, "wrong password", c, ErrBadCredentials)
	}
	return u, nil
}

// underLoginLimit returns ErrRateLimited when email or the client address
// had too many recent failures (passwords and codes alike).
func (s *Service) underLoginLimit(ctx context.Context, email string, c Client) error {
	byEmail, byIP, err := s.auth.RecentFailures(ctx, email, c.IP, s.cfg.Now().Add(-LoginWindow))
	if err != nil {
		return err
	}
	if byEmail >= MaxFailuresPerKey || byIP >= MaxFailuresPerIP {
		return ErrRateLimited
	}
	return nil
}

// loginFailed records the failure (with its real reason, for the auth log
// only) and returns answer. Every failure counts toward the login rate
// limit.
func (s *Service) loginFailed(ctx context.Context, u store.User, reason string, c Client, answer error) error {
	if err := s.auth.Log(ctx, store.AuthEvent{
		UserID: u.ID, Email: u.Email, Action: store.AuthLoginFailed, IP: c.IP,
		Details: map[string]any{"reason": reason},
	}); err != nil {
		return err
	}
	return answer
}

// checkSecondFactor checks a TOTP code (6 characters) or a recovery code
// (anything else) for an enrolled user, and consumes it. method says which
// one was used.
func (s *Service) checkSecondFactor(ctx context.Context, userID, code string) (method string, ok bool, err error) {
	code = strings.TrimSpace(code)
	if len(code) != totp.Digits {
		ok, err := s.auth.UseRecoveryCode(ctx, userID, code)
		return "recovery_code", ok, err
	}
	m, err := s.auth.MFA(ctx, userID)
	if errors.Is(err, store.ErrNotFound) {
		return "totp", false, nil
	}
	if err != nil {
		return "", false, err
	}
	if !m.Enabled {
		return "totp", false, nil
	}
	secret, err := s.key.Open(m.Sealed, userID)
	if err != nil {
		// Not the user's fault: the key changed or the row was tampered with.
		return "", false, fmt.Errorf("open totp secret of %s: %w", userID, err)
	}
	step, ok := totp.Verify(secret, code, s.cfg.Now(), m.LastStep)
	if !ok {
		return "totp", false, nil
	}
	// The store accepts each step once: a replayed code, or two requests
	// racing with the same code, lose here.
	ok, err = s.auth.UseTOTPStep(ctx, userID, step)
	return "totp", ok, err
}
