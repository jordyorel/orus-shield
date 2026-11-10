package api

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/jordyorel/orus-shield/engine/internal/password"
	"github.com/jordyorel/orus-shield/engine/internal/store"
)

// sessionCookie is the session cookie's name. The __Host- prefix makes
// browsers refuse it unless it is Secure, has Path=/ and no Domain: a
// subdomain cannot set or overwrite it.
const sessionCookie = "__Host-orus_session"

// Login rate limit: failures counted over loginWindow.
const (
	loginWindow       = 15 * time.Minute
	maxFailuresPerKey = 5  // per email
	maxFailuresPerIP  = 20 // per client address
)

// msgBadCredentials is the only answer to a failed login, whatever the
// reason (unknown email, no password set, wrong password, disabled
// account): the API never tells whether an account exists.
const msgBadCredentials = "invalid email or password"

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type membershipJSON struct {
	OrgID   string `json:"org_id"`
	OrgName string `json:"org_name"`
	Role    string `json:"role"`
}

type meResponse struct {
	UserID string `json:"user_id"`
	Email  string `json:"email"`
	// MFAEnabled: the user has a second factor. MFASession: this session
	// was opened with it. Admins need MFASession for their organizations.
	MFAEnabled bool             `json:"mfa_enabled"`
	MFASession bool             `json:"mfa_session"`
	Orgs       []membershipJSON `json:"orgs"`
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if !decode(w, r, &req) {
		return
	}
	u, ok := s.authenticate(w, r, req.Email, req.Password, http.StatusUnauthorized)
	if !ok {
		return
	}
	ctx := r.Context()
	if u.MFAEnabled {
		// The password is right, but no session yet: the client sends the
		// code with this token to POST /auth/login/mfa.
		challenge, err := s.auth.CreateMFAChallenge(ctx, u.ID, clientIP(r), s.cfg.Now().Add(mfaChallengeTTL))
		if err != nil {
			s.internalError(w, r, err)
			return
		}
		if err := s.auth.Log(ctx, store.AuthEvent{UserID: u.ID, Email: u.Email, Action: store.AuthMFAChallenge, IP: clientIP(r)}); err != nil {
			s.internalError(w, r, err)
			return
		}
		writeJSON(w, http.StatusOK, mfaChallengeResponse{MFARequired: true, MFAToken: challenge})
		return
	}

	// A new token on every login: a token known before login (session
	// fixation) is worthless.
	expires := s.cfg.Now().Add(s.cfg.SessionMax)
	token, err := s.auth.CreateSession(ctx, u.ID, clientIP(r), r.UserAgent(), expires)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if err := s.auth.Log(ctx, store.AuthEvent{UserID: u.ID, Email: u.Email, Action: store.AuthLoginOK, IP: clientIP(r)}); err != nil {
		s.internalError(w, r, err)
		return
	}
	setSessionCookie(w, token, expires)
	s.writeMe(w, r, store.Session{UserID: u.ID, Email: u.Email})
}

// authenticate checks an email and password under the login rate limit,
// for a login or to confirm a sensitive action. On failure it has answered
// (failStatus with the generic message, or 429) and returns false.
func (s *Server) authenticate(w http.ResponseWriter, r *http.Request, rawEmail, pw string, failStatus int) (store.User, bool) {
	ctx := r.Context()
	email, err := store.NormalizeEmail(rawEmail)
	if err != nil {
		writeError(w, failStatus, msgBadCredentials)
		return store.User{}, false
	}
	if !s.underLoginLimit(w, r, email) {
		return store.User{}, false
	}
	u, err := s.auth.UserByEmail(ctx, email)
	switch {
	case errors.Is(err, store.ErrNotFound):
		password.VerifyDummy(pw) // same time as a real check
		s.loginFailed(w, r, store.User{Email: email}, "unknown email", failStatus, msgBadCredentials)
		return store.User{}, false
	case err != nil:
		s.internalError(w, r, err)
		return store.User{}, false
	}
	if u.PasswordHash == "" || u.DisabledAt != nil {
		password.VerifyDummy(pw)
		s.loginFailed(w, r, u, "no password or disabled", failStatus, msgBadCredentials)
		return store.User{}, false
	}
	ok, err := password.Verify(pw, u.PasswordHash)
	if err != nil {
		s.internalError(w, r, err)
		return store.User{}, false
	}
	if !ok {
		s.loginFailed(w, r, u, "wrong password", failStatus, msgBadCredentials)
		return store.User{}, false
	}
	return u, true
}

// underLoginLimit answers 429 and returns false when email or the client
// address had too many recent failures (passwords and codes alike).
func (s *Server) underLoginLimit(w http.ResponseWriter, r *http.Request, email string) bool {
	byEmail, byIP, err := s.auth.RecentFailures(r.Context(), email, clientIP(r), s.cfg.Now().Add(-loginWindow))
	if err != nil {
		s.internalError(w, r, err)
		return false
	}
	if byEmail >= maxFailuresPerKey || byIP >= maxFailuresPerIP {
		w.Header().Set("Retry-After", strconv.Itoa(int(loginWindow.Seconds())))
		writeError(w, http.StatusTooManyRequests, "too many failed attempts, try again later")
		return false
	}
	return true
}

// loginFailed records the failure (with its real reason, for the auth log
// only) and answers status with msg. Every failure counts toward the login
// rate limit.
func (s *Server) loginFailed(w http.ResponseWriter, r *http.Request, u store.User, reason string, status int, msg string) {
	if err := s.auth.Log(r.Context(), store.AuthEvent{
		UserID: u.ID, Email: u.Email, Action: store.AuthLoginFailed, IP: clientIP(r),
		Details: map[string]any{"reason": reason},
	}); err != nil {
		s.internalError(w, r, err)
		return
	}
	writeError(w, status, msg)
}

func setSessionCookie(w http.ResponseWriter, token string, expires time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: token, Path: "/", Expires: expires,
		Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode,
	})
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request, sess store.Session, token string) {
	if err := s.auth.DeleteSession(r.Context(), token); err != nil {
		s.internalError(w, r, err)
		return
	}
	if err := s.auth.Log(r.Context(), store.AuthEvent{UserID: sess.UserID, Email: sess.Email, Action: store.AuthLogout, IP: clientIP(r)}); err != nil {
		s.internalError(w, r, err)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: "", Path: "/", MaxAge: -1,
		Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode,
	})
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) me(w http.ResponseWriter, r *http.Request, sess store.Session, _ string) {
	s.writeMe(w, r, sess)
}

func (s *Server) writeMe(w http.ResponseWriter, r *http.Request, sess store.Session) {
	ms, err := s.auth.Memberships(r.Context(), sess.UserID)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	resp := meResponse{UserID: sess.UserID, Email: sess.Email, MFAEnabled: sess.MFAEnabled, MFASession: sess.MFA, Orgs: []membershipJSON{}}
	for _, m := range ms {
		resp.Orgs = append(resp.Orgs, membershipJSON{OrgID: m.OrgID, OrgName: m.OrgName, Role: m.Role})
	}
	writeJSON(w, http.StatusOK, resp)
}

type setupPasswordRequest struct {
	Token    string `json:"token"`
	Password string `json:"password"`
}

// setupPassword sets a password with a one-time token from orusctl (first
// setup or reset). It closes every session of the user.
func (s *Server) setupPassword(w http.ResponseWriter, r *http.Request) {
	var req setupPasswordRequest
	if !decode(w, r, &req) {
		return
	}
	if err := password.Check(req.Password); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	hash, err := password.Hash(req.Password)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	_, err = s.auth.SetPasswordWithToken(r.Context(), req.Token, hash, clientIP(r))
	if errors.Is(err, store.ErrInvalidToken) {
		writeError(w, http.StatusBadRequest, "invalid or expired setup token")
		return
	}
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// sessionHandler is a handler that runs only with a valid session.
type sessionHandler func(w http.ResponseWriter, r *http.Request, sess store.Session, token string)

// withSession checks the session cookie. Without a valid session the
// answer is 401, whatever the reason (missing, expired, revoked).
func (s *Server) withSession(h sessionHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(sessionCookie)
		if err != nil || c.Value == "" {
			writeError(w, http.StatusUnauthorized, "not logged in")
			return
		}
		sess, err := s.auth.SessionUser(r.Context(), c.Value, s.cfg.SessionIdle)
		if errors.Is(err, store.ErrInvalidToken) {
			writeError(w, http.StatusUnauthorized, "not logged in")
			return
		}
		if err != nil {
			s.internalError(w, r, err)
			return
		}
		h(w, r, sess, c.Value)
	}
}
