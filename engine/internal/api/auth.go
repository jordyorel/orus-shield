package api

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/jordyorel/orus-shield/engine/internal/account"
	"github.com/jordyorel/orus-shield/engine/internal/password"
	"github.com/jordyorel/orus-shield/engine/internal/store"
)

// sessionCookie is the session cookie's name, shared with the dashboard.
const sessionCookie = account.SessionCookie

// Aliases kept for the tests, which exercise the limit through the API.
const (
	loginWindow       = account.LoginWindow
	maxFailuresPerKey = account.MaxFailuresPerKey
)

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

// accountError answers an error of package account. badCredentials is the
// status of a wrong password: 401 at login, 403 when confirming a
// sensitive action with an open session. Unknown errors are internal.
func (s *Server) accountError(w http.ResponseWriter, r *http.Request, err error, badCredentials int) {
	switch {
	case errors.Is(err, account.ErrBadCredentials):
		writeError(w, badCredentials, err.Error())
	case errors.Is(err, account.ErrRateLimited):
		w.Header().Set("Retry-After", strconv.Itoa(int(account.LoginWindow.Seconds())))
		writeError(w, http.StatusTooManyRequests, err.Error())
	case errors.Is(err, account.ErrBadCode):
		writeError(w, badCredentials, err.Error())
	case errors.Is(err, account.ErrChallengeExpired):
		// Same status as a wrong code; the code tells the dashboard to go
		// back to the password instead of asking for the code again.
		writeErrorCode(w, http.StatusUnauthorized, "login_expired", err.Error())
	case errors.Is(err, account.ErrNoSession):
		writeError(w, http.StatusUnauthorized, err.Error())
	case errors.Is(err, account.ErrInvalidSetupToken),
		errors.Is(err, password.ErrTooShort), errors.Is(err, password.ErrTooLong):
		writeError(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, account.ErrMFAEnabled), errors.Is(err, account.ErrMFANotEnabled),
		errors.Is(err, account.ErrNoMFASetup):
		writeError(w, http.StatusConflict, err.Error())
	case errors.Is(err, account.ErrNotMember):
		writeError(w, http.StatusNotFound, "not found")
	case errors.Is(err, account.ErrMFARequired):
		writeErrorCode(w, http.StatusForbidden, "mfa_required", err.Error())
	case errors.Is(err, account.ErrNeedAdmin):
		writeError(w, http.StatusForbidden, err.Error())
	default:
		s.internalError(w, r, err)
	}
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if !decode(w, r, &req) {
		return
	}
	res, err := s.acct.Login(r.Context(), req.Email, req.Password, account.ClientFrom(r))
	if err != nil {
		s.accountError(w, r, err, http.StatusUnauthorized)
		return
	}
	if res.MFAToken != "" {
		// The client sends the code with this token to POST /auth/login/mfa.
		writeJSON(w, http.StatusOK, mfaChallengeResponse{MFARequired: true, MFAToken: res.MFAToken})
		return
	}
	account.SetSessionCookie(w, res.Session.Token, res.Session.Expires)
	s.writeMe(w, r, res.Session.Session)
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request, sess store.Session, token string) {
	if err := s.acct.Logout(r.Context(), sess, token, account.ClientFrom(r)); err != nil {
		s.internalError(w, r, err)
		return
	}
	account.ClearSessionCookie(w)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) me(w http.ResponseWriter, r *http.Request, sess store.Session, _ string) {
	s.writeMe(w, r, sess)
}

func (s *Server) writeMe(w http.ResponseWriter, r *http.Request, sess store.Session) {
	ms, err := s.acct.Memberships(r.Context(), sess.UserID)
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
	if err := s.acct.SetupPassword(r.Context(), req.Token, req.Password, account.ClientFrom(r)); err != nil {
		s.accountError(w, r, err, http.StatusBadRequest)
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
		sess, token, err := s.acct.SessionFrom(r)
		if err != nil {
			s.accountError(w, r, err, http.StatusUnauthorized)
			return
		}
		h(w, r, sess, token)
	}
}
