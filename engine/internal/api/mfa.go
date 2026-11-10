package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/jordyorel/orus-shield/engine/internal/store"
	"github.com/jordyorel/orus-shield/engine/internal/totp"
)

// Two-factor authentication
//
// Enrolment: POST /auth/mfa/setup (with the password) returns a new secret,
// POST /auth/mfa/confirm (with a first code) enables it and returns the
// recovery codes. Login with MFA: POST /auth/login answers with an
// mfa_token instead of a session, POST /auth/login/mfa exchanges it and a
// code for the session.
//
// Wrong codes count as failed logins: the same limit (5 per account in 15
// minutes) bounds guessing, so a 6-digit code cannot be brute-forced.

const (
	// mfaChallengeTTL is how long the user has to type the code after the
	// password.
	mfaChallengeTTL = 5 * time.Minute
	// mfaIssuer is the name authenticator apps show.
	mfaIssuer  = "Orus Shield"
	msgBadCode = "invalid code"
)

type mfaChallengeResponse struct {
	MFARequired bool   `json:"mfa_required"`
	MFAToken    string `json:"mfa_token"`
}

type loginMFARequest struct {
	MFAToken string `json:"mfa_token"`
	// Code is the 6-digit TOTP code or a recovery code.
	Code string `json:"code"`
}

func (s *Server) loginMFA(w http.ResponseWriter, r *http.Request) {
	var req loginMFARequest
	if !decode(w, r, &req) {
		return
	}
	ctx := r.Context()
	u, err := s.auth.MFAChallengeUser(ctx, req.MFAToken)
	if errors.Is(err, store.ErrInvalidToken) {
		writeError(w, http.StatusUnauthorized, "login expired, sign in again")
		return
	}
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if !s.underLoginLimit(w, r, u.Email) {
		return
	}
	method, ok, err := s.checkSecondFactor(ctx, u.ID, req.Code)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if !ok {
		s.loginFailed(w, r, u, "wrong mfa code", http.StatusUnauthorized, msgBadCode)
		return
	}
	expires := s.cfg.Now().Add(s.cfg.SessionMax)
	token, err := s.auth.CompleteMFALogin(ctx, req.MFAToken, u.ID, clientIP(r), r.UserAgent(), expires)
	if errors.Is(err, store.ErrInvalidToken) { // expired or used meanwhile
		writeError(w, http.StatusUnauthorized, "login expired, sign in again")
		return
	}
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if err := s.auth.Log(ctx, store.AuthEvent{UserID: u.ID, Email: u.Email, Action: store.AuthLoginOK, IP: clientIP(r),
		Details: map[string]any{"mfa": method}}); err != nil {
		s.internalError(w, r, err)
		return
	}
	setSessionCookie(w, token, expires)
	s.writeMe(w, r, store.Session{UserID: u.ID, Email: u.Email, MFA: true, MFAEnabled: true})
}

// checkSecondFactor checks a TOTP code (6 characters) or a recovery code
// (anything else) for an enrolled user, and consumes it. method says which
// one was used.
func (s *Server) checkSecondFactor(ctx context.Context, userID, code string) (method string, ok bool, err error) {
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
	secret, err := s.mfaKey.Open(m.Sealed, userID)
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

type passwordRequest struct {
	Password string `json:"password"`
}

type mfaSetupResponse struct {
	// Secret is for typing into the app; URI is for a QR code.
	Secret string `json:"secret"`
	URI    string `json:"otpauth_uri"`
}

// mfaSetup starts enrolment. It asks for the password again: whoever holds
// a stolen session cookie must not be able to bind their own phone to the
// account.
func (s *Server) mfaSetup(w http.ResponseWriter, r *http.Request, sess store.Session, _ string) {
	var req passwordRequest
	if !decode(w, r, &req) {
		return
	}
	if sess.MFAEnabled {
		writeError(w, http.StatusConflict, "two-factor authentication is already enabled")
		return
	}
	if _, ok := s.authenticate(w, r, sess.Email, req.Password, http.StatusForbidden); !ok {
		return
	}
	secret, err := totp.NewSecret()
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	sealed, err := s.mfaKey.Seal(secret, sess.UserID)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	err = s.auth.BeginMFASetup(r.Context(), sess.UserID, sealed)
	if errors.Is(err, store.ErrExists) {
		writeError(w, http.StatusConflict, "two-factor authentication is already enabled")
		return
	}
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, mfaSetupResponse{Secret: totp.Encode(secret), URI: totp.URI(secret, mfaIssuer, sess.Email)})
}

type codeRequest struct {
	Code string `json:"code"`
}

type recoveryCodesResponse struct {
	// RecoveryCodes are shown once: only their hashes are kept.
	RecoveryCodes []string `json:"recovery_codes"`
}

// mfaConfirm enables the factor started by mfaSetup once the user typed a
// valid code: proof that their app has the secret. The current session
// becomes an MFA session; every other session is closed.
func (s *Server) mfaConfirm(w http.ResponseWriter, r *http.Request, sess store.Session, token string) {
	var req codeRequest
	if !decode(w, r, &req) {
		return
	}
	ctx := r.Context()
	m, err := s.auth.MFA(ctx, sess.UserID)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusConflict, "start two-factor setup first")
		return
	}
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if m.Enabled {
		writeError(w, http.StatusConflict, "two-factor authentication is already enabled")
		return
	}
	secret, err := s.mfaKey.Open(m.Sealed, sess.UserID)
	if err != nil {
		s.internalError(w, r, fmt.Errorf("open totp secret of %s: %w", sess.UserID, err))
		return
	}
	step, ok := totp.Verify(secret, strings.TrimSpace(req.Code), s.cfg.Now(), m.LastStep)
	if !ok {
		writeError(w, http.StatusBadRequest, msgBadCode)
		return
	}
	codes, err := s.auth.EnableMFA(ctx, sess.UserID, step, token, clientIP(r))
	if errors.Is(err, store.ErrNotFound) { // confirmed meanwhile by another request
		writeError(w, http.StatusConflict, "two-factor authentication is already enabled")
		return
	}
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, recoveryCodesResponse{RecoveryCodes: codes})
}

type disableMFARequest struct {
	Password string `json:"password"`
	Code     string `json:"code"`
}

// mfaDisable removes the second factor. It needs both the password and a
// code: a stolen session alone cannot weaken the account. An admin who
// disables MFA loses access to their organizations until they enrol again.
func (s *Server) mfaDisable(w http.ResponseWriter, r *http.Request, sess store.Session, token string) {
	var req disableMFARequest
	if !decode(w, r, &req) {
		return
	}
	if !sess.MFAEnabled {
		writeError(w, http.StatusConflict, "two-factor authentication is not enabled")
		return
	}
	u, ok := s.authenticate(w, r, sess.Email, req.Password, http.StatusForbidden)
	if !ok {
		return
	}
	_, ok, err := s.checkSecondFactor(r.Context(), u.ID, req.Code)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if !ok {
		s.loginFailed(w, r, u, "wrong mfa code", http.StatusForbidden, msgBadCode)
		return
	}
	if err := s.auth.DisableMFA(r.Context(), u.ID, token, clientIP(r)); err != nil {
		s.internalError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
