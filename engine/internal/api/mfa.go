package api

import (
	"net/http"

	"github.com/jordyorel/orus-shield/engine/internal/account"
	"github.com/jordyorel/orus-shield/engine/internal/store"
)

// Two-factor authentication
//
// Enrolment: POST /auth/mfa/setup (with the password) returns a new secret,
// POST /auth/mfa/confirm (with a first code) enables it and returns the
// recovery codes. Login with MFA: POST /auth/login answers with an
// mfa_token instead of a session, POST /auth/login/mfa exchanges it and a
// code for the session. The rules themselves are in package account.

type mfaChallengeResponse struct {
	MFARequired bool   `json:"mfa_required"`
	MFAToken    string `json:"mfa_token"`
}

type loginMFARequest struct {
	MFAToken string `json:"mfa_token"`
	// Code is a 6-digit TOTP code or a recovery code.
	Code string `json:"code"`
}

func (s *Server) loginMFA(w http.ResponseWriter, r *http.Request) {
	var req loginMFARequest
	if !decode(w, r, &req) {
		return
	}
	ns, err := s.acct.LoginMFA(r.Context(), req.MFAToken, req.Code, account.ClientFrom(r))
	if err != nil {
		s.accountError(w, r, err, http.StatusUnauthorized)
		return
	}
	account.SetSessionCookie(w, ns.Token, ns.Expires)
	s.writeMe(w, r, ns.Session)
}

type passwordRequest struct {
	Password string `json:"password"`
}

type mfaSetupResponse struct {
	// Secret is for typing into the app; URI is for a QR code.
	Secret string `json:"secret"`
	URI    string `json:"otpauth_uri"`
}

func (s *Server) mfaSetup(w http.ResponseWriter, r *http.Request, sess store.Session, _ string) {
	var req passwordRequest
	if !decode(w, r, &req) {
		return
	}
	en, err := s.acct.BeginMFA(r.Context(), sess, req.Password, account.ClientFrom(r))
	if err != nil {
		s.accountError(w, r, err, http.StatusForbidden)
		return
	}
	writeJSON(w, http.StatusOK, mfaSetupResponse{Secret: en.Secret, URI: en.URI})
}

type codeRequest struct {
	Code string `json:"code"`
}

type recoveryCodesResponse struct {
	// RecoveryCodes are shown once: only their hashes are kept.
	RecoveryCodes []string `json:"recovery_codes"`
}

func (s *Server) mfaConfirm(w http.ResponseWriter, r *http.Request, sess store.Session, token string) {
	var req codeRequest
	if !decode(w, r, &req) {
		return
	}
	codes, err := s.acct.ConfirmMFA(r.Context(), sess, token, req.Code, account.ClientFrom(r))
	if err != nil {
		// A wrong first code is a bad request, not a failed login: the
		// session is already authenticated.
		s.accountError(w, r, err, http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusOK, recoveryCodesResponse{RecoveryCodes: codes})
}

type disableMFARequest struct {
	Password string `json:"password"`
	Code     string `json:"code"`
}

func (s *Server) mfaDisable(w http.ResponseWriter, r *http.Request, sess store.Session, token string) {
	var req disableMFARequest
	if !decode(w, r, &req) {
		return
	}
	if err := s.acct.DisableMFA(r.Context(), sess, token, req.Password, req.Code, account.ClientFrom(r)); err != nil {
		s.accountError(w, r, err, http.StatusForbidden)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
