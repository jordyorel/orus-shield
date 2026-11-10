package account

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
// Enrolment has two steps: BeginMFA (with the password) creates a new
// secret, ConfirmMFA (with a first code) enables it and returns the
// recovery codes. Wrong codes count as failed logins: the same limit (5 per
// account in 15 minutes) bounds guessing, so a 6-digit code cannot be
// brute-forced.

// Enrolment is a secret waiting for its first code.
type Enrolment struct {
	// Secret is for typing into the authenticator app (base32).
	Secret string
	// URI is the otpauth:// link, for a QR code or a tap on a phone.
	URI string
}

// BeginMFA starts enrolment. It asks for the password again: whoever holds
// a stolen session cookie must not be able to bind their own phone to the
// account. A wrong password is ErrBadCredentials.
func (s *Service) BeginMFA(ctx context.Context, sess store.Session, pw string, c Client) (Enrolment, error) {
	if sess.MFAEnabled {
		return Enrolment{}, ErrMFAEnabled
	}
	if _, err := s.authenticate(ctx, sess.Email, pw, c); err != nil {
		return Enrolment{}, err
	}
	secret, err := totp.NewSecret()
	if err != nil {
		return Enrolment{}, err
	}
	sealed, err := s.key.Seal(secret, sess.UserID)
	if err != nil {
		return Enrolment{}, err
	}
	err = s.auth.BeginMFASetup(ctx, sess.UserID, sealed)
	if errors.Is(err, store.ErrExists) {
		return Enrolment{}, ErrMFAEnabled
	}
	if err != nil {
		return Enrolment{}, err
	}
	return Enrolment{Secret: totp.Encode(secret), URI: totp.URI(secret, mfaIssuer, sess.Email)}, nil
}

// ConfirmMFA enables the factor started by BeginMFA once the user typed a
// valid code: proof that their app has the secret. The session of token
// becomes an MFA session; every other session is closed. The recovery
// codes are returned once: only their hashes are kept.
func (s *Service) ConfirmMFA(ctx context.Context, sess store.Session, token, code string, c Client) ([]string, error) {
	m, err := s.auth.MFA(ctx, sess.UserID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, ErrNoMFASetup
	}
	if err != nil {
		return nil, err
	}
	if m.Enabled {
		return nil, ErrMFAEnabled
	}
	secret, err := s.key.Open(m.Sealed, sess.UserID)
	if err != nil {
		return nil, fmt.Errorf("open totp secret of %s: %w", sess.UserID, err)
	}
	step, ok := totp.Verify(secret, strings.TrimSpace(code), s.cfg.Now(), m.LastStep)
	if !ok {
		return nil, ErrBadCode
	}
	codes, err := s.auth.EnableMFA(ctx, sess.UserID, step, token, c.IP)
	if errors.Is(err, store.ErrNotFound) { // confirmed meanwhile by another request
		return nil, ErrMFAEnabled
	}
	return codes, err
}

// DisableMFA removes the second factor. It needs both the password and a
// code: a stolen session alone cannot weaken the account. A wrong password
// is ErrBadCredentials, a wrong code ErrBadCode. An admin who disables MFA
// loses access to their organizations until they enrol again.
func (s *Service) DisableMFA(ctx context.Context, sess store.Session, token, pw, code string, c Client) error {
	if !sess.MFAEnabled {
		return ErrMFANotEnabled
	}
	u, err := s.authenticate(ctx, sess.Email, pw, c)
	if err != nil {
		return err
	}
	_, ok, err := s.checkSecondFactor(ctx, u.ID, code)
	if err != nil {
		return err
	}
	if !ok {
		return s.loginFailed(ctx, u, "wrong mfa code", c, ErrBadCode)
	}
	return s.auth.DisableMFA(ctx, u.ID, token, c.IP)
}

// SetSessionCookie gives the browser the session token.
func SetSessionCookie(w http.ResponseWriter, token string, expires time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name: SessionCookie, Value: token, Path: "/", Expires: expires,
		Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode,
	})
}

// ClearSessionCookie removes the session cookie from the browser.
func ClearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name: SessionCookie, Value: "", Path: "/", MaxAge: -1,
		Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode,
	})
}
