package account

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/jordyorel/orus-shield/engine/internal/mailer"
	"github.com/jordyorel/orus-shield/engine/internal/password"
	"github.com/jordyorel/orus-shield/engine/internal/store"
)

// Signup limits: requests per email and per client address over
// SignupWindow, and how long the confirmation link works.
const (
	SignupWindow       = time.Hour
	MaxSignupsPerEmail = 3
	MaxSignupsPerIP    = 5
	SignupTokenTTL     = 24 * time.Hour
)

// Signup errors.
var (
	// ErrSignupRateLimited: too many signup requests for the email or the
	// address; retry after SignupWindow.
	ErrSignupRateLimited = errors.New("too many signup requests, try again later")
	// ErrInvalidSignup: the email or the organization name is malformed.
	ErrInvalidSignup = errors.New("invalid email address or organization name")
	// ErrInvalidSignupToken: the confirmation link is unknown, expired or
	// used.
	ErrInvalidSignupToken = errors.New("invalid or expired signup link")
	// ErrAccountExists: the address got an account before the link was
	// used; the user signs in instead.
	ErrAccountExists = errors.New("an account already exists for this address: sign in")
)

// Signup handles the signup form. Nothing is created yet: a confirmation
// link is emailed, and the account and the organization only exist once it
// is used (CompleteSignup), which proves the address is the user's. When
// the address already has an account, the email says so instead (sign in,
// or reset the password). The answer is the same in both cases.
func (s *Service) Signup(ctx context.Context, email, orgName string, c Client) error {
	if _, err := store.NormalizeEmail(email); err != nil {
		return ErrInvalidSignup
	}
	if _, err := store.NormalizeOrgName(orgName); err != nil {
		return ErrInvalidSignup
	}
	byEmail, byIP, err := s.auth.RecentSignupRequests(ctx, email, c.IP, s.cfg.Now().Add(-SignupWindow))
	if err != nil {
		return err
	}
	if byEmail >= MaxSignupsPerEmail || byIP >= MaxSignupsPerIP {
		return ErrSignupRateLimited
	}
	token, existing, err := s.auth.RequestSignup(ctx, email, orgName, c.IP, SignupTokenTTL)
	if err != nil {
		return err
	}
	to, _ := store.NormalizeEmail(email)
	base := strings.TrimRight(s.cfg.PublicURL, "/")
	if existing {
		s.sendInBackground(ctx, mailer.AlreadyRegistered(to, base+"/login", base+"/forgot-password"), "signup_existing")
		return nil
	}
	name, _ := store.NormalizeOrgName(orgName)
	link := base + "/signup/complete#token=" + token
	s.sendInBackground(ctx, mailer.ConfirmSignup(to, name, link, SignupTokenTTL), "signup")
	return nil
}

// CompleteSignup uses the emailed link: it checks the password policy and
// creates the account, the organization and the admin membership. The user
// then signs in; as an admin they enable two-factor authentication first.
func (s *Service) CompleteSignup(ctx context.Context, token, pw string, c Client) error {
	if err := password.Check(pw); err != nil {
		return err
	}
	hash, err := password.Hash(pw)
	if err != nil {
		return err
	}
	_, _, err = s.auth.CompleteSignup(ctx, token, hash, c.IP)
	switch {
	case errors.Is(err, store.ErrInvalidToken):
		return ErrInvalidSignupToken
	case errors.Is(err, store.ErrExists):
		return ErrAccountExists
	}
	return err
}
