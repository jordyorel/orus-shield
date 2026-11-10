package account

import (
	"context"
	"errors"
	"time"

	"github.com/jordyorel/orus-shield/engine/internal/password"
	"github.com/jordyorel/orus-shield/engine/internal/store"
)

// SetupTokenTTL is how long an invitation's setup token is valid, as with
// orusctl user add.
const SetupTokenTTL = 24 * time.Hour

// Errors of the team and password flows.
var (
	// ErrMemberExists: the address is already a member of the organization.
	ErrMemberExists = errors.New("this user is already a member of the organization")
	// ErrAlreadyActivated: no setup token for an account with a password.
	ErrAlreadyActivated = errors.New("this account is already activated")
	// ErrLastAdmin: the change would leave the organization without admin.
	ErrLastAdmin = store.ErrLastAdmin
	// ErrNoMember: the user is not a member of the organization.
	ErrNoMember = errors.New("not found")
)

// Team methods take the organization the caller administers: the API
// checks the caller's admin role there (Access) before calling them.

// Members lists the organization's members.
func (s *Service) Members(ctx context.Context, orgID string) ([]store.Member, error) {
	return s.auth.Members(ctx, orgID)
}

// Invite adds email to the organization; see store.Auth.Invite.
func (s *Service) Invite(ctx context.Context, orgID, email, role string, by store.Session) (store.Invitation, error) {
	inv, err := s.auth.Invite(ctx, orgID, email, role, SetupTokenTTL, by.Email)
	if errors.Is(err, store.ErrExists) {
		return store.Invitation{}, ErrMemberExists
	}
	return inv, err
}

// ReissueSetupToken gives a never activated member a new setup token.
func (s *Service) ReissueSetupToken(ctx context.Context, orgID, userID string, by store.Session) (string, error) {
	token, err := s.auth.ReissueSetupToken(ctx, orgID, userID, SetupTokenTTL, by.Email)
	switch {
	case errors.Is(err, store.ErrExists):
		return "", ErrAlreadyActivated
	case errors.Is(err, store.ErrNotFound):
		return "", ErrNoMember
	}
	return token, err
}

// SetMemberRole changes a member's role, keeping at least one admin.
func (s *Service) SetMemberRole(ctx context.Context, orgID, userID, role string) error {
	err := s.auth.SetMemberRole(ctx, orgID, userID, role)
	if errors.Is(err, store.ErrNotFound) {
		return ErrNoMember
	}
	return err
}

// RemoveMember takes a member out of the organization, keeping an admin.
func (s *Service) RemoveMember(ctx context.Context, orgID, userID string) error {
	err := s.auth.RemoveMember(ctx, orgID, userID)
	if errors.Is(err, store.ErrNotFound) {
		return ErrNoMember
	}
	return err
}

// ChangePassword replaces the signed-in user's password. The current one
// is checked under the login rate limit (a stolen session alone cannot
// change it); the other sessions of the user are closed. A wrong current
// password is ErrBadCredentials; a weak new one the password package's
// error.
func (s *Service) ChangePassword(ctx context.Context, sess store.Session, token, current, next string, c Client) error {
	if _, err := s.authenticate(ctx, sess.Email, current, c); err != nil {
		return err
	}
	if err := password.Check(next); err != nil {
		return err
	}
	hash, err := password.Hash(next)
	if err != nil {
		return err
	}
	return s.auth.ChangePassword(ctx, sess.UserID, hash, token, c.IP)
}
