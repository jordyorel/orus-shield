package account

import (
	"context"
	"errors"
	"time"

	"github.com/jordyorel/orus-shield/engine/internal/mailer"
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

// Invite adds email to the organization; see store.Auth.Invite. The invitee
// is emailed in the background: a link to activate a new account, or a note
// that they have access, for an account that already exists. emailed says
// whether an email was sent (false when mail is not configured): the
// dashboard then tells the admin to pass the code on themselves.
func (s *Service) Invite(ctx context.Context, orgID, email, role string, by store.Session) (inv store.Invitation, emailed bool, err error) {
	inv, err = s.auth.Invite(ctx, orgID, email, role, SetupTokenTTL, by.Email)
	if errors.Is(err, store.ErrExists) {
		return store.Invitation{}, false, ErrMemberExists
	}
	if err != nil {
		return store.Invitation{}, false, err
	}
	org := s.orgName(ctx, by.UserID, orgID)
	var m mailer.Message
	if inv.Token != "" {
		m = mailer.Invitation(inv.Member.Email, org, by.Email, role == store.RoleAdmin, mailer.SetupLink(s.cfg.PublicURL, inv.Token), SetupTokenTTL)
	} else {
		m = mailer.AddedToOrganization(inv.Member.Email, org, by.Email, role == store.RoleAdmin, s.cfg.PublicURL)
	}
	return inv, s.sendInBackground(ctx, m, "invitation"), nil
}

// ReissueSetupToken gives a never activated member a new setup token and
// emails them the new link.
func (s *Service) ReissueSetupToken(ctx context.Context, orgID, userID string, by store.Session) (token string, emailed bool, err error) {
	token, err = s.auth.ReissueSetupToken(ctx, orgID, userID, SetupTokenTTL, by.Email)
	switch {
	case errors.Is(err, store.ErrExists):
		return "", false, ErrAlreadyActivated
	case errors.Is(err, store.ErrNotFound):
		return "", false, ErrNoMember
	case err != nil:
		return "", false, err
	}
	members, err := s.auth.Members(ctx, orgID)
	if err != nil {
		return "", false, err
	}
	for _, mem := range members {
		if mem.UserID == userID {
			m := mailer.Invitation(mem.Email, s.orgName(ctx, by.UserID, orgID), by.Email, mem.Role == store.RoleAdmin,
				mailer.SetupLink(s.cfg.PublicURL, token), SetupTokenTTL)
			return token, s.sendInBackground(ctx, m, "invitation"), nil
		}
	}
	return token, false, nil
}

// orgName is the organization's name as the inviting admin sees it, for
// the email. An empty name only makes the email less precise.
func (s *Service) orgName(ctx context.Context, userID, orgID string) string {
	ms, err := s.auth.Memberships(ctx, userID)
	if err != nil {
		return ""
	}
	for _, m := range ms {
		if m.OrgID == orgID {
			return m.OrgName
		}
	}
	return ""
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
