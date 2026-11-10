package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// Team management for organization admins, through the API's auth handle
// (role orus_auth, migration 0009). Every method takes the organization the
// caller administers: the API checked the caller's role there first.

// ErrLastAdmin is returned when a change would leave an organization
// without any admin.
var ErrLastAdmin = errors.New("an organization keeps at least one admin")

// Member is one user of an organization, as the team page shows it.
type Member struct {
	UserID     string
	Email      string
	Role       string
	Activated  bool // a password is set
	MFAEnabled bool
	Disabled   bool
}

// Invitation is the outcome of Invite. Token is the one-time setup token
// to send to the invitee, empty when the account was already activated
// (the user simply sees the organization at their next login).
type Invitation struct {
	Member Member
	Token  string
}

// Members lists an organization's members by email.
func (a *Auth) Members(ctx context.Context, orgID string) (ms []Member, err error) {
	if !isUUID(orgID) {
		return nil, ErrNotFound
	}
	err = a.inTx(ctx, func(tx pgx.Tx) error {
		ms, err = members(ctx, tx, orgID, "")
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("members: %w", err)
	}
	return ms, nil
}

func members(ctx context.Context, tx pgx.Tx, orgID, userID string) ([]Member, error) {
	rows, err := tx.Query(ctx, `
		SELECT u.id::text, u.email, m.role, u.password_hash IS NOT NULL, coalesce(f.enabled_at IS NOT NULL, false), u.disabled_at IS NOT NULL
		FROM memberships m JOIN users u ON u.id = m.user_id LEFT JOIN user_mfa f ON f.user_id = u.id
		WHERE m.org_id = $1 AND ($2 = '' OR m.user_id::text = $2)
		ORDER BY u.email`, orgID, userID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Member, error) {
		var m Member
		return m, r.Scan(&m.UserID, &m.Email, &m.Role, &m.Activated, &m.MFAEnabled, &m.Disabled)
	})
}

// Invite adds email to the organization with role, creating the account if
// needed. A new or never activated account gets a setup token valid for
// ttl (previous ones are revoked). A user already in the organization is
// ErrExists.
func (a *Auth) Invite(ctx context.Context, orgID, email, role string, ttl time.Duration, by string) (inv Invitation, err error) {
	if role != RoleAdmin && role != RoleViewer {
		return Invitation{}, fmt.Errorf("unknown role %q (admin or viewer)", role)
	}
	if !isUUID(orgID) {
		return Invitation{}, ErrNotFound
	}
	e, err := NormalizeEmail(email)
	if err != nil {
		return Invitation{}, err
	}
	err = a.inTx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "INSERT INTO users (email) VALUES ($1) ON CONFLICT (email) DO NOTHING", e); err != nil {
			return err
		}
		var userID string
		if err := tx.QueryRow(ctx, "SELECT id::text FROM users WHERE email = $1", e).Scan(&userID); err != nil {
			return err
		}
		tag, err := tx.Exec(ctx, `INSERT INTO memberships (user_id, org_id, role) VALUES ($1, $2, $3)
			ON CONFLICT (user_id, org_id) DO NOTHING`, userID, orgID, role)
		if err != nil {
			return foreignKeyNotFound(err)
		}
		if tag.RowsAffected() == 0 {
			return ErrExists
		}
		ms, err := members(ctx, tx, orgID, userID)
		if err != nil || len(ms) != 1 {
			return fmt.Errorf("read new member: %w", err)
		}
		inv.Member = ms[0]
		if !inv.Member.Activated {
			if inv.Token, err = issueToken(ctx, tx, userID, e, ttl, by); err != nil {
				return err
			}
		}
		return nil
	})
	if errors.Is(err, ErrExists) {
		return Invitation{}, fmt.Errorf("invite %s: %w", e, ErrExists)
	}
	if err != nil {
		return Invitation{}, fmt.Errorf("invite %s: %w", e, err)
	}
	return inv, nil
}

// ReissueSetupToken gives a member who never activated their account a new
// setup token (the previous one is revoked). An activated account is
// ErrExists: they reset their password otherwise.
func (a *Auth) ReissueSetupToken(ctx context.Context, orgID, userID string, ttl time.Duration, by string) (token string, err error) {
	if !isUUID(orgID) || !isUUID(userID) {
		return "", ErrNotFound
	}
	err = a.inTx(ctx, func(tx pgx.Tx) error {
		ms, err := members(ctx, tx, orgID, userID)
		if err != nil {
			return err
		}
		if len(ms) == 0 {
			return ErrNotFound
		}
		if ms[0].Activated {
			return ErrExists
		}
		token, err = issueToken(ctx, tx, userID, ms[0].Email, ttl, by)
		return err
	})
	if err != nil {
		return "", fmt.Errorf("reissue setup token: %w", err)
	}
	return token, nil
}

func issueToken(ctx context.Context, tx pgx.Tx, userID, email string, ttl time.Duration, by string) (string, error) {
	token, hash, err := newToken()
	if err != nil {
		return "", err
	}
	if _, err := tx.Exec(ctx, "UPDATE setup_tokens SET used_at = now() WHERE user_id = $1 AND used_at IS NULL", userID); err != nil {
		return "", err
	}
	if _, err := tx.Exec(ctx, "INSERT INTO setup_tokens (token_hash, user_id, expires_at) VALUES ($1, $2, now() + make_interval(secs => $3))",
		hash, userID, ttl.Seconds()); err != nil {
		return "", err
	}
	return token, logAuth(ctx, tx, AuthEvent{UserID: userID, Email: email, Action: AuthSetupTokenIssue, Details: map[string]any{"by": by}})
}

// SetMemberRole changes a member's role. Demoting the last admin is
// ErrLastAdmin; a user outside the organization is ErrNotFound.
func (a *Auth) SetMemberRole(ctx context.Context, orgID, userID, role string) error {
	if role != RoleAdmin && role != RoleViewer {
		return fmt.Errorf("unknown role %q (admin or viewer)", role)
	}
	if !isUUID(orgID) || !isUUID(userID) {
		return ErrNotFound
	}
	return a.inTx(ctx, func(tx pgx.Tx) error {
		if err := lockAdmins(ctx, tx, orgID); err != nil {
			return err
		}
		tag, err := tx.Exec(ctx, "UPDATE memberships SET role = $3 WHERE org_id = $1 AND user_id = $2", orgID, userID, role)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		return keepAnAdmin(ctx, tx, orgID)
	})
}

// RemoveMember takes a user out of the organization (the account stays:
// it may belong to other organizations). Removing the last admin is
// ErrLastAdmin.
func (a *Auth) RemoveMember(ctx context.Context, orgID, userID string) error {
	if !isUUID(orgID) || !isUUID(userID) {
		return ErrNotFound
	}
	return a.inTx(ctx, func(tx pgx.Tx) error {
		if err := lockAdmins(ctx, tx, orgID); err != nil {
			return err
		}
		tag, err := tx.Exec(ctx, "DELETE FROM memberships WHERE org_id = $1 AND user_id = $2", orgID, userID)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		return keepAnAdmin(ctx, tx, orgID)
	})
}

// lockAdmins locks the organization's admin rows, so two admins demoting
// each other at the same time cannot both succeed and leave none.
func lockAdmins(ctx context.Context, tx pgx.Tx, orgID string) error {
	_, err := tx.Exec(ctx, "SELECT 1 FROM memberships WHERE org_id = $1 AND role = 'admin' FOR UPDATE", orgID)
	return err
}

// keepAnAdmin fails the transaction if the organization has no admin left.
func keepAnAdmin(ctx context.Context, tx pgx.Tx, orgID string) error {
	var n int
	if err := tx.QueryRow(ctx, "SELECT count(*) FROM memberships WHERE org_id = $1 AND role = 'admin'", orgID).Scan(&n); err != nil {
		return err
	}
	if n == 0 {
		return ErrLastAdmin
	}
	return nil
}

// ChangePassword replaces a signed-in user's password hash and closes
// their other sessions (keepToken is the current one): a session opened
// with the old password, maybe by someone else, ends.
func (a *Auth) ChangePassword(ctx context.Context, userID, passwordHash, keepToken, ip string) error {
	if !isUUID(userID) {
		return ErrNotFound
	}
	return a.inTx(ctx, func(tx pgx.Tx) error {
		var email string
		if err := tx.QueryRow(ctx, `UPDATE users SET password_hash = $2, password_changed_at = now()
			WHERE id = $1 RETURNING email`, userID, passwordHash).Scan(&email); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrNotFound
			}
			return err
		}
		if _, err := tx.Exec(ctx, "DELETE FROM sessions WHERE user_id = $1 AND token_hash <> $2", userID, tokenHash(keepToken)); err != nil {
			return err
		}
		return logAuth(ctx, tx, AuthEvent{UserID: userID, Email: email, Action: AuthPasswordSet, IP: ip, Details: map[string]any{"by": "user"}})
	})
}
