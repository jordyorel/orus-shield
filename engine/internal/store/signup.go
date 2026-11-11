package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// Auth log actions of self-service signup.
const (
	AuthSignupRequested = "signup.requested"
	AuthSignupCompleted = "signup.completed"
)

// MaxOrgNameChars bounds an organization's name (also checked by the
// table).
const MaxOrgNameChars = maxOrgNameChars

// NormalizeOrgName trims a name typed by a customer and checks its length.
// Control characters are refused: the name ends up in emails and pages.
func NormalizeOrgName(name string) (string, error) {
	n := strings.Join(strings.Fields(name), " ")
	if n == "" || len([]rune(n)) > maxOrgNameChars {
		return "", fmt.Errorf("organization name must have 1 to %d characters", maxOrgNameChars)
	}
	for _, r := range n {
		if r < 0x20 || r == 0x7f {
			return "", errors.New("organization name contains control characters")
		}
	}
	return n, nil
}

// RequestSignup records a signup request for email and orgName from ip.
// When no account has the address, it stores a request valid for ttl and
// returns its token (earlier unused requests for the address are revoked).
// existing is true when an account already has the address: no request is
// stored, and the caller emails the owner instead. Either way the request
// is logged, for the rate limit.
func (a *Auth) RequestSignup(ctx context.Context, email, orgName, ip string, ttl time.Duration) (token string, existing bool, err error) {
	e, err := NormalizeEmail(email)
	if err != nil {
		return "", false, err
	}
	name, err := NormalizeOrgName(orgName)
	if err != nil {
		return "", false, err
	}
	err = a.inTx(ctx, func(tx pgx.Tx) error {
		_, err := userByEmail(ctx, tx, e)
		switch {
		case err == nil:
			existing = true
		case !errors.Is(err, ErrNotFound):
			return err
		}
		if err := logAuth(ctx, tx, AuthEvent{Email: e, Action: AuthSignupRequested, IP: ip,
			Details: map[string]any{"existing_account": existing}}); err != nil {
			return err
		}
		if existing {
			return nil
		}
		if _, err := tx.Exec(ctx, "UPDATE signup_requests SET used_at = now() WHERE email = $1 AND used_at IS NULL", e); err != nil {
			return err
		}
		var hash []byte
		if token, hash, err = newToken(); err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `INSERT INTO signup_requests (token_hash, email, org_name, ip, expires_at)
			VALUES ($1, $2, $3, $4, now() + make_interval(secs => $5))`, hash, e, name, ip, ttl.Seconds())
		return err
	})
	if err != nil {
		return "", false, fmt.Errorf("request signup: %w", err)
	}
	return token, existing, nil
}

// RecentSignupRequests counts signup requests since since, for one email
// and for one IP: the inputs of their rate limit.
func (a *Auth) RecentSignupRequests(ctx context.Context, email, ip string, since time.Time) (byEmail, byIP int, err error) {
	e, _ := NormalizeEmail(email)
	err = a.inTx(ctx, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT
			(SELECT count(*) FROM auth_log WHERE action = $1 AND email = $2 AND at > $4),
			(SELECT count(*) FROM auth_log WHERE action = $1 AND ip = $3 AND at > $4)`,
			AuthSignupRequested, e, ip, since).Scan(&byEmail, &byIP)
	})
	if err != nil {
		return 0, 0, fmt.Errorf("recent signup requests: %w", err)
	}
	return byEmail, byIP, nil
}

// CompleteSignup uses a signup token: in one transaction it consumes the
// request, creates the account with passwordHash, creates the organization
// and makes the user its admin. An unknown, expired or used token is
// ErrInvalidToken; an address that got an account meanwhile is ErrExists.
func (a *Auth) CompleteSignup(ctx context.Context, token, passwordHash, ip string) (u User, orgID string, err error) {
	err = a.inTx(ctx, func(tx pgx.Tx) error {
		var orgName string
		err := tx.QueryRow(ctx, `
			UPDATE signup_requests SET used_at = now()
			WHERE token_hash = $1 AND used_at IS NULL AND expires_at > now()
			RETURNING email, org_name`, tokenHash(token)).Scan(&u.Email, &orgName)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrInvalidToken
		}
		if err != nil {
			return err
		}
		tag, err := tx.Exec(ctx, "INSERT INTO users (email) VALUES ($1) ON CONFLICT (email) DO NOTHING", u.Email)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return ErrExists
		}
		if err := tx.QueryRow(ctx, `UPDATE users SET password_hash = $2, password_changed_at = now()
			WHERE email = $1 RETURNING id::text`, u.Email, passwordHash).Scan(&u.ID); err != nil {
			return err
		}
		// The auth role cannot insert organizations; this function creates
		// the one of the request consumed above (migration 0013).
		if err := tx.QueryRow(ctx, "SELECT signup_create_organization($1)::text", tokenHash(token)).Scan(&orgID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, "INSERT INTO memberships (user_id, org_id, role) VALUES ($1, $2, $3)", u.ID, orgID, RoleAdmin); err != nil {
			return err
		}
		return logAuth(ctx, tx, AuthEvent{UserID: u.ID, Email: u.Email, Action: AuthSignupCompleted, IP: ip,
			Details: map[string]any{"org_id": orgID, "org_name": orgName}})
	})
	if err != nil {
		if errors.Is(err, ErrInvalidToken) || errors.Is(err, ErrExists) {
			return User{}, "", err
		}
		return User{}, "", fmt.Errorf("complete signup: %w", err)
	}
	return u, orgID, nil
}
