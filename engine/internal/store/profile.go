package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
)

// Profile is what Profil shows about the signed-in user.
type Profile struct {
	Name              string
	PasswordChangedAt *time.Time
	// RecoveryCodesLeft: unused recovery codes (0 without MFA).
	RecoveryCodesLeft int
}

// ErrInvalidName is a name that is too long or holds control characters.
var ErrInvalidName = errors.New("invalid name")

// NormalizeName trims a display name and checks it: at most 100
// characters, no control characters. Empty is allowed (no name).
func NormalizeName(name string) (string, error) {
	n := strings.TrimSpace(name)
	if utf8.RuneCountInString(n) > 100 || !utf8.ValidString(n) {
		return "", ErrInvalidName
	}
	for _, r := range n {
		if r < 0x20 || r == 0x7f {
			return "", ErrInvalidName
		}
	}
	return n, nil
}

// Profile returns the user's profile.
func (a *Auth) Profile(ctx context.Context, userID string) (p Profile, err error) {
	err = a.inTx(ctx, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `
			SELECT u.name, u.password_changed_at,
				(SELECT count(*) FROM recovery_codes c WHERE c.user_id = u.id AND c.used_at IS NULL)
			FROM users u WHERE u.id = $1`, userID).
			Scan(&p.Name, &p.PasswordChangedAt, &p.RecoveryCodesLeft)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return Profile{}, ErrNotFound
	}
	if err != nil {
		return Profile{}, fmt.Errorf("profile: %w", err)
	}
	return p, nil
}

// SetName changes the user's display name (already normalized).
func (a *Auth) SetName(ctx context.Context, userID, email, name, ip string) error {
	return a.inTx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "UPDATE users SET name = $2 WHERE id = $1", userID, name); err != nil {
			return fmt.Errorf("set name: %w", err)
		}
		return logAuth(ctx, tx, AuthEvent{UserID: userID, Email: email, Action: "profile.name_changed", IP: ip})
	})
}

// DeviceSession is one open session, as Appareils connectés lists it.
type DeviceSession struct {
	ID         string
	CreatedAt  time.Time
	LastSeenAt time.Time
	IP         string
	UserAgent  string
	Current    bool
}

// Sessions lists the user's sessions still valid within idle, most
// recently used first. current is the caller's own token.
func (a *Auth) Sessions(ctx context.Context, userID, current string, idle time.Duration) (out []DeviceSession, err error) {
	err = a.inTx(ctx, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT id::text, created_at, last_seen_at, ip, user_agent, token_hash = $2
			FROM sessions
			WHERE user_id = $1 AND expires_at > now() AND last_seen_at > now() - make_interval(secs => $3)
			ORDER BY token_hash = $2 DESC, last_seen_at DESC
			LIMIT 50`, userID, tokenHash(current), idle.Seconds())
		if err != nil {
			return err
		}
		out, err = pgx.CollectRows(rows, func(row pgx.CollectableRow) (DeviceSession, error) {
			var d DeviceSession
			err := row.Scan(&d.ID, &d.CreatedAt, &d.LastSeenAt, &d.IP, &d.UserAgent, &d.Current)
			return d, err
		})
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("list sessions: %w", err)
	}
	return out, nil
}

// EndSession closes one of the user's sessions by its public ID. Ending
// another user's session, or an unknown one, is ErrNotFound.
func (a *Auth) EndSession(ctx context.Context, userID, email, sessionID, ip string) error {
	if !isUUID(sessionID) {
		return ErrNotFound
	}
	return a.inTx(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, "DELETE FROM sessions WHERE id = $1 AND user_id = $2", sessionID, userID)
		if err != nil {
			return fmt.Errorf("end session: %w", err)
		}
		if tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		return logAuth(ctx, tx, AuthEvent{UserID: userID, Email: email, Action: "session.ended", IP: ip})
	})
}

// AuthActivity is one line of the user's own security history.
type AuthActivity struct {
	At     time.Time
	Action string
	IP     string
}

// Activity returns the user's latest auth log entries, newest first.
func (a *Auth) Activity(ctx context.Context, userID string, limit int) (out []AuthActivity, err error) {
	err = a.inTx(ctx, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT at, action, ip FROM auth_log WHERE user_id = $1 ORDER BY at DESC LIMIT $2`, userID, limit)
		if err != nil {
			return err
		}
		out, err = pgx.CollectRows(rows, func(row pgx.CollectableRow) (AuthActivity, error) {
			var e AuthActivity
			err := row.Scan(&e.At, &e.Action, &e.IP)
			return e, err
		})
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("auth activity: %w", err)
	}
	return out, nil
}
