package store

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// Two-factor authentication (TOTP)
//
// The store keeps the sealed secret and enforces the rules that need
// atomicity: a time step is accepted once, a recovery code once, a login
// challenge once. Computing and checking codes is package totp's job, and
// sealing package seal's, in the API.

// RecoveryCodeCount is how many recovery codes a user gets at enrolment.
const RecoveryCodeCount = 10

// recoveryEncoding writes recovery codes with letters and digits that are
// easy to read back from paper (base32: no 0/O or 1/I confusion).
var recoveryEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// MFA is a user's second factor as stored.
type MFA struct {
	Sealed   []byte // the TOTP secret, sealed for the user's ID
	Enabled  bool   // confirmed with a first code
	LastStep int64  // last accepted time step
}

func emailOf(ctx context.Context, q querier, userID string) (string, error) {
	var email string
	err := q.QueryRow(ctx, "SELECT email FROM users WHERE id = $1", userID).Scan(&email)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrNotFound
	}
	return email, err
}

// BeginMFASetup stores a new, not yet confirmed secret for the user,
// replacing an unconfirmed one. It returns ErrExists if MFA is already
// enabled: changing the factor means disabling it first.
func (a *Auth) BeginMFASetup(ctx context.Context, userID string, sealed []byte) error {
	if !isUUID(userID) {
		return fmt.Errorf("begin mfa setup: %w", ErrNotFound)
	}
	err := a.inTx(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `
			INSERT INTO user_mfa (user_id, secret_sealed) VALUES ($1, $2)
			ON CONFLICT (user_id) DO UPDATE
				SET secret_sealed = EXCLUDED.secret_sealed, created_at = now(), last_step = 0
				WHERE user_mfa.enabled_at IS NULL`, userID, sealed)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return ErrExists
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("begin mfa setup: %w", err)
	}
	return nil
}

// MFA returns the user's second factor, or ErrNotFound if they never
// started enrolment.
func (a *Auth) MFA(ctx context.Context, userID string) (m MFA, err error) {
	if !isUUID(userID) {
		return MFA{}, fmt.Errorf("get mfa: %w", ErrNotFound)
	}
	err = a.inTx(ctx, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, "SELECT secret_sealed, enabled_at IS NOT NULL, last_step FROM user_mfa WHERE user_id = $1",
			userID).Scan(&m.Sealed, &m.Enabled, &m.LastStep)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		return err
	})
	if err != nil {
		return MFA{}, fmt.Errorf("get mfa: %w", err)
	}
	return m, nil
}

// EnableMFA confirms enrolment after the user typed a valid code for step.
// In one transaction it enables the factor, replaces the recovery codes,
// marks the current session (sessionToken) as opened with MFA and closes
// every other session of the user: a session stolen before enrolment does
// not survive it. It returns the recovery codes, to show once.
func (a *Auth) EnableMFA(ctx context.Context, userID string, step int64, sessionToken, ip string) (codes []string, err error) {
	if !isUUID(userID) {
		return nil, fmt.Errorf("enable mfa: %w", ErrNotFound)
	}
	err = a.inTx(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE user_mfa SET enabled_at = now(), last_step = $2
			WHERE user_id = $1 AND enabled_at IS NULL AND last_step < $2`, userID, step)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return ErrNotFound // no pending enrolment
		}
		if codes, err = replaceRecoveryCodes(ctx, tx, userID); err != nil {
			return err
		}
		if err := keepOnlySession(ctx, tx, userID, sessionToken, true); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, "DELETE FROM mfa_challenges WHERE user_id = $1", userID); err != nil {
			return err
		}
		email, err := emailOf(ctx, tx, userID)
		if err != nil {
			return err
		}
		return logAuth(ctx, tx, AuthEvent{UserID: userID, Email: email, Action: AuthMFAEnabled, IP: ip})
	})
	if err != nil {
		return nil, fmt.Errorf("enable mfa: %w", err)
	}
	return codes, nil
}

// keepOnlySession sets the mfa flag of the session token and deletes every
// other session of the user.
func keepOnlySession(ctx context.Context, tx pgx.Tx, userID, token string, mfa bool) error {
	hash := tokenHash(token)
	if _, err := tx.Exec(ctx, "UPDATE sessions SET mfa = $3 WHERE token_hash = $1 AND user_id = $2", hash, userID, mfa); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, "DELETE FROM sessions WHERE user_id = $1 AND token_hash <> $2", userID, hash)
	return err
}

func replaceRecoveryCodes(ctx context.Context, tx pgx.Tx, userID string) ([]string, error) {
	if _, err := tx.Exec(ctx, "DELETE FROM recovery_codes WHERE user_id = $1", userID); err != nil {
		return nil, err
	}
	codes := make([]string, 0, RecoveryCodeCount)
	for range RecoveryCodeCount {
		b := make([]byte, 10) // 80 bits
		if _, err := rand.Read(b); err != nil {
			return nil, fmt.Errorf("random recovery code: %w", err)
		}
		raw := recoveryEncoding.EncodeToString(b) // 16 characters
		if _, err := tx.Exec(ctx, "INSERT INTO recovery_codes (user_id, code_hash) VALUES ($1, $2)",
			userID, tokenHash(raw)); err != nil {
			return nil, err
		}
		codes = append(codes, raw[0:4]+"-"+raw[4:8]+"-"+raw[8:12]+"-"+raw[12:16])
	}
	return codes, nil
}

// normalizeRecoveryCode accepts a code as the user may type it: lowercase,
// with or without dashes and spaces.
func normalizeRecoveryCode(code string) string {
	return strings.Map(func(r rune) rune {
		if r == '-' || r == ' ' {
			return -1
		}
		return r
	}, strings.ToUpper(strings.TrimSpace(code)))
}

// UseTOTPStep records that a code for step was accepted. It returns false
// if a code for this step or a later one was already accepted (a replay,
// or two requests racing with the same code): only one of them wins.
func (a *Auth) UseTOTPStep(ctx context.Context, userID string, step int64) (ok bool, err error) {
	if !isUUID(userID) {
		return false, nil
	}
	err = a.inTx(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE user_mfa SET last_step = $2
			WHERE user_id = $1 AND enabled_at IS NOT NULL AND last_step < $2`, userID, step)
		ok = tag.RowsAffected() == 1
		return err
	})
	if err != nil {
		return false, fmt.Errorf("use totp step: %w", err)
	}
	return ok, nil
}

// UseRecoveryCode consumes one of the user's recovery codes. It returns
// false if the code is unknown or already used.
func (a *Auth) UseRecoveryCode(ctx context.Context, userID, code string) (ok bool, err error) {
	c := normalizeRecoveryCode(code)
	if !isUUID(userID) || len(c) != 16 {
		return false, nil
	}
	err = a.inTx(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE recovery_codes SET used_at = now()
			WHERE user_id = $1 AND code_hash = $2 AND used_at IS NULL`, userID, tokenHash(c))
		ok = tag.RowsAffected() == 1
		return err
	})
	if err != nil {
		return false, fmt.Errorf("use recovery code: %w", err)
	}
	return ok, nil
}

// CreateMFAChallenge records that the user gave a correct password and
// must now give a code. The returned token is valid until expiresAt and
// opens no session by itself.
func (a *Auth) CreateMFAChallenge(ctx context.Context, userID, ip string, expiresAt time.Time) (string, error) {
	token, hash, err := newToken()
	if err != nil {
		return "", err
	}
	err = a.inTx(ctx, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, "INSERT INTO mfa_challenges (token_hash, user_id, expires_at, ip) VALUES ($1, $2, $3, $4)",
			hash, userID, expiresAt, ip)
		return err
	})
	if err != nil {
		return "", fmt.Errorf("create mfa challenge: %w", err)
	}
	return token, nil
}

// MFAChallengeUser returns the user of a valid challenge: not expired, user
// not disabled, MFA still enabled. Anything else is ErrInvalidToken.
func (a *Auth) MFAChallengeUser(ctx context.Context, token string) (u User, err error) {
	err = a.inTx(ctx, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `SELECT u.id::text, u.email FROM mfa_challenges c
			JOIN users u ON u.id = c.user_id
			JOIN user_mfa m ON m.user_id = u.id AND m.enabled_at IS NOT NULL
			WHERE c.token_hash = $1 AND c.expires_at > now() AND u.disabled_at IS NULL`,
			tokenHash(token)).Scan(&u.ID, &u.Email)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrInvalidToken
		}
		return err
	})
	if err != nil && !errors.Is(err, ErrInvalidToken) {
		return User{}, fmt.Errorf("check mfa challenge: %w", err)
	}
	u.MFAEnabled = err == nil
	return u, err
}

// CompleteMFALogin consumes the challenge of userID (whose code the caller
// has just accepted) and opens a session marked as MFA. A challenge works
// once: a second attempt with it is ErrInvalidToken.
func (a *Auth) CompleteMFALogin(ctx context.Context, challenge, userID, ip, userAgent string, expiresAt time.Time) (token string, err error) {
	err = a.inTx(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `DELETE FROM mfa_challenges
			WHERE token_hash = $1 AND user_id = $2 AND expires_at > now()`, tokenHash(challenge), userID)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return ErrInvalidToken
		}
		token, err = createSession(ctx, tx, userID, ip, userAgent, expiresAt, true)
		return err
	})
	if err != nil && !errors.Is(err, ErrInvalidToken) {
		return "", fmt.Errorf("complete mfa login: %w", err)
	}
	return token, err
}

// DisableMFA removes the user's second factor and recovery codes. The
// current session stays open but loses its MFA mark; every other session
// is closed.
func (a *Auth) DisableMFA(ctx context.Context, userID, sessionToken, ip string) error {
	if !isUUID(userID) {
		return fmt.Errorf("disable mfa: %w", ErrNotFound)
	}
	err := a.inTx(ctx, func(tx pgx.Tx) error {
		if err := deleteMFA(ctx, tx, userID); err != nil {
			return err
		}
		if err := keepOnlySession(ctx, tx, userID, sessionToken, false); err != nil {
			return err
		}
		email, err := emailOf(ctx, tx, userID)
		if err != nil {
			return err
		}
		return logAuth(ctx, tx, AuthEvent{UserID: userID, Email: email, Action: AuthMFADisabled, IP: ip})
	})
	if err != nil {
		return fmt.Errorf("disable mfa: %w", err)
	}
	return nil
}

func deleteMFA(ctx context.Context, tx pgx.Tx, userID string) error {
	for _, q := range []string{
		"DELETE FROM user_mfa WHERE user_id = $1",
		"DELETE FROM recovery_codes WHERE user_id = $1",
		"DELETE FROM mfa_challenges WHERE user_id = $1",
	} {
		if _, err := tx.Exec(ctx, q, userID); err != nil {
			return err
		}
	}
	return nil
}

// ResetMFA removes a user's second factor for a lost phone (orusctl) and
// closes all their sessions. The user logs in with their password and
// must enrol again before using admin routes.
func (s *Store) ResetMFA(ctx context.Context, userID, actor string) error {
	if !isUUID(userID) {
		return fmt.Errorf("reset mfa: %w", ErrNotFound)
	}
	tx, err := s.begin(ctx)
	if err != nil {
		return fmt.Errorf("reset mfa: %w", err)
	}
	defer tx.Rollback(ctx)
	email, err := emailOf(ctx, tx, userID)
	if err != nil {
		return fmt.Errorf("reset mfa: %w", err)
	}
	if err := deleteMFA(ctx, tx, userID); err != nil {
		return fmt.Errorf("reset mfa: %w", err)
	}
	if _, err := tx.Exec(ctx, "DELETE FROM sessions WHERE user_id = $1", userID); err != nil {
		return fmt.Errorf("reset mfa: %w", err)
	}
	if err := logAuth(ctx, tx, AuthEvent{UserID: userID, Email: email, Action: AuthMFAReset, IP: "",
		Details: map[string]any{"by": actor}}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
