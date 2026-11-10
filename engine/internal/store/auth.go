package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Accounts and sessions
//
// Customer data goes through *Org (row-level security, role orus_app).
// Accounts go through *Auth, whose transactions run as the orus_auth role:
// it can read users, memberships and sessions, and nothing else. Creating
// users and memberships is administration, done on *Store by orusctl.

// authRole is the PostgreSQL role of Auth transactions (migration 0007).
const authRole = "orus_auth"

// Roles within an organization.
const (
	RoleAdmin  = "admin"
	RoleViewer = "viewer"
)

// Auth log actions.
const (
	AuthLoginOK         = "login.ok"
	AuthLoginFailed     = "login.failed"
	AuthLogout          = "logout"
	AuthPasswordSet     = "password.set"
	AuthSetupTokenIssue = "setup_token.issued"  //nolint:gosec // G101: an audit action name, not a credential
	AuthMFAChallenge    = "login.mfa_challenge" // password correct, code expected
	AuthMFAEnabled      = "mfa.enabled"
	AuthMFADisabled     = "mfa.disabled"
	AuthMFAReset        = "mfa.reset" // by an operator, for a lost phone
)

// Audit action when a user is added to an organization.
const ActionMemberAdded = "member.added"

var (
	// ErrInvalidToken means a session or setup token is unknown, expired or
	// already used. Callers must not say which.
	ErrInvalidToken = errors.New("invalid or expired token")
	// ErrExists is returned when creating something that already exists.
	ErrExists = errors.New("already exists")
)

// User is an account.
type User struct {
	ID           string
	Email        string
	PasswordHash string // empty until set
	CreatedAt    time.Time
	DisabledAt   *time.Time
	MFAEnabled   bool // a confirmed TOTP second factor
}

// Membership is a user's role in one organization.
type Membership struct {
	OrgID   string
	OrgName string
	Role    string
}

// Session is a valid session, as returned by SessionUser.
type Session struct {
	UserID    string
	Email     string
	ExpiresAt time.Time
	// MFA is true when the session was opened, or upgraded at enrolment,
	// with a second factor. Admin routes require it.
	MFA bool
	// MFAEnabled tells whether the user has a confirmed second factor.
	MFAEnabled bool
}

// AuthEvent is one line of the auth log.
type AuthEvent struct {
	UserID  string // empty when unknown (failed login for an unknown email)
	Email   string
	Action  string
	IP      string
	Details map[string]any
}

// NormalizeEmail lowercases and trims an email address and checks its
// rough shape. Real validation is the setup email we will send later.
func NormalizeEmail(email string) (string, error) {
	e := strings.ToLower(strings.TrimSpace(email))
	at := strings.IndexByte(e, '@')
	if len(e) < 3 || len(e) > 254 || at < 1 || at == len(e)-1 || strings.ContainsAny(e, " \t\r\n") {
		return "", fmt.Errorf("invalid email address %q", email)
	}
	return e, nil
}

// newToken returns a random token for the client and the SHA-256 the
// database keeps. 32 bytes from crypto/rand: unguessable.
func newToken() (token string, hash []byte, err error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", nil, fmt.Errorf("random token: %w", err)
	}
	token = base64.RawURLEncoding.EncodeToString(b)
	h := sha256.Sum256([]byte(token))
	return token, h[:], nil
}

func tokenHash(token string) []byte {
	h := sha256.Sum256([]byte(token))
	return h[:]
}

// ---- Administration (orusctl) ----------------------------------------------

// CreateUser creates an account without a password.
func (s *Store) CreateUser(ctx context.Context, email string) (User, error) {
	e, err := NormalizeEmail(email)
	if err != nil {
		return User{}, err
	}
	var u User
	err = s.pool.QueryRow(ctx, "INSERT INTO users (email) VALUES ($1) RETURNING id::text, email, created_at",
		e).Scan(&u.ID, &u.Email, &u.CreatedAt)
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" { // unique_violation
		return User{}, fmt.Errorf("user %s: %w", e, ErrExists)
	}
	if err != nil {
		return User{}, fmt.Errorf("create user %s: %w", e, err)
	}
	return u, nil
}

// UserByEmail returns an account, for administration.
func (s *Store) UserByEmail(ctx context.Context, email string) (User, error) {
	return userByEmail(ctx, s.pool, email)
}

func userByEmail(ctx context.Context, q querier, email string) (User, error) {
	e, err := NormalizeEmail(email)
	if err != nil {
		return User{}, fmt.Errorf("get user: %w", ErrNotFound)
	}
	var u User
	err = q.QueryRow(ctx, `SELECT u.id::text, u.email, coalesce(u.password_hash, ''), u.created_at, u.disabled_at,
			m.enabled_at IS NOT NULL
		FROM users u LEFT JOIN user_mfa m ON m.user_id = u.id
		WHERE u.email = $1`, e).Scan(&u.ID, &u.Email, &u.PasswordHash, &u.CreatedAt, &u.DisabledAt, &u.MFAEnabled)
	if errors.Is(err, pgx.ErrNoRows) {
		return User{}, fmt.Errorf("get user %s: %w", e, ErrNotFound)
	}
	if err != nil {
		return User{}, fmt.Errorf("get user %s: %w", e, err)
	}
	return u, nil
}

// SetMembership gives a user a role in an organization (adding them or
// changing their role) and audits it in the organization's log.
func (s *Store) SetMembership(ctx context.Context, userID, orgID, role, actor string) error {
	if role != RoleAdmin && role != RoleViewer {
		return fmt.Errorf("unknown role %q (admin or viewer)", role)
	}
	if !isUUID(userID) || !isUUID(orgID) {
		return fmt.Errorf("set membership: %w", ErrNotFound)
	}
	tx, err := s.begin(ctx)
	if err != nil {
		return fmt.Errorf("set membership: %w", err)
	}
	defer tx.Rollback(ctx)
	var email string
	err = tx.QueryRow(ctx, `
		WITH m AS (
			INSERT INTO memberships (user_id, org_id, role) VALUES ($1, $2, $3)
			ON CONFLICT (user_id, org_id) DO UPDATE SET role = EXCLUDED.role
			RETURNING user_id
		)
		SELECT u.email FROM m JOIN users u ON u.id = m.user_id`, userID, orgID, role).Scan(&email)
	if err != nil {
		return fmt.Errorf("set membership: %w", foreignKeyNotFound(err))
	}
	if err := appendAudit(ctx, tx, AuditEntry{
		OrgID: orgID, Actor: actor, Action: ActionMemberAdded, Target: "",
		Details: map[string]any{"user_id": userID, "email": email, "role": role},
	}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// IssueSetupToken returns a one-time token letting the user set their
// password (first setup or reset), valid for ttl. Previous unused tokens of
// the user are invalidated.
func (s *Store) IssueSetupToken(ctx context.Context, userID string, ttl time.Duration, actor string) (string, error) {
	if !isUUID(userID) {
		return "", fmt.Errorf("issue setup token: %w", ErrNotFound)
	}
	token, hash, err := newToken()
	if err != nil {
		return "", err
	}
	tx, err := s.begin(ctx)
	if err != nil {
		return "", fmt.Errorf("issue setup token: %w", err)
	}
	defer tx.Rollback(ctx)
	var email string
	if err := tx.QueryRow(ctx, "SELECT email FROM users WHERE id = $1", userID).Scan(&email); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", fmt.Errorf("issue setup token: %w", ErrNotFound)
		}
		return "", fmt.Errorf("issue setup token: %w", err)
	}
	if _, err := tx.Exec(ctx, "UPDATE setup_tokens SET used_at = now() WHERE user_id = $1 AND used_at IS NULL", userID); err != nil {
		return "", fmt.Errorf("issue setup token: %w", err)
	}
	if _, err := tx.Exec(ctx, "INSERT INTO setup_tokens (token_hash, user_id, expires_at) VALUES ($1, $2, now() + make_interval(secs => $3))",
		hash, userID, ttl.Seconds()); err != nil {
		return "", fmt.Errorf("issue setup token: %w", err)
	}
	if err := logAuth(ctx, tx, AuthEvent{UserID: userID, Email: email, Action: AuthSetupTokenIssue, IP: "",
		Details: map[string]any{"by": actor}}); err != nil {
		return "", err
	}
	return token, tx.Commit(ctx)
}

// ---- Auth handle (API) -----------------------------------------------------

// Auth is the storage of the API's authentication code. Its transactions
// run as orus_auth: accounts and sessions only, never customer data. It is
// safe for concurrent use.
type Auth struct {
	pool *pgxpool.Pool
}

// Auth returns the authentication handle.
func (s *Store) Auth() *Auth { return &Auth{pool: s.pool} }

func (a *Auth) begin(ctx context.Context) (pgx.Tx, error) {
	tx, err := a.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	// authRole is a constant: no injection possible.
	if _, err := tx.Exec(ctx, "SET LOCAL ROLE "+authRole); err != nil {
		_ = tx.Rollback(ctx)
		return nil, fmt.Errorf("switch to role %s: %w", authRole, err)
	}
	return tx, nil
}

// inTx runs fn in an Auth transaction and commits it.
func (a *Auth) inTx(ctx context.Context, fn func(pgx.Tx) error) error {
	tx, err := a.begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// UserByEmail returns the account for email (with its password hash), or
// ErrNotFound.
func (a *Auth) UserByEmail(ctx context.Context, email string) (u User, err error) {
	err = a.inTx(ctx, func(tx pgx.Tx) error {
		u, err = userByEmail(ctx, tx, email)
		return err
	})
	return u, err
}

// Log writes an auth log entry.
func (a *Auth) Log(ctx context.Context, e AuthEvent) error {
	return a.inTx(ctx, func(tx pgx.Tx) error { return logAuth(ctx, tx, e) })
}

func logAuth(ctx context.Context, q querier, e AuthEvent) error {
	details := []byte("{}")
	if e.Details != nil {
		var err error
		if details, err = json.Marshal(e.Details); err != nil {
			return fmt.Errorf("auth log: %w", err)
		}
	}
	var userID *string
	if e.UserID != "" {
		userID = &e.UserID
	}
	_, err := q.Exec(ctx, "INSERT INTO auth_log (user_id, email, action, ip, details) VALUES ($1, $2, $3, $4, $5)",
		userID, truncateRunes(e.Email, 254), e.Action, e.IP, details)
	if err != nil {
		return fmt.Errorf("auth log %s: %w", e.Action, err)
	}
	return nil
}

// RecentFailures counts failed logins since since, for one email and for
// one IP: the inputs of the login rate limit.
func (a *Auth) RecentFailures(ctx context.Context, email, ip string, since time.Time) (byEmail, byIP int, err error) {
	err = a.inTx(ctx, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT
			(SELECT count(*) FROM auth_log WHERE action = $1 AND email = $2 AND at > $4),
			(SELECT count(*) FROM auth_log WHERE action = $1 AND ip = $3 AND at > $4)`,
			AuthLoginFailed, email, ip, since).Scan(&byEmail, &byIP)
	})
	if err != nil {
		return 0, 0, fmt.Errorf("recent login failures: %w", err)
	}
	return byEmail, byIP, nil
}

// CreateSession opens a session for a user without a second factor, valid
// until expiresAt, and returns its token. Users with MFA go through
// CreateMFAChallenge and CompleteMFALogin instead.
func (a *Auth) CreateSession(ctx context.Context, userID, ip, userAgent string, expiresAt time.Time) (token string, err error) {
	err = a.inTx(ctx, func(tx pgx.Tx) error {
		token, err = createSession(ctx, tx, userID, ip, userAgent, expiresAt, false)
		return err
	})
	if err != nil {
		return "", fmt.Errorf("create session: %w", err)
	}
	return token, nil
}

// createSession inserts a session and returns its token. Only the token's
// hash is stored.
func createSession(ctx context.Context, tx pgx.Tx, userID, ip, userAgent string, expiresAt time.Time, mfa bool) (string, error) {
	token, hash, err := newToken()
	if err != nil {
		return "", err
	}
	_, err = tx.Exec(ctx, `INSERT INTO sessions (token_hash, user_id, expires_at, ip, user_agent, mfa)
		VALUES ($1, $2, $3, $4, $5, $6)`, hash, userID, expiresAt, ip, truncateRunes(userAgent, 512), mfa)
	return token, err
}

// SessionUser returns the session for token if it is valid: not expired,
// used within idle, and its user is not disabled. It records the use, at
// most once a minute to spare writes. Any invalid token is ErrInvalidToken.
func (a *Auth) SessionUser(ctx context.Context, token string, idle time.Duration) (s Session, err error) {
	err = a.inTx(ctx, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `
			UPDATE sessions se SET last_seen_at = CASE
				WHEN se.last_seen_at < now() - interval '1 minute' THEN now() ELSE se.last_seen_at END
			FROM users u
			WHERE se.token_hash = $1 AND u.id = se.user_id AND u.disabled_at IS NULL
			  AND se.expires_at > now() AND se.last_seen_at > now() - make_interval(secs => $2)
			RETURNING u.id::text, u.email, se.expires_at, se.mfa,
				EXISTS (SELECT FROM user_mfa m WHERE m.user_id = u.id AND m.enabled_at IS NOT NULL)`,
			tokenHash(token), idle.Seconds()).
			Scan(&s.UserID, &s.Email, &s.ExpiresAt, &s.MFA, &s.MFAEnabled)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrInvalidToken
		}
		return err
	})
	if err != nil && !errors.Is(err, ErrInvalidToken) {
		return Session{}, fmt.Errorf("check session: %w", err)
	}
	return s, err
}

// DeleteSession ends the session of token. Unknown tokens are ignored.
func (a *Auth) DeleteSession(ctx context.Context, token string) error {
	return a.inTx(ctx, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, "DELETE FROM sessions WHERE token_hash = $1", tokenHash(token))
		return err
	})
}

// SetPasswordWithToken uses a setup token: the password hash is stored, the
// token is consumed, and every session of the user is closed. It returns the
// user. An unknown, expired or used token is ErrInvalidToken.
func (a *Auth) SetPasswordWithToken(ctx context.Context, token, passwordHash, ip string) (u User, err error) {
	err = a.inTx(ctx, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `
			UPDATE setup_tokens SET used_at = now()
			WHERE token_hash = $1 AND used_at IS NULL AND expires_at > now()
			RETURNING user_id::text`, tokenHash(token)).Scan(&u.ID)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrInvalidToken
		}
		if err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `UPDATE users SET password_hash = $2, password_changed_at = now()
			WHERE id = $1 AND disabled_at IS NULL RETURNING email`, u.ID, passwordHash).Scan(&u.Email); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrInvalidToken // disabled account
			}
			return err
		}
		if _, err := tx.Exec(ctx, "DELETE FROM sessions WHERE user_id = $1", u.ID); err != nil {
			return err
		}
		return logAuth(ctx, tx, AuthEvent{UserID: u.ID, Email: u.Email, Action: AuthPasswordSet, IP: ip})
	})
	if err != nil && !errors.Is(err, ErrInvalidToken) {
		return User{}, fmt.Errorf("set password: %w", err)
	}
	return u, err
}

// Memberships returns the organizations of a user, by name.
func (a *Auth) Memberships(ctx context.Context, userID string) (ms []Membership, err error) {
	if !isUUID(userID) {
		return nil, nil
	}
	err = a.inTx(ctx, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT m.org_id::text, o.name, m.role
			FROM memberships m JOIN organizations o ON o.id = m.org_id
			WHERE m.user_id = $1 ORDER BY o.name, m.org_id`, userID)
		if err != nil {
			return err
		}
		ms, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (Membership, error) {
			var m Membership
			return m, r.Scan(&m.OrgID, &m.OrgName, &m.Role)
		})
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("memberships: %w", err)
	}
	return ms, nil
}

// Role returns the user's role in an organization, or ErrNotFound if they
// are not a member.
func (a *Auth) Role(ctx context.Context, userID, orgID string) (role string, err error) {
	if !isUUID(userID) || !isUUID(orgID) {
		return "", ErrNotFound
	}
	err = a.inTx(ctx, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, "SELECT role FROM memberships WHERE user_id = $1 AND org_id = $2", userID, orgID).Scan(&role)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		return err
	})
	return role, err
}
