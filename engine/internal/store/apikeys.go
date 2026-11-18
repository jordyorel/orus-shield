package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// API keys (migration 0031): an organization's own tools call the API with
// "Authorization: Bearer orus_…". The key is shown once at creation; the
// database keeps its SHA-256 only, and its first characters (Prefix) so
// the customer can tell keys apart.

// KeyPrefix starts every key, so a leaked one is recognizable (secret
// scanners, logs) and never mistaken for a session token.
const KeyPrefix = "orus_"

// Key scopes.
const (
	ScopeRead  = "read"  // read the organization's results
	ScopeWrite = "write" // also start scans and mark findings
)

// Audit actions of API keys.
const (
	ActionAPIKeyCreated = "api_key.created"
	ActionAPIKeyRevoked = "api_key.revoked"
)

// MaxAPIKeys bounds the active keys of one organization.
const MaxAPIKeys = 20

var (
	// ErrInvalidKey is a key that does not exist, was revoked or expired.
	// The API answers 401 without telling which.
	ErrInvalidKey = errors.New("invalid API key")
	// ErrTooManyKeys: the organization has MaxAPIKeys active keys.
	ErrTooManyKeys = errors.New("too many API keys")
	// ErrBadKeyRequest: a key's name or scope is not acceptable.
	ErrBadKeyRequest = errors.New("API key needs a name (80 characters at most) and a scope, read or write")
)

// APIKey is a key as the organization sees it: never the key itself.
type APIKey struct {
	ID         string
	Name       string
	Prefix     string
	Scope      string
	CreatedBy  string
	CreatedAt  time.Time
	ExpiresAt  *time.Time
	LastUsedAt *time.Time
	RevokedAt  *time.Time
}

// KeyAccess is what a presented key gives: its organization and scope.
type KeyAccess struct {
	KeyID, OrgID, Name, Scope string
}

const keyListColumns = "id::text, name, prefix, scope, created_by, created_at, expires_at, last_used_at, revoked_at"

func scanAPIKey(row pgx.CollectableRow) (APIKey, error) {
	var k APIKey
	err := row.Scan(&k.ID, &k.Name, &k.Prefix, &k.Scope, &k.CreatedBy, &k.CreatedAt, &k.ExpiresAt, &k.LastUsedAt, &k.RevokedAt)
	return k, err
}

// CreateAPIKey creates a key named name with scope, valid until expires
// (nil: until revoked), and returns it with the key itself, the only time
// it exists outside the caller's hands.
func (o *Org) CreateAPIKey(ctx context.Context, name, scope string, expires *time.Time, actor string) (APIKey, string, error) {
	name = strings.TrimSpace(name)
	if name == "" || len([]rune(name)) > 80 || strings.ContainsAny(name, "\x00\r\n\t") {
		return APIKey{}, "", ErrBadKeyRequest
	}
	if scope != ScopeRead && scope != ScopeWrite {
		return APIKey{}, "", ErrBadKeyRequest
	}
	token, _, err := newToken()
	if err != nil {
		return APIKey{}, "", err
	}
	key := KeyPrefix + token
	hash := tokenHash(key)
	tx, err := o.begin(ctx)
	if err != nil {
		return APIKey{}, "", fmt.Errorf("create API key: %w", err)
	}
	defer tx.Rollback(ctx)
	var active int
	if err := tx.QueryRow(ctx, "SELECT count(*) FROM api_keys WHERE revoked_at IS NULL AND (expires_at IS NULL OR expires_at > now())").Scan(&active); err != nil {
		return APIKey{}, "", fmt.Errorf("create API key: %w", err)
	}
	if active >= MaxAPIKeys {
		return APIKey{}, "", ErrTooManyKeys
	}
	rows, err := tx.Query(ctx, `INSERT INTO api_keys (org_id, name, prefix, token_hash, scope, created_by, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING `+keyListColumns,
		o.orgID, name, key[:12], hash, scope, actor, expires)
	if err != nil {
		return APIKey{}, "", fmt.Errorf("create API key: %w", err)
	}
	k, err := pgx.CollectExactlyOneRow(rows, scanAPIKey)
	if err != nil {
		return APIKey{}, "", fmt.Errorf("create API key: %w", err)
	}
	if err := appendAudit(ctx, tx, AuditEntry{OrgID: o.orgID, Actor: actor, Action: ActionAPIKeyCreated, Target: "api",
		Details: map[string]any{"key_id": k.ID, "name": name, "scope": scope}}); err != nil {
		return APIKey{}, "", err
	}
	if err := tx.Commit(ctx); err != nil {
		return APIKey{}, "", fmt.Errorf("create API key: %w", err)
	}
	return k, key, nil
}

// APIKeys lists the organization's keys, newest first, revoked ones
// included (they say who did what).
func (o *Org) APIKeys(ctx context.Context) ([]APIKey, error) {
	tx, err := o.begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("list API keys: %w", err)
	}
	defer tx.Rollback(ctx)
	rows, err := tx.Query(ctx, "SELECT "+keyListColumns+" FROM api_keys ORDER BY created_at DESC LIMIT 100")
	if err != nil {
		return nil, fmt.Errorf("list API keys: %w", err)
	}
	keys, err := pgx.CollectRows(rows, scanAPIKey)
	if err != nil {
		return nil, fmt.Errorf("list API keys: %w", err)
	}
	return keys, tx.Commit(ctx)
}

// RevokeAPIKey revokes a key at once. An unknown key, or one of another
// organization, is ErrNotFound.
func (o *Org) RevokeAPIKey(ctx context.Context, id, actor string) error {
	if !isUUID(id) {
		return ErrNotFound
	}
	tx, err := o.begin(ctx)
	if err != nil {
		return fmt.Errorf("revoke API key: %w", err)
	}
	defer tx.Rollback(ctx)
	var name string
	err = tx.QueryRow(ctx, "UPDATE api_keys SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL RETURNING name", id).Scan(&name)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("revoke API key: %w", err)
	}
	if err := appendAudit(ctx, tx, AuditEntry{OrgID: o.orgID, Actor: actor, Action: ActionAPIKeyRevoked, Target: "api",
		Details: map[string]any{"key_id": id, "name": name}}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// KeyAccess checks a presented key: it must exist, not be revoked or
// expired. It records the key's last use (at most once a minute, so a busy
// script does not write on every call).
func (a *Auth) KeyAccess(ctx context.Context, key string, now time.Time) (KeyAccess, error) {
	if !strings.HasPrefix(key, KeyPrefix) || len(key) > 200 {
		return KeyAccess{}, ErrInvalidKey
	}
	var k KeyAccess
	var expires, revoked *time.Time
	err := a.inTx(ctx, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, "SELECT id::text, org_id::text, name, scope, expires_at, revoked_at FROM api_keys WHERE token_hash = $1",
			tokenHash(key)).Scan(&k.KeyID, &k.OrgID, &k.Name, &k.Scope, &expires, &revoked)
		if err != nil {
			return err
		}
		if revoked != nil || (expires != nil && !expires.After(now)) {
			return ErrInvalidKey
		}
		_, err = tx.Exec(ctx, `UPDATE api_keys SET last_used_at = $2 WHERE id = $1
			AND (last_used_at IS NULL OR last_used_at < $2::timestamptz - interval '1 minute')`, k.KeyID, now)
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) || errors.Is(err, ErrInvalidKey) {
		return KeyAccess{}, ErrInvalidKey
	}
	if err != nil {
		return KeyAccess{}, fmt.Errorf("API key: %w", err)
	}
	return k, nil
}
