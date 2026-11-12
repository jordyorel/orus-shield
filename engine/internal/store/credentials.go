package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// Audit actions of test accounts. The secret is never in the details.
const (
	ActionCredentialSet     = "credential.set"     //nolint:gosec // G101: an audit action name, not a credential
	ActionCredentialRemoved = "credential.removed" //nolint:gosec // G101: as above
)

// Credential kinds.
const (
	CredentialHeader = "header"
	CredentialForm   = "form"
)

// Credential describes a target's test account, without its secret.
type Credential struct {
	TargetID      string
	Kind          string // CredentialHeader or CredentialForm
	HeaderName    string // header
	LoginURL      string // form
	Username      string // form
	UsernameField string // form, "" for the default
	PasswordField string // form, "" for the default
	CreatedAt     time.Time
	CreatedBy     string
}

// CredentialOwner is what a target's secret is sealed for (package seal):
// a sealed value copied onto another target does not open.
func CredentialOwner(targetID string) string { return "target-credential:" + targetID }

//nolint:gosec // G101: column names; the sealed secret is not among them
const credentialColumns = `target_id::text, kind, coalesce(header_name, ''), coalesce(login_url, ''), coalesce(username, ''),
	coalesce(username_field, ''), coalesce(password_field, ''), created_at, created_by`

func scanCredential(row pgx.Row) (*Credential, error) {
	var c Credential
	err := row.Scan(&c.TargetID, &c.Kind, &c.HeaderName, &c.LoginURL, &c.Username, &c.UsernameField, &c.PasswordField, &c.CreatedAt, &c.CreatedBy)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &c, nil
}

// Credential returns the test account of one of the organization's
// targets, nil when there is none. The secret is not readable here.
func (o *Org) Credential(ctx context.Context, targetID string) (*Credential, error) {
	if !isUUID(targetID) {
		return nil, nil
	}
	tx, err := o.begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("credential: %w", err)
	}
	defer tx.Rollback(ctx)
	c, err := scanCredential(tx.QueryRow(ctx, "SELECT "+credentialColumns+" FROM target_credentials WHERE org_id = $1 AND target_id = $2", o.orgID, targetID))
	if err != nil {
		return nil, fmt.Errorf("credential: %w", err)
	}
	return c, tx.Commit(ctx)
}

// SetCredential stores (or replaces) a target's test account with its
// sealed secret, audited without the secret.
func (o *Org) SetCredential(ctx context.Context, c Credential, sealed []byte, actor string) error {
	if !isUUID(c.TargetID) {
		return ErrNotFound
	}
	tx, err := o.begin(ctx)
	if err != nil {
		return fmt.Errorf("set credential: %w", err)
	}
	defer tx.Rollback(ctx)
	_, err = tx.Exec(ctx, `
		INSERT INTO target_credentials (target_id, org_id, kind, header_name, login_url, username, username_field, password_field, sealed_secret, created_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		ON CONFLICT (target_id) DO UPDATE SET kind = $3, header_name = $4, login_url = $5, username = $6,
			username_field = $7, password_field = $8, sealed_secret = $9, created_by = $10, created_at = now()`,
		c.TargetID, o.orgID, c.Kind, nullable(c.HeaderName), nullable(c.LoginURL), nullable(c.Username),
		nullable(c.UsernameField), nullable(c.PasswordField), sealed, actor)
	if err != nil {
		return fmt.Errorf("set credential: %w", foreignKeyNotFound(err))
	}
	var domain string
	if err := tx.QueryRow(ctx, "SELECT domain FROM targets WHERE id = $1", c.TargetID).Scan(&domain); err != nil {
		return fmt.Errorf("set credential: %w", err)
	}
	if err := appendAudit(ctx, tx, AuditEntry{
		OrgID: o.orgID, Actor: actor, Action: ActionCredentialSet, Target: domain,
		Details: map[string]any{"kind": c.Kind, "header_name": c.HeaderName, "login_url": c.LoginURL, "username": c.Username},
	}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// DeleteCredential removes a target's test account, audited. None is
// ErrNotFound.
func (o *Org) DeleteCredential(ctx context.Context, targetID, actor string) error {
	if !isUUID(targetID) {
		return ErrNotFound
	}
	tx, err := o.begin(ctx)
	if err != nil {
		return fmt.Errorf("delete credential: %w", err)
	}
	defer tx.Rollback(ctx)
	var domain string
	err = tx.QueryRow(ctx, `
		DELETE FROM target_credentials c USING targets t
		WHERE t.id = c.target_id AND c.org_id = $1 AND c.target_id = $2 RETURNING t.domain`, o.orgID, targetID).Scan(&domain)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("delete credential: %w", err)
	}
	if err := appendAudit(ctx, tx, AuditEntry{OrgID: o.orgID, Actor: actor, Action: ActionCredentialRemoved, Target: domain}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// TargetCredential returns a target's test account and its sealed secret
// for the worker (schema owner), nil when there is none.
func (s *Store) TargetCredential(ctx context.Context, targetID string) (*Credential, []byte, error) {
	if !isUUID(targetID) {
		return nil, nil, nil
	}
	var sealed []byte
	var c Credential
	err := s.pool.QueryRow(ctx, "SELECT "+credentialColumns+", sealed_secret FROM target_credentials WHERE target_id = $1", targetID).
		Scan(&c.TargetID, &c.Kind, &c.HeaderName, &c.LoginURL, &c.Username, &c.UsernameField, &c.PasswordField, &c.CreatedAt, &c.CreatedBy, &sealed)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, fmt.Errorf("target credential: %w", err)
	}
	return &c, sealed, nil
}
