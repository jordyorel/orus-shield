package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// Audit actions of identity provider connections (step K).
const (
	ActionIdentityConnected    = "identity.connected"
	ActionIdentityDisconnected = "identity.disconnected"
)

// ProviderM365 is Microsoft 365, the only provider so far.
const ProviderM365 = "m365"

// ErrTenantInUse: the tenant is already connected to another domain of the
// organization.
var ErrTenantInUse = errors.New("this tenant is already connected to another domain")

// IdentityConnection is an identity provider connected to a domain. It
// holds no secret.
type IdentityConnection struct {
	TargetID    string
	Domain      string
	Provider    string
	TenantID    string
	TenantName  string
	Permissions []string
	ConnectedAt time.Time
	ConnectedBy string
}

const identityColumns = "c.target_id::text, t.domain, c.provider, c.tenant_id, c.tenant_name, c.permissions, c.connected_at, c.connected_by"

func scanIdentity(row pgx.CollectableRow) (IdentityConnection, error) {
	var c IdentityConnection
	err := row.Scan(&c.TargetID, &c.Domain, &c.Provider, &c.TenantID, &c.TenantName, &c.Permissions, &c.ConnectedAt, &c.ConnectedBy)
	return c, err
}

// IdentityConnections lists the organization's connections, by domain.
func (o *Org) IdentityConnections(ctx context.Context) ([]IdentityConnection, error) {
	tx, err := o.begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("identity connections: %w", err)
	}
	defer tx.Rollback(ctx)
	rows, err := tx.Query(ctx, "SELECT "+identityColumns+` FROM identity_connections c
		JOIN targets t ON t.id = c.target_id WHERE c.org_id = $1 ORDER BY t.domain, c.provider`, o.orgID)
	if err != nil {
		return nil, fmt.Errorf("identity connections: %w", err)
	}
	out, err := pgx.CollectRows(rows, scanIdentity)
	if err != nil {
		return nil, fmt.Errorf("identity connections: %w", err)
	}
	return out, tx.Commit(ctx)
}

// ConnectIdentity records (or replaces) a target's connection. The caller
// has checked the tenant (it manages the domain, read-only permissions).
func (o *Org) ConnectIdentity(ctx context.Context, c IdentityConnection, actor string) error {
	if !isUUID(c.TargetID) {
		return ErrNotFound
	}
	tx, err := o.begin(ctx)
	if err != nil {
		return fmt.Errorf("connect identity: %w", err)
	}
	defer tx.Rollback(ctx)
	var domain string
	err = tx.QueryRow(ctx, `
		INSERT INTO identity_connections (org_id, target_id, provider, tenant_id, tenant_name, permissions, connected_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (target_id, provider) DO UPDATE SET tenant_id = excluded.tenant_id, tenant_name = excluded.tenant_name,
			permissions = excluded.permissions, connected_at = now(), connected_by = excluded.connected_by
		RETURNING (SELECT domain FROM targets WHERE id = $2)`,
		o.orgID, c.TargetID, c.Provider, c.TenantID, c.TenantName, c.Permissions, actor).Scan(&domain)
	if err != nil {
		if isUniqueViolation(err) {
			return ErrTenantInUse
		}
		return fmt.Errorf("connect identity: %w", foreignKeyNotFound(err))
	}
	if err := appendAudit(ctx, tx, AuditEntry{
		OrgID: o.orgID, Actor: actor, Action: ActionIdentityConnected, Target: domain,
		Details: map[string]any{"provider": c.Provider, "tenant_id": c.TenantID, "tenant_name": c.TenantName, "permissions": c.Permissions},
	}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// DisconnectIdentity removes a target's connection. Its findings keep their
// state: the worker no longer runs the module on the target, so nothing
// marks them fixed without a scan having seen them gone.
func (o *Org) DisconnectIdentity(ctx context.Context, targetID, provider, actor string) error {
	if !isUUID(targetID) {
		return ErrNotFound
	}
	tx, err := o.begin(ctx)
	if err != nil {
		return fmt.Errorf("disconnect identity: %w", err)
	}
	defer tx.Rollback(ctx)
	var domain, tenant string
	err = tx.QueryRow(ctx, `
		DELETE FROM identity_connections c USING targets t
		WHERE t.id = c.target_id AND c.org_id = $1 AND c.target_id = $2 AND c.provider = $3
		RETURNING t.domain, c.tenant_id`, o.orgID, targetID, provider).Scan(&domain, &tenant)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("disconnect identity: %w", err)
	}
	if err := appendAudit(ctx, tx, AuditEntry{
		OrgID: o.orgID, Actor: actor, Action: ActionIdentityDisconnected, Target: domain,
		Details: map[string]any{"provider": provider, "tenant_id": tenant},
	}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// TargetIdentity returns a target's connection to provider for the worker
// (no row-level security), nil when there is none.
func (s *Store) TargetIdentity(ctx context.Context, targetID, provider string) (*IdentityConnection, error) {
	if !isUUID(targetID) {
		return nil, nil
	}
	rows, err := s.pool.Query(ctx, "SELECT "+identityColumns+` FROM identity_connections c
		JOIN targets t ON t.id = c.target_id WHERE c.target_id = $1 AND c.provider = $2`, targetID, provider)
	if err != nil {
		return nil, fmt.Errorf("target identity: %w", err)
	}
	c, err := pgx.CollectExactlyOneRow(rows, scanIdentity)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("target identity: %w", err)
	}
	return &c, nil
}
