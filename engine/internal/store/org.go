package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Tenant isolation
//
// Every row belongs to one organization (a customer). Two independent layers
// keep organizations apart:
//
//  1. In Go, API code only gets an *Org (from Store.Org). Every query an Org
//     runs filters on its org_id. Methods that work across organizations
//     (claiming scans, recording results) exist only on *Store, which only
//     the worker holds.
//  2. In PostgreSQL, every Org transaction switches to the orus_app role and
//     sets app.org_id. Row-level security policies (migration 0003) then
//     hide the rows of every other organization, so a query that forgot its
//     filter still cannot read or write them.
//
// Both layers must fail for data to leak between customers.

// appRole is the PostgreSQL role Org transactions run as. It is subject to
// row-level security and has only the privileges the API needs.
const appRole = "orus_app"

// ErrAmbiguous is returned when a name matches several organizations.
var ErrAmbiguous = errors.New("ambiguous name")

// ActionOrgCreated is the audit action for a new organization.
const ActionOrgCreated = "org.created"

// scope is what both *Store and *Org are built on: a pool, and the
// organization the caller is limited to.
//
// Methods defined on scope are shared: Go promotes them to both types
// (embedding). They are the ones both the worker and the API need, such as
// reading a target or recording a verification. Each one filters with
// orgParam and starts its transactions with begin, so the same code is
// unscoped for the worker and scoped for an Org.
type scope struct {
	pool *pgxpool.Pool
	// orgID is empty for the worker's *Store: every organization. An *Org
	// always has one (Store.Org rejects an empty ID).
	orgID string
}

// begin starts a transaction. For an organization it also switches to the
// orus_app role and sets app.org_id, which turns row-level security on for
// this transaction only (SET LOCAL and set_config(..., true) are undone at
// commit or rollback, so a pooled connection never carries them to the next
// caller).
func (sc scope) begin(ctx context.Context) (pgx.Tx, error) {
	tx, err := sc.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	if sc.orgID == "" {
		return tx, nil
	}
	// appRole is a constant: no injection possible. SET does not accept a
	// query parameter for the role name.
	if _, err := tx.Exec(ctx, "SET LOCAL ROLE "+appRole); err != nil {
		_ = tx.Rollback(ctx)
		return nil, fmt.Errorf("switch to role %s: %w", appRole, err)
	}
	if _, err := tx.Exec(ctx, "SELECT set_config('app.org_id', $1, true)", sc.orgID); err != nil {
		_ = tx.Rollback(ctx)
		return nil, fmt.Errorf("set organization: %w", err)
	}
	return tx, nil
}

// orgParam is the value for an organization filter written as
//
//	($n::uuid IS NULL OR org_id = $n::uuid)
//
// nil (SQL NULL) for the worker, which sees every organization; the org ID
// for an Org. Only scope methods use this form: Org-only methods compare
// org_id directly.
func (sc scope) orgParam() any {
	if sc.orgID == "" {
		return nil
	}
	return sc.orgID
}

// Org is the storage limited to one organization. It is what the API (and
// orusctl, until the API exists) works with. It is safe for concurrent use.
type Org struct {
	scope
}

// Org returns the handle for one organization. It does not check that the
// organization exists: a handle for an unknown ID sees nothing and cannot
// create anything (foreign keys).
func (s *Store) Org(orgID string) (*Org, error) {
	if !isUUID(orgID) {
		return nil, fmt.Errorf("organization id %q: %w", orgID, ErrNotFound)
	}
	return &Org{scope{pool: s.pool, orgID: orgID}}, nil
}

// ID returns the organization this handle is limited to.
func (o *Org) ID() string { return o.orgID }

// Organization is a customer.
type Organization struct {
	ID        string
	Name      string
	CreatedAt time.Time
}

const maxOrgNameChars = 200

// CreateOrganization stores a new organization and audits it.
func (s *Store) CreateOrganization(ctx context.Context, name, actor string) (Organization, error) {
	if name == "" || len([]rune(name)) > maxOrgNameChars {
		return Organization{}, fmt.Errorf("create organization: name must have 1 to %d characters", maxOrgNameChars)
	}
	tx, err := s.begin(ctx)
	if err != nil {
		return Organization{}, fmt.Errorf("create organization: %w", err)
	}
	defer tx.Rollback(ctx)

	var org Organization
	err = tx.QueryRow(ctx, "INSERT INTO organizations (name) VALUES ($1) RETURNING id::text, name, created_at",
		name).Scan(&org.ID, &org.Name, &org.CreatedAt)
	if err != nil {
		return Organization{}, fmt.Errorf("create organization: %w", err)
	}
	if err := appendAudit(ctx, tx, AuditEntry{
		OrgID: org.ID, Actor: actor, Action: ActionOrgCreated, Target: "",
		Details: map[string]any{"name": org.Name},
	}); err != nil {
		return Organization{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Organization{}, fmt.Errorf("create organization: %w", err)
	}
	return org, nil
}

// ListOrganizations returns every organization, oldest first.
func (s *Store) ListOrganizations(ctx context.Context) ([]Organization, error) {
	rows, err := s.pool.Query(ctx, "SELECT id::text, name, created_at FROM organizations ORDER BY created_at, id")
	if err != nil {
		return nil, fmt.Errorf("list organizations: %w", err)
	}
	orgs, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (Organization, error) {
		var o Organization
		return o, r.Scan(&o.ID, &o.Name, &o.CreatedAt)
	})
	if err != nil {
		return nil, fmt.Errorf("list organizations: %w", err)
	}
	return orgs, nil
}

// FindOrganization returns the organization whose ID or name is ref. A name
// shared by several organizations is ErrAmbiguous: use the ID then.
func (s *Store) FindOrganization(ctx context.Context, ref string) (Organization, error) {
	query := "SELECT id::text, name, created_at FROM organizations WHERE name = $1 ORDER BY id LIMIT 2"
	if isUUID(ref) {
		query = "SELECT id::text, name, created_at FROM organizations WHERE id = $1::uuid"
	}
	rows, err := s.pool.Query(ctx, query, ref)
	if err != nil {
		return Organization{}, fmt.Errorf("find organization %q: %w", ref, err)
	}
	orgs, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (Organization, error) {
		var o Organization
		return o, r.Scan(&o.ID, &o.Name, &o.CreatedAt)
	})
	if err != nil {
		return Organization{}, fmt.Errorf("find organization %q: %w", ref, err)
	}
	switch len(orgs) {
	case 0:
		return Organization{}, fmt.Errorf("find organization %q: %w", ref, ErrNotFound)
	case 1:
		return orgs[0], nil
	}
	return Organization{}, fmt.Errorf("find organization %q: %w: several organizations have this name, use the ID", ref, ErrAmbiguous)
}

// isUUID reports whether s is a UUID in its canonical text form
// (8-4-4-4-12 hexadecimal digits). Checking in Go avoids sending malformed
// IDs to PostgreSQL, which would answer with a cast error instead of "not
// found".
func isUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, c := range s {
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return false
			}
		default:
			if !('0' <= c && c <= '9' || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F') {
				return false
			}
		}
	}
	return true
}
