package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// Audit actions of declared APIs.
const (
	ActionAPIAdded   = "api.added"
	ActionAPIRemoved = "api.removed"
)

// API kinds.
const (
	APIOpenAPI = "openapi"
	APIGraphQL = "graphql"
)

// API is an API a customer declared on one of their targets.
type API struct {
	ID        string
	TargetID  string
	Name      string
	Kind      string // APIOpenAPI or APIGraphQL
	BaseURL   string
	SpecURL   string // "" when none
	Spec      string // uploaded document, "" when none
	CreatedAt time.Time
	CreatedBy string
}

// NewAPI is what CreateAPI stores; the caller has validated it.
type NewAPI struct {
	Name, Kind, BaseURL, SpecURL, Spec string
}

const apiColumns = "id::text, target_id::text, name, kind, base_url, coalesce(spec_url, ''), coalesce(spec, ''), created_at, created_by"

func scanAPI(row pgx.CollectableRow) (API, error) {
	var a API
	err := row.Scan(&a.ID, &a.TargetID, &a.Name, &a.Kind, &a.BaseURL, &a.SpecURL, &a.Spec, &a.CreatedAt, &a.CreatedBy)
	return a, err
}

func nullable(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// ListAPIs returns the APIs declared on one of the organization's targets.
func (o *Org) ListAPIs(ctx context.Context, targetID string) ([]API, error) {
	if !isUUID(targetID) {
		return nil, nil
	}
	tx, err := o.begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("list apis: %w", err)
	}
	defer tx.Rollback(ctx)
	rows, err := tx.Query(ctx, "SELECT "+apiColumns+" FROM apis WHERE org_id = $1 AND target_id = $2 ORDER BY created_at", o.orgID, targetID)
	if err != nil {
		return nil, fmt.Errorf("list apis: %w", err)
	}
	out, err := pgx.CollectRows(rows, scanAPI)
	if err != nil {
		return nil, fmt.Errorf("list apis: %w", err)
	}
	return out, tx.Commit(ctx)
}

// CreateAPI declares an API on one of the organization's targets, audited.
// The same base URL twice is ErrExists; another organization's target is
// ErrNotFound.
func (o *Org) CreateAPI(ctx context.Context, targetID string, n NewAPI, actor string) (API, error) {
	if !isUUID(targetID) {
		return API{}, ErrNotFound
	}
	tx, err := o.begin(ctx)
	if err != nil {
		return API{}, fmt.Errorf("create api: %w", err)
	}
	defer tx.Rollback(ctx)
	rows, err := tx.Query(ctx, `
		INSERT INTO apis (org_id, target_id, name, kind, base_url, spec_url, spec, created_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING `+apiColumns,
		o.orgID, targetID, n.Name, n.Kind, n.BaseURL, nullable(n.SpecURL), nullable(n.Spec), actor)
	if err != nil {
		return API{}, fmt.Errorf("create api: %w", err)
	}
	a, err := pgx.CollectExactlyOneRow(rows, scanAPI)
	if err != nil {
		if isUniqueViolation(err) {
			return API{}, ErrExists
		}
		return API{}, fmt.Errorf("create api: %w", foreignKeyNotFound(err))
	}
	var domain string
	if err := tx.QueryRow(ctx, "SELECT domain FROM targets WHERE id = $1", targetID).Scan(&domain); err != nil {
		return API{}, fmt.Errorf("create api: %w", err)
	}
	if err := appendAudit(ctx, tx, AuditEntry{
		OrgID: o.orgID, Actor: actor, Action: ActionAPIAdded, Target: domain,
		Details: map[string]any{"api_id": a.ID, "name": a.Name, "kind": a.Kind, "base_url": a.BaseURL, "spec_url": a.SpecURL, "spec_uploaded": a.Spec != ""},
	}); err != nil {
		return API{}, err
	}
	return a, tx.Commit(ctx)
}

// DeleteAPI removes a declared API, audited. Unknown is ErrNotFound.
func (o *Org) DeleteAPI(ctx context.Context, targetID, apiID, actor string) error {
	if !isUUID(targetID) || !isUUID(apiID) {
		return ErrNotFound
	}
	tx, err := o.begin(ctx)
	if err != nil {
		return fmt.Errorf("delete api: %w", err)
	}
	defer tx.Rollback(ctx)
	var name, base, domain string
	err = tx.QueryRow(ctx, `
		DELETE FROM apis a USING targets t
		WHERE t.id = a.target_id AND a.org_id = $1 AND a.target_id = $2 AND a.id = $3
		RETURNING a.name, a.base_url, t.domain`, o.orgID, targetID, apiID).Scan(&name, &base, &domain)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("delete api: %w", err)
	}
	if err := appendAudit(ctx, tx, AuditEntry{
		OrgID: o.orgID, Actor: actor, Action: ActionAPIRemoved, Target: domain,
		Details: map[string]any{"api_id": apiID, "name": name, "base_url": base},
	}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// TargetAPIs returns a target's declared APIs for the worker (no
// row-level security).
func (s *Store) TargetAPIs(ctx context.Context, targetID string) ([]API, error) {
	if !isUUID(targetID) {
		return nil, nil
	}
	rows, err := s.pool.Query(ctx, "SELECT "+apiColumns+" FROM apis WHERE target_id = $1 ORDER BY created_at", targetID)
	if err != nil {
		return nil, fmt.Errorf("target apis: %w", err)
	}
	out, err := pgx.CollectRows(rows, scanAPI)
	if err != nil {
		return nil, fmt.Errorf("target apis: %w", err)
	}
	return out, nil
}
