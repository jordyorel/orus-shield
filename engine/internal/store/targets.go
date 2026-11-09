package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/jordyorel/orus-shield/engine/internal/module"
)

// DefaultRatePerSec is the outbound request rate of a new target.
const DefaultRatePerSec = 5

// Target is a domain a customer asked us to scan.
type Target struct {
	ID         string
	OrgID      string // the organization that owns it
	Domain     string
	VerifiedAt *time.Time // nil: ownership not verified
	// Exclusions is kept as raw JSON here; the gate package parses and
	// validates it. The store does not interpret it.
	Exclusions json.RawMessage
	RatePerSec float64
	CreatedAt  time.Time

	// Ownership verification (see package ownership). VerifyToken is empty
	// until one is issued.
	VerifyToken          string
	VerifyTokenExpiresAt *time.Time // deadline to publish it; nil once verified
	VerifyCheckedAt      *time.Time // last successful check of the record
}

// Verified reports whether ownership of the target has been proven.
func (t Target) Verified() bool { return t.VerifiedAt != nil }

// NewTarget holds the fields needed to create a target.
type NewTarget struct {
	Domain     string
	Exclusions json.RawMessage // empty: no exclusions
	RatePerSec float64         // 0: DefaultRatePerSec
}

const targetColumns = `id::text, org_id::text, domain, verified_at, exclusions, rate_per_sec, created_at,
	coalesce(verify_token, ''), verify_token_expires_at, verify_checked_at`

func scanTarget(row pgx.Row) (Target, error) {
	var t Target
	err := row.Scan(&t.ID, &t.OrgID, &t.Domain, &t.VerifiedAt, &t.Exclusions, &t.RatePerSec, &t.CreatedAt,
		&t.VerifyToken, &t.VerifyTokenExpiresAt, &t.VerifyCheckedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Target{}, ErrNotFound
	}
	return t, err
}

// CreateTarget stores a new, unverified target in the organization. The
// domain is normalized first, so "Example.COM." and "example.com" are the
// same target. Another organization may have the same domain.
func (o *Org) CreateTarget(ctx context.Context, nt NewTarget) (Target, error) {
	domain, err := module.NormalizeDomain(nt.Domain)
	if err != nil {
		return Target{}, fmt.Errorf("create target: %w", err)
	}
	exclusions := nt.Exclusions
	if len(exclusions) == 0 {
		exclusions = json.RawMessage("{}")
	}
	rate := nt.RatePerSec
	if rate == 0 {
		rate = DefaultRatePerSec
	}
	tx, err := o.begin(ctx)
	if err != nil {
		return Target{}, fmt.Errorf("create target %s: %w", domain, err)
	}
	defer tx.Rollback(ctx)
	t, err := scanTarget(tx.QueryRow(ctx,
		`INSERT INTO targets (org_id, domain, exclusions, rate_per_sec) VALUES ($1, $2, $3, $4)
		 RETURNING `+targetColumns,
		o.orgID, domain, exclusions, rate))
	if err != nil {
		return Target{}, fmt.Errorf("create target %s: %w", domain, err)
	}
	if err := tx.Commit(ctx); err != nil {
		return Target{}, fmt.Errorf("create target %s: %w", domain, err)
	}
	return t, nil
}

// GetTarget returns the target with the given ID, or ErrNotFound. Through an
// Org, a target of another organization is ErrNotFound too: the caller
// cannot tell it exists.
func (sc scope) GetTarget(ctx context.Context, id string) (Target, error) {
	if !isUUID(id) {
		return Target{}, fmt.Errorf("get target %s: %w", id, ErrNotFound)
	}
	tx, err := sc.begin(ctx)
	if err != nil {
		return Target{}, fmt.Errorf("get target %s: %w", id, err)
	}
	defer tx.Rollback(ctx)
	t, err := scanTarget(tx.QueryRow(ctx,
		"SELECT "+targetColumns+" FROM targets WHERE id = $1 AND ($2::uuid IS NULL OR org_id = $2::uuid)",
		id, sc.orgParam()))
	if err != nil {
		return Target{}, fmt.Errorf("get target %s: %w", id, err)
	}
	return t, tx.Commit(ctx)
}

// TargetByDomain returns the organization's target for domain, or
// ErrNotFound.
func (o *Org) TargetByDomain(ctx context.Context, domain string) (Target, error) {
	normalized, err := module.NormalizeDomain(domain)
	if err != nil {
		return Target{}, fmt.Errorf("get target: %w", err)
	}
	tx, err := o.begin(ctx)
	if err != nil {
		return Target{}, fmt.Errorf("get target %s: %w", normalized, err)
	}
	defer tx.Rollback(ctx)
	t, err := scanTarget(tx.QueryRow(ctx,
		"SELECT "+targetColumns+" FROM targets WHERE org_id = $1 AND domain = $2", o.orgID, normalized))
	if err != nil {
		return Target{}, fmt.Errorf("get target %s: %w", normalized, err)
	}
	return t, tx.Commit(ctx)
}
