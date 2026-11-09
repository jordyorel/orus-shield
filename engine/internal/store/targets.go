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

const targetColumns = `id::text, domain, verified_at, exclusions, rate_per_sec, created_at,
	coalesce(verify_token, ''), verify_token_expires_at, verify_checked_at`

func scanTarget(row pgx.Row) (Target, error) {
	var t Target
	err := row.Scan(&t.ID, &t.Domain, &t.VerifiedAt, &t.Exclusions, &t.RatePerSec, &t.CreatedAt,
		&t.VerifyToken, &t.VerifyTokenExpiresAt, &t.VerifyCheckedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Target{}, ErrNotFound
	}
	return t, err
}

// CreateTarget stores a new, unverified target. The domain is normalized
// first, so "Example.COM." and "example.com" are the same target.
func (s *Store) CreateTarget(ctx context.Context, nt NewTarget) (Target, error) {
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
	t, err := scanTarget(s.pool.QueryRow(ctx,
		`INSERT INTO targets (domain, exclusions, rate_per_sec) VALUES ($1, $2, $3)
		 RETURNING `+targetColumns,
		domain, exclusions, rate))
	if err != nil {
		return Target{}, fmt.Errorf("create target %s: %w", domain, err)
	}
	return t, nil
}

// GetTarget returns the target with the given ID, or ErrNotFound.
func (s *Store) GetTarget(ctx context.Context, id string) (Target, error) {
	t, err := scanTarget(s.pool.QueryRow(ctx, "SELECT "+targetColumns+" FROM targets WHERE id = $1", id))
	if err != nil {
		return Target{}, fmt.Errorf("get target %s: %w", id, err)
	}
	return t, nil
}

// TargetByDomain returns the target for domain, or ErrNotFound.
func (s *Store) TargetByDomain(ctx context.Context, domain string) (Target, error) {
	normalized, err := module.NormalizeDomain(domain)
	if err != nil {
		return Target{}, fmt.Errorf("get target: %w", err)
	}
	t, err := scanTarget(s.pool.QueryRow(ctx, "SELECT "+targetColumns+" FROM targets WHERE domain = $1", normalized))
	if err != nil {
		return Target{}, fmt.Errorf("get target %s: %w", normalized, err)
	}
	return t, nil
}
