package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/jordyorel/orus-shield/engine/internal/module"
	"github.com/jordyorel/orus-shield/engine/internal/schedule"
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
	// Internal: an agent's internal network (step J), verified by the
	// agent's enrolment, scanned by the agent only.
	Internal bool

	// Schedule is nil when the target is only scanned on demand.
	Schedule *TargetSchedule
}

// TargetSchedule is a target's scheduled scan (migration 0010).
type TargetSchedule struct {
	schedule.Schedule
	// Modules run by each scheduled scan. The API checks them against the
	// catalog; the worker refuses unknown ones, like for any scan.
	Modules []string
	// NextScanAt is when the scheduler queues the next scan.
	NextScanAt time.Time
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
	coalesce(verify_token, ''), verify_token_expires_at, verify_checked_at,
	schedule_frequency, schedule_weekday, schedule_hour, schedule_timezone, schedule_modules, next_scan_at, internal`

func scanTarget(row pgx.Row) (Target, error) {
	var t Target
	var (
		frequency, timezone *string
		weekday, hour       *int16
		modules             []string
		next                *time.Time
	)
	err := row.Scan(&t.ID, &t.OrgID, &t.Domain, &t.VerifiedAt, &t.Exclusions, &t.RatePerSec, &t.CreatedAt,
		&t.VerifyToken, &t.VerifyTokenExpiresAt, &t.VerifyCheckedAt,
		&frequency, &weekday, &hour, &timezone, &modules, &next, &t.Internal)
	if errors.Is(err, pgx.ErrNoRows) {
		return Target{}, ErrNotFound
	}
	// The table constraint sets all schedule columns together.
	if err == nil && frequency != nil && weekday != nil && hour != nil && timezone != nil && next != nil {
		t.Schedule = &TargetSchedule{
			Schedule: schedule.Schedule{
				Frequency: schedule.Frequency(*frequency), Weekday: time.Weekday(*weekday),
				Hour: int(*hour), TimeZone: *timezone,
			},
			Modules: modules, NextScanAt: *next,
		}
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
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" { // unique_violation: domain already in this organization
		return Target{}, fmt.Errorf("create target %s: %w", domain, ErrExists)
	}
	if err != nil {
		return Target{}, fmt.Errorf("create target %s: %w", domain, err)
	}
	if err := tx.Commit(ctx); err != nil {
		return Target{}, fmt.Errorf("create target %s: %w", domain, err)
	}
	return t, nil
}

// TargetSettings are the scan settings of a target a customer may change.
// A nil field is left unchanged.
type TargetSettings struct {
	// Exclusions must already be valid for gate.ParseExclusions: the API
	// checks them with the worker's parser before calling.
	Exclusions json.RawMessage
	RatePerSec *float64 // > 0
	// Schedule replaces the target's schedule; the caller validates it and
	// computes NextScanAt. ClearSchedule removes it (on-demand scans only).
	Schedule      *TargetSchedule
	ClearSchedule bool
}

// UpdateTargetSettings changes a target's exclusions and rate and returns
// the target as stored. The worker reads them at the start of each scan,
// so a change applies from the next scan on. A target of another
// organization is ErrNotFound.
func (o *Org) UpdateTargetSettings(ctx context.Context, id string, ts TargetSettings) (Target, error) {
	if !isUUID(id) {
		return Target{}, fmt.Errorf("update target %s: %w", id, ErrNotFound)
	}
	if ts.RatePerSec != nil && *ts.RatePerSec <= 0 {
		return Target{}, fmt.Errorf("update target %s: rate must be positive", id)
	}
	if ts.Schedule != nil && ts.ClearSchedule {
		return Target{}, fmt.Errorf("update target %s: schedule set and cleared at once", id)
	}
	var exclusions any
	if ts.Exclusions != nil {
		exclusions = ts.Exclusions
	}
	var sched TargetSchedule
	if ts.Schedule != nil {
		if err := ts.Schedule.Validate(); err != nil {
			return Target{}, fmt.Errorf("update target %s: %w", id, err)
		}
		if len(ts.Schedule.Modules) == 0 || ts.Schedule.NextScanAt.IsZero() {
			return Target{}, fmt.Errorf("update target %s: schedule needs modules and a next scan time", id)
		}
		sched = *ts.Schedule
	}
	tx, err := o.begin(ctx)
	if err != nil {
		return Target{}, fmt.Errorf("update target %s: %w", id, err)
	}
	defer tx.Rollback(ctx)
	// $5 sets the schedule from $6..$11, $12 clears it, neither keeps it.
	t, err := scanTarget(tx.QueryRow(ctx, `
		UPDATE targets SET exclusions = coalesce($3::jsonb, exclusions), rate_per_sec = coalesce($4, rate_per_sec),
			schedule_frequency = CASE WHEN $5 THEN $6 WHEN $12 THEN NULL ELSE schedule_frequency END,
			schedule_weekday   = CASE WHEN $5 THEN $7 WHEN $12 THEN NULL ELSE schedule_weekday END,
			schedule_hour      = CASE WHEN $5 THEN $8 WHEN $12 THEN NULL ELSE schedule_hour END,
			schedule_timezone  = CASE WHEN $5 THEN $9 WHEN $12 THEN NULL ELSE schedule_timezone END,
			schedule_modules   = CASE WHEN $5 THEN $10::text[] WHEN $12 THEN NULL ELSE schedule_modules END,
			next_scan_at       = CASE WHEN $5 THEN $11::timestamptz WHEN $12 THEN NULL ELSE next_scan_at END
		WHERE id = $1 AND org_id = $2
		RETURNING `+targetColumns, id, o.orgID, exclusions, ts.RatePerSec,
		ts.Schedule != nil, string(sched.Frequency), int16(sched.Weekday), int16(sched.Hour), sched.TimeZone, //nolint:gosec // G115: Validate bounds weekday 0-6 and hour 0-23
		sched.Modules, sched.NextScanAt, ts.ClearSchedule))
	if err != nil {
		return Target{}, fmt.Errorf("update target %s: %w", id, err)
	}
	if err := tx.Commit(ctx); err != nil {
		return Target{}, fmt.Errorf("update target %s: %w", id, err)
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
