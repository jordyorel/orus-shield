package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/jordyorel/orus-shield/engine/internal/posture"
)

// PosturePoints returns what the organization's score trend since since
// needs: every snapshot from since on, plus each target's last snapshot
// before since (its value when the period starts). Points are oldest
// first; package posture pools them (posture.Series).
func (o *Org) PosturePoints(ctx context.Context, since time.Time) ([]posture.Point, error) {
	tx, err := o.begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("posture points: %w", err)
	}
	defer tx.Rollback(ctx)
	rows, err := tx.Query(ctx, `
		(SELECT target_id::text, at, details->'total' FROM posture_snapshots
		 WHERE org_id = $1 AND at >= $2)
		UNION ALL
		(SELECT DISTINCT ON (target_id) target_id::text, at, details->'total' FROM posture_snapshots
		 WHERE org_id = $1 AND at < $2
		 ORDER BY target_id, at DESC, id DESC)
		ORDER BY 2`, o.orgID, since)
	if err != nil {
		return nil, fmt.Errorf("posture points: %w", err)
	}
	points, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (posture.Point, error) {
		var p posture.Point
		var total []byte
		if err := r.Scan(&p.TargetID, &p.At, &total); err != nil {
			return p, err
		}
		return p, json.Unmarshal(total, &p.Total)
	})
	if err != nil {
		return nil, fmt.Errorf("posture points: %w", err)
	}
	return points, tx.Commit(ctx)
}

// Remediation summarizes the fixes of a period.
type Remediation struct {
	// Fixed counts the "fixed" events of the period. A finding fixed,
	// reopened and fixed again counts twice: two remediations.
	Fixed int
	// Mean is the average time from the finding's last opening (first seen
	// or reopened) to its fix. Zero when Fixed is zero.
	Mean time.Duration
}

// Remediation returns the organization's fixes observed in [since, until),
// from the finding history. A fix is observed by the first scan that no longer sees
// the finding, so the time includes the delay until that scan: it measures
// what the customer can see, not the minute the change was made.
func (o *Org) Remediation(ctx context.Context, since, until time.Time) (Remediation, error) {
	tx, err := o.begin(ctx)
	if err != nil {
		return Remediation{}, fmt.Errorf("remediation: %w", err)
	}
	defer tx.Rollback(ctx)
	// For each fix, the latest earlier event that (re)opened the same
	// finding. Events are ordered by id: two events of one finding never
	// share a transaction, so id order is the order of the changes.
	var r Remediation
	var seconds float64
	err = tx.QueryRow(ctx, `
		SELECT count(*), coalesce(avg(extract(epoch FROM fx.at - op.at)), 0)::float8
		FROM finding_events fx
		CROSS JOIN LATERAL (
			SELECT o.at FROM finding_events o
			WHERE o.org_id = fx.org_id AND o.target_id = fx.target_id AND o.finding_id = fx.finding_id
			  AND o.to_status = 'open' AND o.id < fx.id
			ORDER BY o.id DESC LIMIT 1) op
		WHERE fx.org_id = $1 AND fx.to_status = 'fixed' AND fx.at >= $2 AND fx.at < $3`,
		o.orgID, since, until).Scan(&r.Fixed, &seconds)
	if err != nil {
		return Remediation{}, fmt.Errorf("remediation: %w", err)
	}
	r.Mean = time.Duration(seconds * float64(time.Second))
	return r, tx.Commit(ctx)
}

// NewAssets counts the organization's current assets first observed since
// since: what the attack surface gained over a period.
func (o *Org) NewAssets(ctx context.Context, since time.Time) (int, error) {
	tx, err := o.begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("new assets: %w", err)
	}
	defer tx.Rollback(ctx)
	var n int
	if err := tx.QueryRow(ctx, `
		SELECT count(*) FROM assets
		WHERE org_id = $1 AND gone_at IS NULL AND first_seen >= $2`, o.orgID, since).Scan(&n); err != nil {
		return 0, fmt.Errorf("new assets: %w", err)
	}
	return n, tx.Commit(ctx)
}

// MonthCount is the findings opened and fixed in one calendar month (UTC).
type MonthCount struct {
	Month  time.Time // first day of the month, UTC
	Opened int       // first seen or reopened
	Fixed  int
}

// Trends returns, for the last months calendar months including the
// current one (1 to 24), how many findings were opened (first seen or
// reopened) and fixed, from the finding history. Every month is present,
// zero when nothing happened.
func (o *Org) Trends(ctx context.Context, months int, now time.Time) ([]MonthCount, error) {
	months = min(max(months, 1), 24)
	first := time.Date(now.UTC().Year(), now.UTC().Month(), 1, 0, 0, 0, 0, time.UTC).AddDate(0, -(months - 1), 0)
	tx, err := o.begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("trends: %w", err)
	}
	defer tx.Rollback(ctx)
	// Opened: first seen (no from_status) or reopened after a fix. A risk
	// acceptance withdrawn (accepted_risk -> open) is not a new finding.
	rows, err := tx.Query(ctx, `
		SELECT date_trunc('month', at AT TIME ZONE 'UTC'),
		       count(*) FILTER (WHERE to_status = 'open' AND (from_status IS NULL OR from_status = 'fixed')),
		       count(*) FILTER (WHERE to_status = 'fixed')
		FROM finding_events
		WHERE org_id = $1 AND at >= $2
		GROUP BY 1`, o.orgID, first)
	if err != nil {
		return nil, fmt.Errorf("trends: %w", err)
	}
	defer rows.Close()
	byMonth := map[time.Time]MonthCount{}
	for rows.Next() {
		var c MonthCount
		if err := rows.Scan(&c.Month, &c.Opened, &c.Fixed); err != nil {
			return nil, fmt.Errorf("trends: %w", err)
		}
		c.Month = c.Month.UTC()
		byMonth[c.Month] = c
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("trends: %w", err)
	}
	out := make([]MonthCount, 0, months)
	for i := range months {
		m := first.AddDate(0, i, 0)
		c := byMonth[m]
		c.Month = m
		out = append(out, c)
	}
	return out, tx.Commit(ctx)
}
