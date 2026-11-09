package store

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// ListTargets returns the organization's targets, by domain.
func (o *Org) ListTargets(ctx context.Context) ([]Target, error) {
	tx, err := o.begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("list targets: %w", err)
	}
	defer tx.Rollback(ctx)
	rows, err := tx.Query(ctx, "SELECT "+targetColumns+" FROM targets WHERE org_id = $1 ORDER BY domain", o.orgID)
	if err != nil {
		return nil, fmt.Errorf("list targets: %w", err)
	}
	targets, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (Target, error) { return scanTarget(r) })
	if err != nil {
		return nil, fmt.Errorf("list targets: %w", err)
	}
	return targets, tx.Commit(ctx)
}

// ListScans returns the latest scans of one of the organization's targets,
// newest first, at most limit (1 to 100).
func (o *Org) ListScans(ctx context.Context, targetID string, limit int) ([]Scan, error) {
	if !isUUID(targetID) {
		return nil, nil
	}
	limit = min(max(limit, 1), 100)
	tx, err := o.begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("list scans: %w", err)
	}
	defer tx.Rollback(ctx)
	rows, err := tx.Query(ctx, "SELECT "+scanColumns+` FROM scans s JOIN targets t ON t.id = s.target_id
		WHERE s.org_id = $1 AND s.target_id = $2 ORDER BY s.created_at DESC, s.id DESC LIMIT $3`,
		o.orgID, targetID, limit)
	if err != nil {
		return nil, fmt.Errorf("list scans: %w", err)
	}
	scans, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (Scan, error) { return scanScan(r) })
	if err != nil {
		return nil, fmt.Errorf("list scans: %w", err)
	}
	return scans, tx.Commit(ctx)
}

// TargetSummary is one target as the overview shows it.
type TargetSummary struct {
	ID            string
	Domain        string
	Verified      bool
	LastScanAt    *time.Time     // last finished scan; nil if never
	OpenFindings  map[string]int // by severity
	PostureScore  *int           // latest snapshot; nil if none or no score
	CurrentAssets int
}

// Overview returns a summary of every target of the organization: the
// data of the attack surface screen's totals and priority actions.
func (o *Org) Overview(ctx context.Context) ([]TargetSummary, error) {
	tx, err := o.begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("overview: %w", err)
	}
	defer tx.Rollback(ctx)
	// One query, with correlated subqueries per target: fine for the tens
	// of targets an SME has; to revisit with aggregates if that grows.
	rows, err := tx.Query(ctx, `
		SELECT t.id::text, t.domain, t.verified_at IS NOT NULL,
			(SELECT max(s.finished_at) FROM scans s WHERE s.target_id = t.id AND s.status = 'done'),
			(SELECT coalesce(jsonb_object_agg(severity, n), '{}') FROM (
				SELECT f.severity, count(*) AS n FROM findings f
				WHERE f.target_id = t.id AND f.status = 'open' GROUP BY f.severity) AS c),
			(SELECT p.score FROM posture_snapshots p WHERE p.target_id = t.id ORDER BY p.at DESC, p.id DESC LIMIT 1),
			(SELECT count(*) FROM assets a WHERE a.target_id = t.id AND a.gone_at IS NULL)
		FROM targets t WHERE t.org_id = $1 ORDER BY t.domain`, o.orgID)
	if err != nil {
		return nil, fmt.Errorf("overview: %w", err)
	}
	summaries, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (TargetSummary, error) {
		var s TargetSummary
		err := r.Scan(&s.ID, &s.Domain, &s.Verified, &s.LastScanAt, &s.OpenFindings, &s.PostureScore, &s.CurrentAssets)
		return s, err
	})
	if err != nil {
		return nil, fmt.Errorf("overview: %w", err)
	}
	return summaries, tx.Commit(ctx)
}
