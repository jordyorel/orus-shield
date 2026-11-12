package store

import (
	"context"
	"fmt"
	"time"
)

// ActionDeepQuota is the audit action of a deep scan run as a standard one
// because the month's quota was used.
const ActionDeepQuota = "scan.deep_quota_reached"

// MarkScanDeep records that a scan runs with the deep profile (it counts
// against the month's quota). Fenced like every scan update: a worker
// whose lease was taken over gets ErrLeaseLost.
func (s *Store) MarkScanDeep(ctx context.Context, scanID string, attempt int) error {
	tag, err := s.pool.Exec(ctx, `
		UPDATE scans SET deep = true WHERE id = $1 AND attempts = $2 AND status = 'running'`, scanID, attempt)
	if err != nil {
		return fmt.Errorf("mark scan %s deep: %w", scanID, err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("mark scan %s deep: %w", scanID, ErrLeaseLost)
	}
	return nil
}

// DeepScansSince counts an organization's scans run with the deep profile
// since since, for the worker (no row-level security).
func (s *Store) DeepScansSince(ctx context.Context, orgID string, since time.Time) (int, error) {
	if !isUUID(orgID) {
		return 0, fmt.Errorf("deep scans of %s: %w", orgID, ErrNotFound)
	}
	var n int
	err := s.pool.QueryRow(ctx, `SELECT count(*) FROM scans WHERE org_id = $1 AND deep AND started_at >= $2`, orgID, since).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("deep scans of %s: %w", orgID, err)
	}
	return n, nil
}

// DeepScansSince counts the organization's deep scans since since.
func (o *Org) DeepScansSince(ctx context.Context, since time.Time) (int, error) {
	tx, err := o.begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("deep scans: %w", err)
	}
	defer tx.Rollback(ctx)
	var n int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM scans WHERE org_id = $1 AND deep AND started_at >= $2`, o.orgID, since).Scan(&n); err != nil {
		return 0, fmt.Errorf("deep scans: %w", err)
	}
	return n, tx.Commit(ctx)
}

// MonthStart is the first instant of t's calendar month, in UTC: deep scan
// quotas count per calendar month.
func MonthStart(t time.Time) time.Time {
	t = t.UTC()
	return time.Date(t.Year(), t.Month(), 1, 0, 0, 0, 0, time.UTC)
}
