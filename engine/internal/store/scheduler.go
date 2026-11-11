package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// ActorScheduler is who requested a scheduled scan, in scans and in the
// audit log (rule 4: every scan records who started it).
const ActorScheduler = "scheduler"

// EnqueueDueScans queues one scan for each target whose next_scan_at has
// passed, at most limit targets per call, and moves next_scan_at to the
// following run (schedule.Next from now). It returns the number of scans
// queued.
//
// Several workers may call it at the same time: FOR UPDATE SKIP LOCKED gives
// each due target to one of them only, and next_scan_at moves in the same
// transaction as the insert, so a slot is never queued twice.
//
// A target that still has a queued or running scan gets no new one: a slow
// scan must not pile up behind itself. Its next_scan_at moves on anyway.
// Each scheduled scan has its scan.requested audit entry, like any other.
func (s *Store) EnqueueDueScans(ctx context.Context, now time.Time, limit int) (int, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("enqueue due scans: %w", err)
	}
	defer tx.Rollback(ctx)

	rows, err := tx.Query(ctx, `
		SELECT `+targetColumns+` FROM targets
		WHERE next_scan_at <= $1
		ORDER BY next_scan_at
		LIMIT $2
		FOR UPDATE SKIP LOCKED`, now, limit)
	if err != nil {
		return 0, fmt.Errorf("enqueue due scans: %w", err)
	}
	due, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (Target, error) { return scanTarget(row) })
	if err != nil {
		return 0, fmt.Errorf("enqueue due scans: %w", err)
	}

	queued := 0
	var errs []error
	for _, t := range due {
		if t.Schedule == nil {
			continue // cannot happen: next_scan_at implies a schedule
		}
		next, err := t.Schedule.Next(now)
		if err != nil {
			// Validated when saved; a time zone removed from the database
			// later would land here. Retry in a day rather than every
			// minute, and say so.
			errs = append(errs, fmt.Errorf("target %s: %w", t.ID, err))
			next = now.Add(24 * time.Hour)
		}
		if _, err := tx.Exec(ctx, `UPDATE targets SET next_scan_at = $2 WHERE id = $1`, t.ID, next); err != nil {
			return 0, fmt.Errorf("enqueue due scans: target %s: %w", t.ID, err)
		}

		var busy bool
		if err := tx.QueryRow(ctx, `
			SELECT EXISTS (SELECT 1 FROM scans WHERE target_id = $1 AND status IN ('queued', 'running'))`,
			t.ID).Scan(&busy); err != nil {
			return 0, fmt.Errorf("enqueue due scans: target %s: %w", t.ID, err)
		}
		if busy {
			continue
		}
		var scanID string
		if err := tx.QueryRow(ctx, `
			INSERT INTO scans (org_id, target_id, modules, requested_by) VALUES ($1, $2, $3, $4)
			RETURNING id::text`, t.OrgID, t.ID, t.Schedule.Modules, ActorScheduler).Scan(&scanID); err != nil {
			return 0, fmt.Errorf("enqueue due scans: target %s: %w", t.ID, err)
		}
		if err := appendAudit(ctx, tx, AuditEntry{
			OrgID: t.OrgID, Actor: ActorScheduler, Action: ActionScanRequested, Target: t.Domain,
			Details: map[string]any{
				"scan_id": scanID, "modules": t.Schedule.Modules, "scheduled": true,
				"frequency": t.Schedule.Frequency, "next_scan_at": next,
			},
		}); err != nil {
			return 0, err
		}
		queued++
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("enqueue due scans: %w", err)
	}
	return queued, errors.Join(errs...)
}
