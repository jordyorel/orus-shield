package store

import (
	"context"
	"errors"
	"fmt"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
)

// Scan statuses.
const (
	StatusQueued  = "queued"
	StatusRunning = "running"
	StatusDone    = "done"
	StatusFailed  = "failed"
)

// ErrLeaseLost means the worker no longer owns the scan: its lease expired
// and another worker claimed it (or it was already finished). The worker must
// drop its results.
var ErrLeaseLost = errors.New("scan lease lost")

// maxErrorChars bounds error messages stored with a scan. They can contain
// text from the target (rule 7).
const maxErrorChars = 2000

// Scan is one job in the queue.
type Scan struct {
	ID          string
	OrgID       string
	TargetID    string
	Domain      string
	Modules     []string
	RequestedBy string
	Status      string
	// Attempt is the number of times the scan was claimed. The worker that
	// holds attempt N must pass N back: it is the fencing token.
	Attempt    int
	Error      string
	CreatedAt  time.Time
	StartedAt  *time.Time
	FinishedAt *time.Time
	// NewFindings and FixedFindings are the findings this scan opened and
	// marked fixed. Set by ListScans and RecentScans for finished scans
	// only; nil elsewhere.
	NewFindings   *int
	FixedFindings *int
}

const scanColumns = `s.id::text, s.org_id::text, s.target_id::text, t.domain, s.modules, s.requested_by, s.status,
	s.attempts, coalesce(s.error, ''), s.created_at, s.started_at, s.finished_at`

func scanScan(row pgx.Row) (Scan, error) {
	var sc Scan
	err := row.Scan(&sc.ID, &sc.OrgID, &sc.TargetID, &sc.Domain, &sc.Modules, &sc.RequestedBy, &sc.Status,
		&sc.Attempt, &sc.Error, &sc.CreatedAt, &sc.StartedAt, &sc.FinishedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Scan{}, ErrNotFound
	}
	return sc, err
}

// EnqueueScan adds a scan of one of the organization's targets to the queue
// and records who requested it in the audit log, in the same transaction: a
// scan can never exist without its audit entry (security rule 4). A target of
// another organization is ErrNotFound.
//
// A scan of the target still waiting in the queue with at least these
// modules is reused instead: clicking "Revérifier" or "Marquer comme
// corrigé" twice must not queue the same work twice. The request is
// audited either way, with the scan that will answer it.
func (o *Org) EnqueueScan(ctx context.Context, targetID string, modules []string, requestedBy string) (Scan, error) {
	if len(modules) == 0 {
		return Scan{}, errors.New("enqueue scan: no modules")
	}
	if requestedBy == "" {
		return Scan{}, errors.New("enqueue scan: empty requester")
	}

	if !isUUID(targetID) {
		return Scan{}, fmt.Errorf("enqueue scan for target %s: %w", targetID, ErrNotFound)
	}
	tx, err := o.begin(ctx)
	if err != nil {
		return Scan{}, fmt.Errorf("enqueue scan: %w", err)
	}
	defer tx.Rollback(ctx)

	sc, err := scanScan(tx.QueryRow(ctx, `
		SELECT `+scanColumns+` FROM scans s JOIN targets t ON t.id = s.target_id
		WHERE s.org_id = $1 AND s.target_id = $2 AND s.status = 'queued' AND s.modules @> $3
		ORDER BY s.created_at LIMIT 1`, o.orgID, targetID, modules))
	reused := err == nil
	if errors.Is(err, ErrNotFound) { // nothing waiting: a new scan
		// The foreign key on (org_id, target_id) rejects a target of another
		// organization, exactly like a target that does not exist.
		sc, err = scanScan(tx.QueryRow(ctx, `
			WITH s AS (
				INSERT INTO scans (org_id, target_id, modules, requested_by) VALUES ($1, $2, $3, $4)
				RETURNING *
			)
			SELECT `+scanColumns+` FROM s JOIN targets t ON t.id = s.target_id`,
			o.orgID, targetID, modules, requestedBy))
	}
	if err != nil {
		return Scan{}, fmt.Errorf("enqueue scan for target %s: %w", targetID, foreignKeyNotFound(err))
	}
	if err := appendAudit(ctx, tx, AuditEntry{
		OrgID:   sc.OrgID,
		Actor:   requestedBy,
		Action:  ActionScanRequested,
		Target:  sc.Domain,
		Details: map[string]any{"scan_id": sc.ID, "modules": modules, "reused_queued_scan": reused},
	}); err != nil {
		return Scan{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Scan{}, fmt.Errorf("enqueue scan: %w", err)
	}
	return sc, nil
}

// ClaimScan gives the oldest available scan to the calling worker for the
// duration of lease. A scan is available when it is queued, or running with
// an expired lease (its worker crashed). ok is false when there is nothing
// to do.
//
// FOR UPDATE SKIP LOCKED lets many workers claim at the same time: each one
// skips rows another transaction is already claiming, so no scan is given
// twice and nobody waits.
//
// Scans whose lease expired after maxAttempts claims are marked failed
// instead of being retried forever.
func (s *Store) ClaimScan(ctx context.Context, workerID string, lease time.Duration, maxAttempts int) (sc Scan, ok bool, err error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Scan{}, false, fmt.Errorf("claim scan: %w", err)
	}
	defer tx.Rollback(ctx)

	// 1. Give up on scans that keep crashing their workers.
	rows, err := tx.Query(ctx, `
		UPDATE scans s SET status = 'failed', locked_until = NULL, finished_at = now(),
			error = format('abandoned after %s attempts', s.attempts)
		FROM targets t
		WHERE t.id = s.target_id AND s.status = 'running' AND s.locked_until < now() AND s.attempts >= $1
		RETURNING s.id::text, s.org_id::text, t.domain, s.attempts`, maxAttempts)
	if err != nil {
		return Scan{}, false, fmt.Errorf("claim scan: expire abandoned scans: %w", err)
	}
	type abandoned struct {
		id, orgID, domain string
		attempts          int
	}
	gaveUp, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (abandoned, error) {
		var a abandoned
		return a, r.Scan(&a.id, &a.orgID, &a.domain, &a.attempts)
	})
	if err != nil {
		return Scan{}, false, fmt.Errorf("claim scan: expire abandoned scans: %w", err)
	}
	for _, a := range gaveUp {
		if err := appendAudit(ctx, tx, AuditEntry{
			OrgID: a.orgID, Actor: "queue", Action: ActionScanFailed, Target: a.domain,
			Details: map[string]any{"scan_id": a.id, "reason": "abandoned", "attempts": a.attempts},
		}); err != nil {
			return Scan{}, false, err
		}
	}

	// 2. Claim the oldest available scan.
	sc, err = scanScan(tx.QueryRow(ctx, `
		WITH s AS (
			UPDATE scans SET status = 'running', attempts = attempts + 1,
				locked_until = now() + make_interval(secs => $1),
				started_at = coalesce(started_at, now())
			WHERE id = (
				SELECT id FROM scans
				WHERE (status = 'queued'
				   OR (status = 'running' AND locked_until < now() AND attempts < $2))
				  -- Internal networks are scanned by their agent, never here.
				  AND NOT EXISTS (SELECT 1 FROM agents a WHERE a.target_id = scans.target_id)
				ORDER BY created_at
				LIMIT 1
				FOR UPDATE SKIP LOCKED
			)
			RETURNING *
		)
		SELECT `+scanColumns+` FROM s JOIN targets t ON t.id = s.target_id`,
		lease.Seconds(), maxAttempts))
	if errors.Is(err, ErrNotFound) {
		return Scan{}, false, tx.Commit(ctx) // keep the abandoned-scan updates
	}
	if err != nil {
		return Scan{}, false, fmt.Errorf("claim scan: %w", err)
	}
	if err := appendAudit(ctx, tx, AuditEntry{
		OrgID: sc.OrgID, Actor: workerID, Action: ActionScanStarted, Target: sc.Domain,
		Details: map[string]any{"scan_id": sc.ID, "modules": sc.Modules, "attempt": sc.Attempt},
	}); err != nil {
		return Scan{}, false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Scan{}, false, fmt.Errorf("claim scan: %w", err)
	}
	return sc, true, nil
}

// ExtendLease renews the lease of a running scan. Long scans call it
// periodically (a heartbeat) so they are not taken over while still working.
func (s *Store) ExtendLease(ctx context.Context, scanID string, attempt int, lease time.Duration) error {
	tag, err := s.pool.Exec(ctx, `
		UPDATE scans SET locked_until = now() + make_interval(secs => $3)
		WHERE id = $1 AND attempts = $2 AND status = 'running'`,
		scanID, attempt, lease.Seconds())
	if err != nil {
		return fmt.Errorf("extend lease of scan %s: %w", scanID, err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("extend lease of scan %s: %w", scanID, ErrLeaseLost)
	}
	return nil
}

// FailScan marks a scan as failed, if the caller still owns it.
func (s *Store) FailScan(ctx context.Context, scanID string, attempt int, workerID, reason string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("fail scan %s: %w", scanID, err)
	}
	defer tx.Rollback(ctx)

	reason = truncateRunes(reason, maxErrorChars)
	var orgID, domain string
	err = tx.QueryRow(ctx, `
		UPDATE scans s SET status = 'failed', error = $3, locked_until = NULL, finished_at = now()
		FROM targets t
		WHERE t.id = s.target_id AND s.id = $1 AND s.attempts = $2 AND s.status = 'running'
		RETURNING s.org_id::text, t.domain`, scanID, attempt, reason).Scan(&orgID, &domain)
	if errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("fail scan %s: %w", scanID, ErrLeaseLost)
	}
	if err != nil {
		return fmt.Errorf("fail scan %s: %w", scanID, err)
	}
	if err := appendAudit(ctx, tx, AuditEntry{
		OrgID: orgID, Actor: workerID, Action: ActionScanFailed, Target: domain,
		Details: map[string]any{"scan_id": scanID, "attempt": attempt, "reason": reason},
	}); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("fail scan %s: %w", scanID, err)
	}
	return nil
}

// GetScan returns the organization's scan with the given ID, or
// ErrNotFound.
func (o *Org) GetScan(ctx context.Context, id string) (Scan, error) {
	if !isUUID(id) {
		return Scan{}, fmt.Errorf("get scan %s: %w", id, ErrNotFound)
	}
	tx, err := o.begin(ctx)
	if err != nil {
		return Scan{}, fmt.Errorf("get scan %s: %w", id, err)
	}
	defer tx.Rollback(ctx)
	sc, err := scanScan(tx.QueryRow(ctx,
		"SELECT "+scanColumns+" FROM scans s JOIN targets t ON t.id = s.target_id WHERE s.id = $1 AND s.org_id = $2",
		id, o.orgID))
	if err != nil {
		return Scan{}, fmt.Errorf("get scan %s: %w", id, err)
	}
	return sc, tx.Commit(ctx)
}

// foreignKeyNotFound turns "target does not exist" foreign key violations
// into ErrNotFound.
func foreignKeyNotFound(err error) error {
	var pgErr interface{ SQLState() string }
	if errors.As(err, &pgErr) && pgErr.SQLState() == "23503" { // foreign_key_violation
		return fmt.Errorf("%w: %w", ErrNotFound, err)
	}
	return err
}

// truncateRunes keeps at most max characters of s, cutting on a character
// boundary.
func truncateRunes(s string, max int) string {
	if utf8.RuneCountInString(s) <= max {
		return s
	}
	return string([]rune(s)[:max])
}
