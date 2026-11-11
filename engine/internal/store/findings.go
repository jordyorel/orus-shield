package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/jordyorel/orus-shield/engine/internal/asset"
	"github.com/jordyorel/orus-shield/engine/internal/finding"
	"github.com/jordyorel/orus-shield/engine/internal/module"
)

// Audit action for manual status changes.
const ActionFindingStatus = "finding.status_changed"

// ScanResult is what a worker reports when it has run every module of a scan.
type ScanResult struct {
	ScanID   string
	Attempt  int // fencing token from ClaimScan
	WorkerID string
	At       time.Time // when the results were observed
	// Succeeded lists the modules that ran to completion. Only their open
	// findings that were not seen again are marked fixed: a module that
	// failed tells us nothing about whether its findings still exist.
	Succeeded []string
	Failed    map[string]string // module ID -> error message
	// Findings come from the succeeded modules. The store sets FirstSeen,
	// LastSeen and Status, then validates them.
	Findings []finding.Finding
	// Assets observed, by module ID. Only succeeded modules may report
	// assets; a succeeded module absent from the map reported none.
	Assets map[string][]asset.Asset
	// Checks are the catalog outcomes of the succeeded modules, by module
	// ID (module.Evaluate). They update check_status and the posture.
	Checks map[string][]module.CheckOutcome
	// Unobserved reports whether something was out of reach in this scan:
	// covered by a customer exclusion, or an IP whose ownership could not be
	// verified. value is a finding's asset (kind "") or an inventory asset.
	// A module skips such destinations, so their absence from its output
	// proves nothing: their open findings are not marked fixed and their
	// assets are not retired; both keep their last_seen. nil: everything
	// was in reach.
	Unobserved func(kind asset.Kind, value string) bool
}

// FinishScan records a scan's results in one transaction: the scan is marked
// done, findings are created or updated, findings that disappeared are marked
// fixed, and the audit log gets an entry. If the worker lost its lease,
// nothing is written and ErrLeaseLost is returned.
//
// Lifecycle rules:
//   - new finding: open, first_seen = last_seen = At;
//   - seen again: last_seen = At, first_seen kept; fixed becomes open again
//     (a regression) and loses its fixed_at;
//   - open and not seen again by a module that succeeded: fixed, with
//     fixed_at = At, unless its asset was out of reach (r.Unobserved):
//     then it is left unchanged;
//   - accepted_risk is the customer's decision and is never changed here.
//
// Findings it opens or reopens that are Alertable are queued as email
// notifications to the organization's admins (notifications table), in the
// same transaction.
//
// Every status change (opened, fixed, reopened) is also recorded in
// finding_events, in the same transaction, for remediation history. The
// asset inventory is updated in the same transaction too (see saveAssets).
func (s *Store) FinishScan(ctx context.Context, r ScanResult) error {
	// PostgreSQL stores microseconds. Rounding here keeps the columns and
	// the JSON copy identical.
	at := r.At.UTC().Truncate(time.Microsecond)

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("finish scan %s: %w", r.ScanID, err)
	}
	defer tx.Rollback(ctx)

	var orgID, targetID, domain string
	err = tx.QueryRow(ctx, `
		UPDATE scans s SET status = 'done', error = nullif($3, ''), locked_until = NULL, finished_at = now()
		FROM targets t
		WHERE t.id = s.target_id AND s.id = $1 AND s.attempts = $2 AND s.status = 'running'
		RETURNING s.org_id::text, s.target_id::text, t.domain`,
		r.ScanID, r.Attempt, truncateRunes(failureSummary(r.Failed), maxErrorChars)).Scan(&orgID, &targetID, &domain)
	if errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("finish scan %s: %w", r.ScanID, ErrLeaseLost)
	}
	if err != nil {
		return fmt.Errorf("finish scan %s: %w", r.ScanID, err)
	}

	seen := make([]string, 0, len(r.Findings))
	created, reopened := 0, 0
	var alerts []AlertFinding // opened or reopened by this scan, worth an email
	for _, f := range r.Findings {
		f.FirstSeen, f.LastSeen, f.Status = at, at, finding.StatusOpen
		if err := f.Validate(); err != nil {
			return fmt.Errorf("finish scan %s: finding %s: %w", r.ScanID, f.ID, err)
		}
		if f.Target != domain {
			return fmt.Errorf("finish scan %s: finding %s is for %q, scan is for %q", r.ScanID, f.ID, f.Target, domain)
		}
		data, err := json.Marshal(f)
		if err != nil {
			return fmt.Errorf("finish scan %s: encode finding %s: %w", r.ScanID, f.ID, err)
		}
		// RETURNING old.status (PostgreSQL 18) gives the status before this
		// statement: NULL for a new row. That is all we need to know which
		// event happened. data comes from f, whose FixedAt is nil, so a
		// reopened finding's JSON loses fixed_at like its column.
		var previous *string
		err = tx.QueryRow(ctx, `
			INSERT INTO findings AS f (org_id, target_id, id, module_id, check_id, severity, status, first_seen, last_seen, data)
			VALUES ($8, $1, $2, $3, $4, $5, 'open', $6, $6, $7)
			ON CONFLICT (target_id, id) DO UPDATE SET
				severity  = EXCLUDED.severity,
				last_seen = EXCLUDED.last_seen,
				status    = CASE WHEN f.status = 'accepted_risk' THEN 'accepted_risk' ELSE 'open' END,
				fixed_at  = NULL,
				-- The JSON copy gets the lifecycle fields from the row, so
				-- both always agree.
				data = EXCLUDED.data || jsonb_build_object(
					'first_seen', f.first_seen,
					'status', CASE WHEN f.status = 'accepted_risk' THEN 'accepted_risk' ELSE 'open' END)
			RETURNING old.status`,
			targetID, f.ID, f.ModuleID, f.CheckID, string(f.Severity), at, data, orgID).Scan(&previous)
		if err != nil {
			return fmt.Errorf("finish scan %s: save finding %s: %w", r.ScanID, f.ID, err)
		}
		if (previous == nil || *previous == string(finding.StatusFixed)) && Alertable(f) {
			alerts = append(alerts, AlertFinding{ID: f.ID, Title: f.Title, Asset: f.Asset, Severity: f.Severity, Reopened: previous != nil})
		}
		switch {
		case previous == nil:
			created++
			err = recordEvent(ctx, tx, FindingEvent{OrgID: orgID, TargetID: targetID, FindingID: f.ID, At: at,
				To: finding.StatusOpen, Actor: r.WorkerID, ScanID: r.ScanID})
		case *previous == string(finding.StatusFixed):
			reopened++
			err = recordEvent(ctx, tx, FindingEvent{OrgID: orgID, TargetID: targetID, FindingID: f.ID, At: at,
				From: finding.StatusFixed, To: finding.StatusOpen, Actor: r.WorkerID, ScanID: r.ScanID})
		}
		if err != nil {
			return fmt.Errorf("finish scan %s: finding %s: %w", r.ScanID, f.ID, err)
		}
		seen = append(seen, f.ID)
	}

	var fixed int64
	unobserved := 0
	if len(r.Succeeded) > 0 && r.Unobserved != nil {
		kept, err := unobservedFindings(ctx, tx, targetID, r, seen)
		if err != nil {
			return fmt.Errorf("finish scan %s: %w", r.ScanID, err)
		}
		// Treated like findings seen again by the UPDATE below, without
		// touching their row: last_seen stays the last real observation.
		unobserved = len(kept)
		seen = append(seen, kept...)
	}
	if len(r.Succeeded) > 0 {
		// One statement marks the findings fixed and records one event per
		// finding, from the rows the UPDATE returns.
		tag, err := tx.Exec(ctx, `
			WITH fixed AS (
				UPDATE findings SET status = 'fixed', fixed_at = $4,
					data = data || jsonb_build_object('status', 'fixed', 'fixed_at', $4::timestamptz)
				WHERE target_id = $1 AND status = 'open' AND module_id = ANY($2) AND NOT (id = ANY($3))
				RETURNING org_id, target_id, id
			)
			INSERT INTO finding_events (org_id, target_id, finding_id, at, from_status, to_status, actor, scan_id)
			SELECT org_id, target_id, id, $4, 'open', 'fixed', $5, $6 FROM fixed`,
			targetID, r.Succeeded, seen, at, r.WorkerID, r.ScanID)
		if err != nil {
			return fmt.Errorf("finish scan %s: mark fixed findings: %w", r.ScanID, err)
		}
		fixed = tag.RowsAffected()
	}

	assets, err := saveAssets(ctx, tx, orgID, targetID, domain, at, r)
	if err != nil {
		return fmt.Errorf("finish scan %s: %w", r.ScanID, err)
	}
	score, err := saveChecks(ctx, tx, orgID, targetID, r.ScanID, at, r)
	if err != nil {
		return fmt.Errorf("finish scan %s: %w", r.ScanID, err)
	}
	// Same transaction: the alerts exist if and only if the results do.
	notified, err := queueAlerts(ctx, tx, orgID, targetID, r.ScanID, domain, alerts)
	if err != nil {
		return fmt.Errorf("finish scan %s: %w", r.ScanID, err)
	}

	// Empty lists, not null, so the audit JSON has one shape.
	succeeded := append([]string{}, r.Succeeded...)
	failed := append([]string{}, slices.Sorted(maps.Keys(r.Failed))...)
	if err := appendAudit(ctx, tx, AuditEntry{
		OrgID: orgID, Actor: r.WorkerID, Action: ActionScanFinished, Target: domain,
		Details: map[string]any{
			"scan_id": r.ScanID, "attempt": r.Attempt,
			"succeeded": succeeded, "failed": failed,
			"findings": len(r.Findings), "new": created, "fixed": fixed, "reopened": reopened,
			"unobserved": unobserved, "alerts": len(alerts), "notified": notified,
			"assets": assets.reported, "assets_new": assets.created, "assets_back": assets.back, "assets_gone": assets.gone,
			"assets_unobserved": assets.unobserved,
			"score":             score,
		},
	}); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("finish scan %s: %w", r.ScanID, err)
	}
	return nil
}

// unobservedFindings returns the open findings of the succeeded modules that
// were not seen again and whose asset was out of reach in this scan.
func unobservedFindings(ctx context.Context, tx pgx.Tx, targetID string, r ScanResult, seen []string) ([]string, error) {
	rows, err := tx.Query(ctx, `
		SELECT id, data->>'asset' FROM findings
		WHERE target_id = $1 AND status = 'open' AND module_id = ANY($2) AND NOT (id = ANY($3))`,
		targetID, r.Succeeded, seen)
	if err != nil {
		return nil, fmt.Errorf("list findings not seen again: %w", err)
	}
	type candidate struct{ id, asset string }
	candidates, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (candidate, error) {
		var c candidate
		err := row.Scan(&c.id, &c.asset)
		return c, err
	})
	if err != nil {
		return nil, fmt.Errorf("list findings not seen again: %w", err)
	}
	var kept []string
	for _, c := range candidates {
		if r.Unobserved("", c.asset) {
			kept = append(kept, c.id)
		}
	}
	return kept, nil
}

// failureSummary turns module errors into one message, in module order.
func failureSummary(failed map[string]string) string {
	var parts []string
	for _, id := range slices.Sorted(maps.Keys(failed)) {
		parts = append(parts, id+": "+failed[id])
	}
	return strings.Join(parts, "; ")
}

// ListFindings returns every finding of one of the organization's targets,
// most severe first. A target of another organization has no findings.
func (o *Org) ListFindings(ctx context.Context, targetID string) ([]finding.Finding, error) {
	if !isUUID(targetID) {
		return nil, nil
	}
	tx, err := o.begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("list findings: %w", err)
	}
	defer tx.Rollback(ctx)
	rows, err := tx.Query(ctx, `
		SELECT data FROM findings WHERE org_id = $1 AND target_id = $2
		ORDER BY array_position(ARRAY['critical','high','medium','low','info'], severity), first_seen, id`,
		o.orgID, targetID)
	if err != nil {
		return nil, fmt.Errorf("list findings: %w", err)
	}
	findings, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (finding.Finding, error) {
		var data []byte
		if err := row.Scan(&data); err != nil {
			return finding.Finding{}, err
		}
		var f finding.Finding
		err := json.Unmarshal(data, &f)
		return f, err
	})
	if err != nil {
		return nil, fmt.Errorf("list findings: %w", err)
	}
	return findings, tx.Commit(ctx)
}

// SetFindingStatus records a customer decision: accepted_risk, or open to
// undo it. "fixed" is set by scans only, never by hand.
func (o *Org) SetFindingStatus(ctx context.Context, targetID, findingID string, status finding.Status, actor string) error {
	if status != finding.StatusAcceptedRisk && status != finding.StatusOpen {
		return fmt.Errorf("set finding status: %q cannot be set manually", status)
	}
	if !isUUID(targetID) {
		return fmt.Errorf("set finding status %s: %w", findingID, ErrNotFound)
	}
	tx, err := o.begin(ctx)
	if err != nil {
		return fmt.Errorf("set finding status: %w", err)
	}
	defer tx.Rollback(ctx)

	// A fixed finding whose risk is accepted is no longer fixed: fixed_at
	// is cleared, in the column and in the JSON copy.
	var domain, previous string
	var at time.Time
	err = tx.QueryRow(ctx, `
		UPDATE findings f SET status = $3, fixed_at = NULL,
			data = (f.data - 'fixed_at') || jsonb_build_object('status', $3::text)
		FROM targets t
		WHERE t.id = f.target_id AND f.org_id = $4 AND f.target_id = $1 AND f.id = $2
		RETURNING t.domain, old.status, now()`,
		targetID, findingID, string(status), o.orgID).Scan(&domain, &previous, &at)
	if errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("set finding status %s: %w", findingID, ErrNotFound)
	}
	if err != nil {
		return fmt.Errorf("set finding status %s: %w", findingID, err)
	}
	if previous != string(status) {
		if err := recordEvent(ctx, tx, FindingEvent{OrgID: o.orgID, TargetID: targetID, FindingID: findingID,
			At: at, From: finding.Status(previous), To: status, Actor: actor}); err != nil {
			return fmt.Errorf("set finding status %s: %w", findingID, err)
		}
	}
	if err := appendAudit(ctx, tx, AuditEntry{
		OrgID: o.orgID, Actor: actor, Action: ActionFindingStatus, Target: domain,
		Details: map[string]any{"finding_id": findingID, "from": previous, "to": status},
	}); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("set finding status %s: %w", findingID, err)
	}
	return nil
}
