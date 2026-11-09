package store

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/jordyorel/orus-shield/engine/internal/finding"
	"github.com/jordyorel/orus-shield/engine/internal/module"
	"github.com/jordyorel/orus-shield/engine/internal/posture"
)

// CheckState is the latest status of one catalog check on a target.
type CheckState struct {
	CheckID     string
	ModuleID    string
	Category    module.Category
	Severity    finding.Severity
	Status      module.CheckStatus
	Findings    int
	EvaluatedAt time.Time
	ScanID      string
}

// PostureSnapshot is the posture of a target after one scan.
type PostureSnapshot struct {
	ScanID  string
	At      time.Time
	Score   *int // nil: nothing with a weight was evaluated
	Details posture.Snapshot
}

// saveChecks records the check outcomes of a finished scan and, if any
// check was evaluated, a posture snapshot computed from the latest status
// of every check of the target (this scan's modules and the others). It
// runs inside FinishScan's transaction.
func saveChecks(ctx context.Context, tx pgx.Tx, orgID, targetID, scanID string, at time.Time, r ScanResult) (*int, error) {
	// Findings per module and check, to cross-check the outcomes: a check
	// is failed exactly when it produced findings in this scan.
	produced := make(map[string]int)
	for _, f := range r.Findings {
		produced[f.ModuleID+" "+f.CheckID]++
	}
	saved := 0
	for _, moduleID := range slices.Sorted(maps.Keys(r.Checks)) {
		if !slices.Contains(r.Succeeded, moduleID) {
			return nil, fmt.Errorf("check outcomes from module %s, which did not succeed", moduleID)
		}
		for _, o := range r.Checks[moduleID] {
			switch {
			case o.Status != module.CheckPassed && o.Status != module.CheckFailed && o.Status != module.CheckNotApplicable:
				return nil, fmt.Errorf("check %s: unknown status %q", o.ID, o.Status)
			case !o.Severity.Valid() || !o.Category.Valid():
				return nil, fmt.Errorf("check %s: invalid severity or category", o.ID)
			case o.Findings != produced[moduleID+" "+o.ID]:
				return nil, fmt.Errorf("check %s: %d findings claimed, %d in the scan", o.ID, o.Findings, produced[moduleID+" "+o.ID])
			}
			_, err := tx.Exec(ctx, `
				INSERT INTO check_status (org_id, target_id, check_id, module_id, category, severity, status, findings, evaluated_at, scan_id)
				VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
				ON CONFLICT (target_id, check_id) DO UPDATE SET
					module_id = EXCLUDED.module_id, category = EXCLUDED.category, severity = EXCLUDED.severity,
					status = EXCLUDED.status, findings = EXCLUDED.findings,
					evaluated_at = EXCLUDED.evaluated_at, scan_id = EXCLUDED.scan_id`,
				orgID, targetID, o.ID, moduleID, string(o.Category), string(o.Severity), string(o.Status), o.Findings, at, scanID)
			if err != nil {
				return nil, fmt.Errorf("save check %s: %w", o.ID, err)
			}
			saved++
		}
	}
	if saved == 0 {
		return nil, nil // nothing evaluated: the posture did not change
	}

	states, err := checkStates(ctx, tx, targetID, nil)
	if err != nil {
		return nil, err
	}
	checks := make([]posture.Check, len(states))
	for i, s := range states {
		checks[i] = posture.Check{ID: s.CheckID, Category: s.Category, Severity: s.Severity, Status: s.Status}
	}
	snap := posture.Compute(checks)
	details, err := json.Marshal(snap)
	if err != nil {
		return nil, fmt.Errorf("encode posture: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO posture_snapshots (org_id, target_id, scan_id, at, score, passed, failed, not_applicable, details)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		orgID, targetID, scanID, at, snap.Score, snap.Total.Passed, snap.Total.Failed, snap.Total.NotApplicable, details); err != nil {
		return nil, fmt.Errorf("save posture snapshot: %w", err)
	}
	return snap.Score, nil
}

// checkStates reads the check status of a target. org is an organization
// filter as in scope.orgParam: nil for the worker.
func checkStates(ctx context.Context, q querier, targetID string, org any) ([]CheckState, error) {
	rows, err := q.Query(ctx, `
		SELECT check_id, module_id, category, severity, status, findings, evaluated_at, scan_id::text
		FROM check_status WHERE target_id = $1 AND ($2::uuid IS NULL OR org_id = $2::uuid)
		ORDER BY module_id, check_id`, targetID, org)
	if err != nil {
		return nil, fmt.Errorf("read check status: %w", err)
	}
	states, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (CheckState, error) {
		var s CheckState
		var cat, sev, st string
		err := r.Scan(&s.CheckID, &s.ModuleID, &cat, &sev, &st, &s.Findings, &s.EvaluatedAt, &s.ScanID)
		s.Category, s.Severity, s.Status = module.Category(cat), finding.Severity(sev), module.CheckStatus(st)
		return s, err
	})
	if err != nil {
		return nil, fmt.Errorf("read check status: %w", err)
	}
	return states, nil
}

// CheckStatuses returns the latest status of every check evaluated on one
// of the organization's targets, by module then check ID.
func (o *Org) CheckStatuses(ctx context.Context, targetID string) ([]CheckState, error) {
	if !isUUID(targetID) {
		return nil, nil
	}
	tx, err := o.begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("check statuses: %w", err)
	}
	defer tx.Rollback(ctx)
	states, err := checkStates(ctx, tx, targetID, o.orgParam())
	if err != nil {
		return nil, err
	}
	return states, tx.Commit(ctx)
}

// PostureHistory returns the latest snapshots of one of the organization's
// targets, newest first, at most limit (1 to 1000).
func (o *Org) PostureHistory(ctx context.Context, targetID string, limit int) ([]PostureSnapshot, error) {
	if !isUUID(targetID) {
		return nil, nil
	}
	limit = min(max(limit, 1), 1000)
	tx, err := o.begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("posture history: %w", err)
	}
	defer tx.Rollback(ctx)
	rows, err := tx.Query(ctx, `
		SELECT scan_id::text, at, score, details FROM posture_snapshots
		WHERE org_id = $1 AND target_id = $2
		ORDER BY at DESC, id DESC LIMIT $3`, o.orgID, targetID, limit)
	if err != nil {
		return nil, fmt.Errorf("posture history: %w", err)
	}
	snaps, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (PostureSnapshot, error) {
		var p PostureSnapshot
		var details []byte
		if err := r.Scan(&p.ScanID, &p.At, &p.Score, &details); err != nil {
			return p, err
		}
		return p, json.Unmarshal(details, &p.Details)
	})
	if err != nil {
		return nil, fmt.Errorf("posture history: %w", err)
	}
	return snaps, tx.Commit(ctx)
}
