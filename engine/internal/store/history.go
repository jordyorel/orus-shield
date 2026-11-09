package store

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/jordyorel/orus-shield/engine/internal/finding"
)

// FindingEvent is one status change of a finding. Events are written in the
// same transaction as the change itself, so the history and the current
// status always agree.
type FindingEvent struct {
	OrgID     string
	TargetID  string
	FindingID string
	At        time.Time      // when the change was observed (scan) or requested (manual)
	From      finding.Status // empty when the finding was first seen
	To        finding.Status
	Actor     string // worker ID for scan events, the customer for manual ones
	ScanID    string // empty for manual changes
}

// Kind names the change for display: opened, fixed, reopened, risk_accepted
// or risk_withdrawn.
func (e FindingEvent) Kind() string {
	switch {
	case e.From == "":
		return "opened"
	case e.To == finding.StatusFixed:
		return "fixed"
	case e.To == finding.StatusAcceptedRisk:
		return "risk_accepted"
	case e.From == finding.StatusAcceptedRisk:
		return "risk_withdrawn"
	default:
		return "reopened"
	}
}

func recordEvent(ctx context.Context, q querier, e FindingEvent) error {
	var from, scanID *string
	if e.From != "" {
		f := string(e.From)
		from = &f
	}
	if e.ScanID != "" {
		scanID = &e.ScanID
	}
	_, err := q.Exec(ctx, `
		INSERT INTO finding_events (org_id, target_id, finding_id, at, from_status, to_status, actor, scan_id)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		e.OrgID, e.TargetID, e.FindingID, e.At, from, string(e.To), e.Actor, scanID)
	if err != nil {
		return fmt.Errorf("record finding event: %w", err)
	}
	return nil
}

// FindingHistory returns the status changes of one finding of the
// organization, oldest first. A finding of another organization has no
// history.
func (o *Org) FindingHistory(ctx context.Context, targetID, findingID string) ([]FindingEvent, error) {
	if !isUUID(targetID) {
		return nil, nil
	}
	tx, err := o.begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("finding history: %w", err)
	}
	defer tx.Rollback(ctx)
	rows, err := tx.Query(ctx, `
		SELECT org_id::text, target_id::text, finding_id, at, coalesce(from_status, ''), to_status, actor,
		       coalesce(scan_id::text, '')
		FROM finding_events
		WHERE org_id = $1 AND target_id = $2 AND finding_id = $3
		ORDER BY id`, o.orgID, targetID, findingID)
	if err != nil {
		return nil, fmt.Errorf("finding history: %w", err)
	}
	events, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (FindingEvent, error) {
		var e FindingEvent
		var from, to string
		err := r.Scan(&e.OrgID, &e.TargetID, &e.FindingID, &e.At, &from, &to, &e.Actor, &e.ScanID)
		e.From, e.To = finding.Status(from), finding.Status(to)
		return e, err
	})
	if err != nil {
		return nil, fmt.Errorf("finding history: %w", err)
	}
	return events, tx.Commit(ctx)
}
