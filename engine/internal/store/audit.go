package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// Audit actions.
const (
	ActionScanRequested = "scan.requested"
	ActionScanStarted   = "scan.started"
	ActionModuleRefused = "module.refused"
	ActionScanFinished  = "scan.finished"
	ActionScanFailed    = "scan.failed"
	ActionIPNotVerified = "ip.not_verified"
)

// AuditEntry is one line of the audit log (security rule 4).
type AuditEntry struct {
	At      time.Time // set by the database when written
	OrgID   string    // the organization concerned; an Org fills it in
	Actor   string    // who: a user, or "worker:<id>"
	Action  string
	Target  string // the domain, kept as text so entries outlive the target
	Details any    // marshaled to JSON; nil means {}
}

// AppendAudit writes an entry. The table is append-only: entries can never be
// changed or deleted, even by this application.
//
// Through an Org, an empty OrgID means the handle's organization, and any
// other organization is refused. Through the worker's Store, OrgID is
// required.
func (sc scope) AppendAudit(ctx context.Context, e AuditEntry) error {
	switch {
	case sc.orgID != "" && e.OrgID == "":
		e.OrgID = sc.orgID
	case sc.orgID != "" && e.OrgID != sc.orgID:
		return fmt.Errorf("audit %s: entry is for another organization", e.Action)
	case e.OrgID == "":
		return fmt.Errorf("audit %s: missing organization", e.Action)
	}
	tx, err := sc.begin(ctx)
	if err != nil {
		return fmt.Errorf("audit %s: %w", e.Action, err)
	}
	defer tx.Rollback(ctx)
	if err := appendAudit(ctx, tx, e); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("audit %s: %w", e.Action, err)
	}
	return nil
}

// appendAudit writes e inside an existing transaction. Callers set OrgID
// from the row they just changed.
func appendAudit(ctx context.Context, q querier, e AuditEntry) error {
	details := []byte("{}")
	if e.Details != nil {
		var err error
		if details, err = json.Marshal(e.Details); err != nil {
			return fmt.Errorf("audit %s: encode details: %w", e.Action, err)
		}
	}
	_, err := q.Exec(ctx,
		"INSERT INTO audit_log (org_id, actor, action, target, details) VALUES ($1, $2, $3, $4, $5)",
		e.OrgID, e.Actor, e.Action, e.Target, details)
	if err != nil {
		return fmt.Errorf("audit %s: %w", e.Action, err)
	}
	return nil
}

// AuditLog returns the organization's entries for target, oldest first.
// Details are returned as raw JSON.
func (o *Org) AuditLog(ctx context.Context, target string) ([]AuditEntry, error) {
	tx, err := o.begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("read audit log: %w", err)
	}
	defer tx.Rollback(ctx)
	rows, err := tx.Query(ctx,
		"SELECT at, org_id::text, actor, action, target, details FROM audit_log WHERE org_id = $1 AND target = $2 ORDER BY id",
		o.orgID, target)
	if err != nil {
		return nil, fmt.Errorf("read audit log: %w", err)
	}
	entries, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (AuditEntry, error) {
		var e AuditEntry
		var details json.RawMessage
		err := row.Scan(&e.At, &e.OrgID, &e.Actor, &e.Action, &e.Target, &details)
		e.Details = details
		return e, err
	})
	if err != nil {
		return nil, fmt.Errorf("read audit log: %w", err)
	}
	return entries, tx.Commit(ctx)
}
