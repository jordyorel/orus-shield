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
	Actor   string    // who: a user, or "worker:<id>"
	Action  string
	Target  string // the domain, kept as text so entries outlive the target
	Details any    // marshaled to JSON; nil means {}
}

// AppendAudit writes an entry. The table is append-only: entries can never be
// changed or deleted, even by this application.
func (s *Store) AppendAudit(ctx context.Context, e AuditEntry) error {
	return appendAudit(ctx, s.pool, e)
}

func appendAudit(ctx context.Context, q querier, e AuditEntry) error {
	details := []byte("{}")
	if e.Details != nil {
		var err error
		if details, err = json.Marshal(e.Details); err != nil {
			return fmt.Errorf("audit %s: encode details: %w", e.Action, err)
		}
	}
	_, err := q.Exec(ctx,
		"INSERT INTO audit_log (actor, action, target, details) VALUES ($1, $2, $3, $4)",
		e.Actor, e.Action, e.Target, details)
	if err != nil {
		return fmt.Errorf("audit %s: %w", e.Action, err)
	}
	return nil
}

// AuditLog returns the entries for target, oldest first. Details are
// returned as raw JSON.
func (s *Store) AuditLog(ctx context.Context, target string) ([]AuditEntry, error) {
	rows, err := s.pool.Query(ctx,
		"SELECT at, actor, action, target, details FROM audit_log WHERE target = $1 ORDER BY id", target)
	if err != nil {
		return nil, fmt.Errorf("read audit log: %w", err)
	}
	entries, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (AuditEntry, error) {
		var e AuditEntry
		var details json.RawMessage
		err := row.Scan(&e.At, &e.Actor, &e.Action, &e.Target, &details)
		e.Details = details
		return e, err
	})
	if err != nil {
		return nil, fmt.Errorf("read audit log: %w", err)
	}
	return entries, nil
}
