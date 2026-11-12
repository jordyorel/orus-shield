package store

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/jordyorel/orus-shield/engine/internal/finding"
)

// ActivityKind says what an activity entry is.
type ActivityKind string

const (
	// ActivityFinding: a finding changed status (opened, fixed, reopened,
	// accepted).
	ActivityFinding ActivityKind = "finding"
	// ActivityScan: a scan finished.
	ActivityScan ActivityKind = "scan"
)

// Activity is one line of Aujourd'hui > Depuis votre dernière visite.
type Activity struct {
	Kind     ActivityKind
	At       time.Time
	TargetID string
	Domain   string
	// Finding entries.
	FindingID string
	Title     string
	Asset     string
	Severity  finding.Severity
	From      string // "" when the finding was first seen
	To        string
	// Scan entries.
	ScanID      string
	RequestedBy string
	Assets      int // current assets of the target after the scan
}

// Activity returns the organization's latest finding changes and finished
// scans since since, newest first, at most limit of them.
func (o *Org) Activity(ctx context.Context, since time.Time, limit int) ([]Activity, error) {
	tx, err := o.begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("activity: %w", err)
	}
	defer tx.Rollback(ctx)
	rows, err := tx.Query(ctx, `
		(SELECT 'finding', e.at, e.target_id::text, t.domain, e.finding_id,
			f.data->>'title', f.data->>'asset', f.severity, coalesce(e.from_status, ''), e.to_status,
			'', '', 0
		FROM finding_events e
		JOIN targets t ON t.id = e.target_id
		JOIN findings f ON f.target_id = e.target_id AND f.id = e.finding_id
		WHERE e.org_id = $1 AND e.at >= $2
		ORDER BY e.at DESC LIMIT $3)
		UNION ALL
		(SELECT 'scan', s.finished_at, s.target_id::text, t.domain, '',
			'', '', '', '', '',
			s.id::text, s.requested_by,
			(SELECT count(*)::int FROM assets a WHERE a.target_id = s.target_id AND a.gone_at IS NULL)
		FROM scans s JOIN targets t ON t.id = s.target_id
		WHERE s.org_id = $1 AND s.status = 'done' AND s.finished_at >= $2
		ORDER BY s.finished_at DESC LIMIT $3)
		ORDER BY 2 DESC LIMIT $3`, o.orgID, since, limit)
	if err != nil {
		return nil, fmt.Errorf("activity: %w", err)
	}
	out, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (Activity, error) {
		var a Activity
		var sev string
		err := row.Scan(&a.Kind, &a.At, &a.TargetID, &a.Domain, &a.FindingID, &a.Title, &a.Asset, &sev,
			&a.From, &a.To, &a.ScanID, &a.RequestedBy, &a.Assets)
		a.Severity = finding.Severity(sev)
		return a, err
	})
	if err != nil {
		return nil, fmt.Errorf("activity: %w", err)
	}
	return out, tx.Commit(ctx)
}
