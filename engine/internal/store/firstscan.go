package store

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/jordyorel/orus-shield/engine/internal/finding"
)

// NotifyFirstScan is the kind of notification sent when a domain's first
// scan finishes: a summary, not an alert.
const NotifyFirstScan = "first_scan"

// FirstScanSummary is the payload of a first_scan notification: what the
// dashboard shows after that scan, in a few figures.
type FirstScanSummary struct {
	OrgID   string `json:"org_id"`
	OrgName string `json:"org_name"`
	Domain  string `json:"domain"`
	ScanID  string `json:"scan_id"`
	// Score is the domain's posture score (0 to 100), nil when no check
	// was evaluated.
	Score *int `json:"score"`
	// Open counts the open findings by severity.
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	// Hostnames counts the names found under the domain (discovery).
	Hostnames int `json:"hostnames"`
}

// queueFirstScanSummary writes one first_scan notification per activated
// admin when scanID is the first scan of the target to finish, inside
// FinishScan's transaction (after the findings, assets and checks are
// saved, so the figures are this scan's). Internal networks get none: their
// agent's enrolment already told the admin. Every offer gets it; the email
// switch of Réglages applies.
func queueFirstScanSummary(ctx context.Context, tx pgx.Tx, orgID, targetID, scanID, domain string, score *int) (int, error) {
	var first, internal bool
	err := tx.QueryRow(ctx, `
		SELECT NOT EXISTS (SELECT 1 FROM scans WHERE target_id = $1 AND status = 'done' AND id <> $2),
			t.internal
		FROM targets t WHERE t.id = $1`, targetID, scanID).Scan(&first, &internal)
	if err != nil {
		return 0, fmt.Errorf("queue first scan summary: %w", err)
	}
	if !first || internal {
		return 0, nil
	}
	if _, email, err := alertSettings(ctx, tx, orgID); err != nil {
		return 0, fmt.Errorf("queue first scan summary: %w", err)
	} else if !email {
		return 0, nil
	}

	p := FirstScanSummary{OrgID: orgID, Domain: domain, ScanID: scanID, Score: score}
	rows, err := tx.Query(ctx, `
		SELECT severity, count(*) FROM findings
		WHERE target_id = $1 AND status = 'open' GROUP BY severity`, targetID)
	if err != nil {
		return 0, fmt.Errorf("queue first scan summary: %w", err)
	}
	counts := map[finding.Severity]*int{
		finding.SeverityCritical: &p.Critical, finding.SeverityHigh: &p.High,
		finding.SeverityMedium: &p.Medium, finding.SeverityLow: &p.Low,
	}
	for rows.Next() {
		var sev string
		var n int
		if err := rows.Scan(&sev, &n); err != nil {
			rows.Close()
			return 0, fmt.Errorf("queue first scan summary: %w", err)
		}
		if c := counts[finding.Severity(sev)]; c != nil { // info is not counted
			*c = n
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, fmt.Errorf("queue first scan summary: %w", err)
	}
	err = tx.QueryRow(ctx, `
		SELECT (SELECT count(*) FROM assets WHERE target_id = $1 AND kind = 'hostname' AND gone_at IS NULL),
			(SELECT name FROM organizations WHERE id = $2)`, targetID, orgID).Scan(&p.Hostnames, &p.OrgName)
	if err != nil {
		return 0, fmt.Errorf("queue first scan summary: %w", err)
	}
	data, err := json.Marshal(p)
	if err != nil {
		return 0, fmt.Errorf("queue first scan summary: %w", err)
	}
	tag, err := tx.Exec(ctx, `
		INSERT INTO notifications (org_id, target_id, scan_id, kind, recipient, payload)
		SELECT $1, $2, $3, $4, u.email, $5
		FROM memberships m JOIN users u ON u.id = m.user_id
		WHERE m.org_id = $1 AND m.role = $6 AND u.password_hash IS NOT NULL AND u.disabled_at IS NULL`,
		orgID, targetID, scanID, NotifyFirstScan, data, RoleAdmin)
	if err != nil {
		return 0, fmt.Errorf("queue first scan summary: %w", err)
	}
	return int(tag.RowsAffected()), nil
}
