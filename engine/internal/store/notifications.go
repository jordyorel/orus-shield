package store

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/jordyorel/orus-shield/engine/internal/finding"
)

// NotifyNewFindings is the kind of notification sent when a scan opens or
// reopens findings worth an alert.
const NotifyNewFindings = "new_findings"

// maxAlertFindings bounds the findings listed in one alert; the total is
// still given.
const maxAlertFindings = 20

// AlertFinding is one finding in an alert.
type AlertFinding struct {
	ID       string           `json:"id"`
	Title    string           `json:"title"`
	Asset    string           `json:"asset"`
	Severity finding.Severity `json:"severity"`
	Reopened bool             `json:"reopened"` // was fixed, and is back
}

// NewFindingsAlert is the payload of a new_findings notification.
type NewFindingsAlert struct {
	OrgID    string         `json:"org_id"`
	OrgName  string         `json:"org_name"`
	Domain   string         `json:"domain"`
	ScanID   string         `json:"scan_id"`
	Findings []AlertFinding `json:"findings"` // most severe first, at most maxAlertFindings
	Total    int            `json:"total"`
}

// Alertable reports whether a finding that a scan opened or reopened is
// worth an email: critical and high only, so a daily scan never turns into
// daily noise. A certificate expiring within a week is high (tls module),
// so it alerts; the 30-day warning does not.
func Alertable(f finding.Finding) bool {
	return f.Severity.Rank() >= finding.SeverityHigh.Rank()
}

// queueAlerts writes one notification per admin of the organization, inside
// FinishScan's transaction. Admins whose account is not activated or is
// disabled are skipped.
func queueAlerts(ctx context.Context, tx pgx.Tx, orgID, targetID, scanID, domain string, alerts []AlertFinding) (int, error) {
	if len(alerts) == 0 {
		return 0, nil
	}
	slices.SortStableFunc(alerts, func(a, b AlertFinding) int {
		return cmp.Compare(b.Severity.Rank(), a.Severity.Rank())
	})
	payload := NewFindingsAlert{OrgID: orgID, Domain: domain, ScanID: scanID, Total: len(alerts), Findings: alerts}
	if len(payload.Findings) > maxAlertFindings {
		payload.Findings = payload.Findings[:maxAlertFindings]
	}
	if err := tx.QueryRow(ctx, "SELECT name FROM organizations WHERE id = $1", orgID).Scan(&payload.OrgName); err != nil {
		return 0, fmt.Errorf("queue alerts: %w", err)
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return 0, fmt.Errorf("queue alerts: %w", err)
	}
	tag, err := tx.Exec(ctx, `
		INSERT INTO notifications (org_id, target_id, scan_id, kind, recipient, payload)
		SELECT $1, $2, $3, $4, u.email, $5
		FROM memberships m JOIN users u ON u.id = m.user_id
		WHERE m.org_id = $1 AND m.role = $6 AND u.password_hash IS NOT NULL AND u.disabled_at IS NULL`,
		orgID, targetID, scanID, NotifyNewFindings, data, RoleAdmin)
	if err != nil {
		return 0, fmt.Errorf("queue alerts: %w", err)
	}
	return int(tag.RowsAffected()), nil
}

// Notification is one email waiting in the outbox.
type Notification struct {
	ID        string
	OrgID     string
	Kind      string
	Recipient string
	Payload   json.RawMessage
	CreatedAt time.Time
	Attempts  int // including the current one
}

// ClaimNotifications takes up to limit notifications due at now and leases
// them for lease: their next attempt moves to now+lease before they are
// returned, so another worker does not send them meanwhile. A worker that
// crashes mid-delivery leaves them to be retried after the lease.
func (s *Store) ClaimNotifications(ctx context.Context, now time.Time, lease time.Duration, limit int) ([]Notification, error) {
	rows, err := s.pool.Query(ctx, `
		UPDATE notifications n SET next_attempt_at = $2, attempts = n.attempts + 1
		WHERE n.id IN (
			SELECT id FROM notifications
			WHERE sent_at IS NULL AND failed_at IS NULL AND next_attempt_at <= $1
			ORDER BY next_attempt_at
			LIMIT $3
			FOR UPDATE SKIP LOCKED)
		RETURNING n.id::text, n.org_id::text, n.kind, n.recipient, n.payload, n.created_at, n.attempts`,
		now, now.Add(lease), limit)
	if err != nil {
		return nil, fmt.Errorf("claim notifications: %w", err)
	}
	out, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (Notification, error) {
		var n Notification
		err := r.Scan(&n.ID, &n.OrgID, &n.Kind, &n.Recipient, &n.Payload, &n.CreatedAt, &n.Attempts)
		return n, err
	})
	if err != nil {
		return nil, fmt.Errorf("claim notifications: %w", err)
	}
	return out, nil
}

// MarkNotificationSent records a delivered notification.
func (s *Store) MarkNotificationSent(ctx context.Context, id string, at time.Time) error {
	return s.markNotification(ctx, `UPDATE notifications SET sent_at = $2, last_error = NULL WHERE id = $1`, id, at)
}

// RetryNotification records a failed attempt; the next one is at retryAt.
func (s *Store) RetryNotification(ctx context.Context, id, reason string, retryAt time.Time) error {
	return s.markNotification(ctx, `UPDATE notifications SET next_attempt_at = $2, last_error = $3 WHERE id = $1`,
		id, retryAt, truncateRunes(reason, maxErrorChars))
}

// AbandonNotification gives up on a notification (too many attempts, or
// too old to be useful).
func (s *Store) AbandonNotification(ctx context.Context, id, reason string, at time.Time) error {
	return s.markNotification(ctx, `UPDATE notifications SET failed_at = $2, last_error = $3 WHERE id = $1`,
		id, at, truncateRunes(reason, maxErrorChars))
}

func (s *Store) markNotification(ctx context.Context, query string, id string, args ...any) error {
	if !isUUID(id) {
		return fmt.Errorf("notification %s: %w", id, ErrNotFound)
	}
	tag, err := s.pool.Exec(ctx, query, append([]any{id}, args...)...)
	if err != nil {
		return fmt.Errorf("notification %s: %w", id, err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("notification %s: %w", id, ErrNotFound)
	}
	return nil
}
