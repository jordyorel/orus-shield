package store

import (
	"context"
	"fmt"
	"time"

	"github.com/jordyorel/orus-shield/engine/internal/plan"
)

// NotifyTrialEnding is the kind of the email sent before a paid trial ends
// (migration 0036). Paddle sends the legal reminder before it charges the
// card; ours says what the trial brought and how to cancel.
const NotifyTrialEnding = "trial_ending"

// TrialEndingNotice is how long before its end a trial's email is queued.
const TrialEndingNotice = 3 * 24 * time.Hour

// trialEndingMin: a trial closer than this to its end gets no email (the
// worker was down for days): "your trial ends in an hour" helps nobody.
const trialEndingMin = 12 * time.Hour

// TrialEnding is the payload of a trial_ending notification: the trial's
// figures when the email was queued. Problems are counted as the dashboard
// counts them: one line per check failing on a domain, whatever the number
// of names (groupIssues in web/src/ui/model.ts).
type TrialEnding struct {
	OrgID       string    `json:"org_id"`
	OrgName     string    `json:"org_name"`
	Plan        plan.ID   `json:"plan"`
	TrialEndsAt time.Time `json:"trial_ends_at"`
	// Scans counts the scans finished since the trial started.
	Scans int `json:"scans"`
	// Fixed counts the problem lines fixed since the trial started.
	Fixed int `json:"fixed"`
	// Open counts the open problem lines (info aside), Urgent the critical
	// and high ones among them.
	Open   int `json:"open"`
	Urgent int `json:"urgent"`
	// Domains counts the verified domains (internal networks aside).
	Domains int `json:"domains"`
}

// QueueTrialEndings queues the email of every trial run by a payment
// provider that ends within TrialEndingNotice (but not within
// trialEndingMin), once per trial end: one per activated admin. A trial
// whose end moves gets a new email for its new end; the notifier drops the
// old one (TrialEndingWanted). Manual trials (orusctl) are left out: nobody
// charges at their end. It returns the number of emails queued.
//
// It runs in the worker (cross-organization) and is cheap enough to run at
// every notifier pass: one indexed lookup when nothing is due.
func (s *Store) QueueTrialEndings(ctx context.Context, now time.Time) (int, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT s.org_id::text, o.name, s.plan, s.trial_ends_at FROM subscriptions s
		JOIN organizations o ON o.id = s.org_id
		WHERE s.status = 'trialing' AND s.provider <> 'manual'
			AND s.trial_ends_at > $1 AND s.trial_ends_at <= $2
			AND NOT EXISTS (SELECT 1 FROM notifications n WHERE n.org_id = s.org_id AND n.kind = $3
				AND (n.payload->>'trial_ends_at')::timestamptz = s.trial_ends_at)`,
		now.Add(trialEndingMin), now.Add(TrialEndingNotice), NotifyTrialEnding)
	if err != nil {
		return 0, fmt.Errorf("queue trial endings: %w", err)
	}
	var due []TrialEnding
	for rows.Next() {
		var t TrialEnding
		if err := rows.Scan(&t.OrgID, &t.OrgName, &t.Plan, &t.TrialEndsAt); err != nil {
			rows.Close()
			return 0, fmt.Errorf("queue trial endings: %w", err)
		}
		due = append(due, t)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, fmt.Errorf("queue trial endings: %w", err)
	}
	queued := 0
	for _, t := range due {
		n, err := s.queueTrialEnding(ctx, t)
		if err != nil {
			return queued, err
		}
		queued += n
	}
	return queued, nil
}

// queueTrialEnding computes one trial's figures and queues its emails.
func (s *Store) queueTrialEnding(ctx context.Context, t TrialEnding) (int, error) {
	start := t.TrialEndsAt.Add(-plan.TrialDays * 24 * time.Hour)
	// Problem lines: (domain, check, title), as the dashboard groups them.
	// A line is open when one of its names still has the problem.
	err := s.pool.QueryRow(ctx, `
		WITH f AS (
			SELECT f.target_id, f.data->>'check_id' AS check_id, f.data->>'title' AS title,
				f.status, f.severity, f.fixed_at
			FROM findings f JOIN targets tg ON tg.id = f.target_id
			WHERE tg.org_id = $1 AND f.severity <> 'info'
		), lines AS (
			SELECT bool_or(status = 'open') AS open,
				bool_or(status = 'open' AND severity IN ('critical', 'high')) AS urgent,
				max(fixed_at) FILTER (WHERE status = 'fixed') AS fixed_at
			FROM f GROUP BY target_id, check_id, title
		)
		SELECT (SELECT count(*) FROM scans sc JOIN targets tg ON tg.id = sc.target_id
				WHERE tg.org_id = $1 AND sc.status = 'done' AND sc.finished_at >= $2),
			(SELECT count(*) FROM lines WHERE NOT open AND fixed_at >= $2),
			(SELECT count(*) FROM lines WHERE open),
			(SELECT count(*) FROM lines WHERE urgent),
			(SELECT count(*) FROM targets WHERE org_id = $1 AND verified_at IS NOT NULL AND NOT internal)`,
		t.OrgID, start).Scan(&t.Scans, &t.Fixed, &t.Open, &t.Urgent, &t.Domains)
	if err != nil {
		return 0, fmt.Errorf("queue trial ending: %w", err)
	}
	t.OrgName = truncateRunes(t.OrgName, 200)
	tag, err := s.pool.Exec(ctx, `
		INSERT INTO notifications (org_id, kind, recipient, payload)
		SELECT $1, $2, u.email, $3
		FROM memberships m JOIN users u ON u.id = m.user_id
		WHERE m.org_id = $1 AND m.role = $4 AND u.password_hash IS NOT NULL AND u.disabled_at IS NULL`,
		t.OrgID, NotifyTrialEnding, t, RoleAdmin)
	if err != nil {
		return 0, fmt.Errorf("queue trial ending: %w", err)
	}
	return int(tag.RowsAffected()), nil
}

// TrialEndingWanted reports whether a trial_ending email queued for a
// trial ending at endsAt should still go out at now: the trial still runs
// (not canceled, not converted early) and still ends then.
func (s *Store) TrialEndingWanted(ctx context.Context, orgID string, endsAt, now time.Time) (bool, error) {
	if !isUUID(orgID) || !now.Before(endsAt) {
		return false, nil
	}
	var ok bool
	err := s.pool.QueryRow(ctx, `
		SELECT EXISTS (SELECT 1 FROM subscriptions WHERE org_id = $1 AND status = 'trialing'
			AND provider <> 'manual' AND trial_ends_at = $2)`, orgID, endsAt).Scan(&ok)
	if err != nil {
		return false, fmt.Errorf("trial ending wanted: %w", err)
	}
	return ok, nil
}
