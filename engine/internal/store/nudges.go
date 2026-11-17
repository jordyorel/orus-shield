package store

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/jordyorel/orus-shield/engine/internal/plan"
)

// NotifyTrialNudge is the kind of the reminders sent after the free audit,
// inviting to start the 14-day trial.
const NotifyTrialNudge = "trial_nudge"

// nudgeDays are the days after the free audit when reminders are due.
var nudgeDays = []int{3, 10}

// TrialNudge is the payload of a trial_nudge notification: the audit's
// figures, as they were when it finished.
type TrialNudge struct {
	OrgID    string `json:"org_id"`
	OrgName  string `json:"org_name"`
	Domain   string `json:"domain"`
	Day      int    `json:"day"` // days after the audit: 3 or 10
	Critical int    `json:"critical"`
	High     int    `json:"high"`
	Open     int    `json:"open"` // every open finding, info aside
	// Top is the title of the most severe open finding (module text).
	Top string `json:"top"`
	// Unsubscribe is the recipient's one-click unsubscribe token.
	Unsubscribe string `json:"unsubscribe"`
}

// queueTrialNudges queues the reminders of a free audit (see migration
// 0025), inside FinishScan's transaction, for every activated admin who did
// not unsubscribe. p carries the audit's figures.
func queueTrialNudges(ctx context.Context, tx pgx.Tx, orgID, targetID, scanID string, at time.Time, p FirstScanSummary) error {
	top := ""
	if err := tx.QueryRow(ctx, `
		SELECT coalesce((SELECT data->>'title' FROM findings
			WHERE target_id = $1 AND status = 'open' AND severity <> 'info'
			ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END, first_seen
			LIMIT 1), '')`, targetID).Scan(&top); err != nil {
		return fmt.Errorf("queue trial nudges: %w", err)
	}
	base, err := json.Marshal(TrialNudge{OrgID: orgID, OrgName: p.OrgName, Domain: p.Domain, Critical: p.Critical,
		High: p.High, Open: p.Critical + p.High + p.Medium + p.Low, Top: truncateRunes(top, 200)})
	if err != nil {
		return fmt.Errorf("queue trial nudges: %w", err)
	}
	// One token per recipient (two random UUIDs: 244 random bits), stored
	// hashed; the reminder's payload carries it in clear for the link.
	_, err = tx.Exec(ctx, `
		WITH r AS MATERIALIZED (
			SELECT u.email, gen_random_uuid()::text || gen_random_uuid()::text AS token
			FROM memberships m JOIN users u ON u.id = m.user_id
			WHERE m.org_id = $1 AND m.role = $7 AND u.password_hash IS NOT NULL AND u.disabled_at IS NULL
				AND NOT EXISTS (SELECT 1 FROM marketing_optouts o WHERE o.email = lower(u.email))
		), tokens AS (
			INSERT INTO unsubscribe_tokens (token_hash, email)
			SELECT sha256(convert_to(token, 'UTF8')), lower(email) FROM r
		)
		INSERT INTO notifications (org_id, target_id, scan_id, kind, recipient, payload, created_at, next_attempt_at)
		SELECT $1, $2, $3, $4, r.email,
			$5::jsonb || jsonb_build_object('day', d.day, 'unsubscribe', r.token),
			$6::timestamptz + d.day * interval '1 day', $6::timestamptz + d.day * interval '1 day'
		FROM r CROSS JOIN unnest($8::int[]) AS d(day)`,
		orgID, targetID, scanID, NotifyTrialNudge, base, at, RoleAdmin, nudgeDays)
	if err != nil {
		return fmt.Errorf("queue trial nudges: %w", err)
	}
	return nil
}

// TrialNudgeWanted reports whether a trial reminder should still go out at
// now: the organization is still on the free offer and never had a paid
// offer or a trial (no Paddle customer, stored plan Gratuit), and the
// recipient did not unsubscribe.
func (s *Store) TrialNudgeWanted(ctx context.Context, orgID, recipient string, now time.Time) (bool, error) {
	if !isUUID(orgID) {
		return false, nil
	}
	sub, err := s.SubscriptionOf(ctx, orgID)
	if err != nil {
		return false, fmt.Errorf("trial nudge wanted: %w", err)
	}
	if sub != nil && sub.Plan != plan.Discovery {
		return false, nil
	}
	if plan.Resolve(sub, now).Plan.Monitoring {
		return false, nil
	}
	var customer, optedOut bool
	err = s.pool.QueryRow(ctx, `
		SELECT EXISTS (SELECT 1 FROM subscriptions WHERE org_id = $1 AND provider_customer IS NOT NULL),
			EXISTS (SELECT 1 FROM marketing_optouts WHERE email = lower($2))`, orgID, recipient).Scan(&customer, &optedOut)
	if err != nil {
		return false, fmt.Errorf("trial nudge wanted: %w", err)
	}
	return !customer && !optedOut, nil
}

// ErrUnknownToken is returned for an unsubscribe token we never issued.
var ErrUnknownToken = errors.New("unknown token")

// Unsubscribe records the opt-out of the address an unsubscribe token was
// issued for. It is idempotent: unsubscribing twice is not an error.
func (a *Auth) Unsubscribe(ctx context.Context, token string) error {
	token = strings.TrimSpace(token)
	if token == "" || len(token) > 200 {
		return ErrUnknownToken
	}
	sum := sha256.Sum256([]byte(token))
	tx, err := a.begin(ctx)
	if err != nil {
		return fmt.Errorf("unsubscribe: %w", err)
	}
	defer tx.Rollback(ctx)
	var email string
	err = tx.QueryRow(ctx, "SELECT email FROM unsubscribe_tokens WHERE token_hash = $1", sum[:]).Scan(&email)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrUnknownToken
	}
	if err != nil {
		return fmt.Errorf("unsubscribe: %w", err)
	}
	if _, err := tx.Exec(ctx, "INSERT INTO marketing_optouts (email) VALUES ($1) ON CONFLICT DO NOTHING", email); err != nil {
		return fmt.Errorf("unsubscribe: %w", err)
	}
	return tx.Commit(ctx)
}
