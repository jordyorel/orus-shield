package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/jordyorel/orus-shield/engine/internal/plan"
)

// ActionPlanChanged is the audit action of a subscription change.
const ActionPlanChanged = "plan.changed"

const subscriptionColumns = "plan, status, trial_ends_at, period_end"

func scanSubscription(row pgx.Row) (*plan.Subscription, error) {
	var sub plan.Subscription
	var p, st string
	err := row.Scan(&p, &st, &sub.TrialEndsAt, &sub.PeriodEnd)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil // no subscription: the free offer
	}
	if err != nil {
		return nil, err
	}
	sub.Plan, sub.Status = plan.ID(p), plan.Status(st)
	return &sub, nil
}

// SubscriptionOf returns an organization's subscription, nil when it has
// none (the worker resolves the plan of the scan's organization).
func (s *Store) SubscriptionOf(ctx context.Context, orgID string) (*plan.Subscription, error) {
	if !isUUID(orgID) {
		return nil, fmt.Errorf("subscription of %s: %w", orgID, ErrNotFound)
	}
	sub, err := scanSubscription(s.pool.QueryRow(ctx,
		"SELECT "+subscriptionColumns+" FROM subscriptions WHERE org_id = $1", orgID))
	if err != nil {
		return nil, fmt.Errorf("subscription of %s: %w", orgID, err)
	}
	return sub, nil
}

// Subscription returns the organization's subscription, nil when none.
func (o *Org) Subscription(ctx context.Context) (*plan.Subscription, error) {
	tx, err := o.begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("subscription: %w", err)
	}
	defer tx.Rollback(ctx)
	sub, err := scanSubscription(tx.QueryRow(ctx,
		"SELECT "+subscriptionColumns+" FROM subscriptions WHERE org_id = $1", o.orgID))
	if err != nil {
		return nil, fmt.Errorf("subscription: %w", err)
	}
	return sub, tx.Commit(ctx)
}

// Plan returns the plan in force for the organization at now.
func (o *Org) Plan(ctx context.Context, now time.Time) (plan.Effective, error) {
	sub, err := o.Subscription(ctx)
	if err != nil {
		return plan.Effective{}, err
	}
	return plan.Resolve(sub, now), nil
}

// SetSubscription replaces an organization's subscription (orusctl, and
// later the payment providers' webhooks), with its audit entry.
func (s *Store) SetSubscription(ctx context.Context, orgID string, sub plan.Subscription, provider, actor string) error {
	if _, ok := plan.Get(sub.Plan); !ok || !sub.Status.Valid() {
		return fmt.Errorf("set subscription: invalid plan %q or status %q", sub.Plan, sub.Status)
	}
	if sub.Status == plan.Trialing && sub.TrialEndsAt == nil {
		return errors.New("set subscription: a trial needs an end")
	}
	if !isUUID(orgID) {
		return fmt.Errorf("set subscription of %s: %w", orgID, ErrNotFound)
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("set subscription: %w", err)
	}
	defer tx.Rollback(ctx)
	_, err = tx.Exec(ctx, `
		INSERT INTO subscriptions (org_id, plan, status, trial_ends_at, period_end, provider, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, now())
		ON CONFLICT (org_id) DO UPDATE SET plan = $2, status = $3, trial_ends_at = $4, period_end = $5,
			provider = $6, updated_at = now()`,
		orgID, string(sub.Plan), string(sub.Status), sub.TrialEndsAt, sub.PeriodEnd, provider)
	if err != nil {
		return fmt.Errorf("set subscription of %s: %w", orgID, foreignKeyNotFound(err))
	}
	if err := appendAudit(ctx, tx, AuditEntry{
		OrgID: orgID, Actor: actor, Action: ActionPlanChanged,
		Details: map[string]any{"plan": sub.Plan, "status": sub.Status, "trial_ends_at": sub.TrialEndsAt,
			"period_end": sub.PeriodEnd, "provider": provider},
	}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// CountTargets returns how many domains the organization has.
func (o *Org) CountTargets(ctx context.Context) (int, error) {
	tx, err := o.begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("count targets: %w", err)
	}
	defer tx.Rollback(ctx)
	var n int
	if err := tx.QueryRow(ctx, "SELECT count(*) FROM targets WHERE org_id = $1", o.orgID).Scan(&n); err != nil {
		return 0, fmt.Errorf("count targets: %w", err)
	}
	return n, tx.Commit(ctx)
}
