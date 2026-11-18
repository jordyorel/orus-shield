package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/jordyorel/orus-shield/engine/internal/plan"
)

const billingRole = "orus_billing"

// Billing is the store handle of the payment webhooks: it writes
// subscriptions and their audit entries, nothing else.
type Billing struct{ pool *pgxpool.Pool }

// Billing returns the payment webhooks' handle.
func (s *Store) Billing() *Billing { return &Billing{pool: s.pool} }

// ProviderUpdate is a subscription as a payment provider reports it.
type ProviderUpdate struct {
	EventID, EventType string
	OrgID              string
	Sub                plan.Subscription
	Provider           string // "paddle"
	Ref                string // the provider's subscription ID
	Customer           string // the provider's customer ID
	Period             string // "monthly" or "yearly"; "" when unknown
	// OnlyIfNew: apply only if the organization does not have this
	// subscription (Ref) recorded yet. A sync on the customer's return uses
	// it, so it never overwrites what a webhook recorded since.
	OnlyIfNew bool
}

// Apply records a provider's subscription update once per event: an event
// already handled is ignored (applied=false). An unknown organization is
// ErrNotFound.
func (b *Billing) Apply(ctx context.Context, u ProviderUpdate) (applied bool, err error) {
	if !isUUID(u.OrgID) {
		return false, ErrNotFound
	}
	if _, ok := plan.Get(u.Sub.Plan); !ok || !u.Sub.Status.Valid() {
		return false, fmt.Errorf("apply subscription: invalid plan %q or status %q", u.Sub.Plan, u.Sub.Status)
	}
	tx, err := b.pool.Begin(ctx)
	if err != nil {
		return false, fmt.Errorf("apply subscription: %w", err)
	}
	defer tx.Rollback(ctx)
	// billingRole is a constant: no injection possible.
	if _, err := tx.Exec(ctx, "SET LOCAL ROLE "+billingRole); err != nil {
		return false, fmt.Errorf("apply subscription: %w", err)
	}
	var exists bool
	if err := tx.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM organizations WHERE id = $1)", u.OrgID).Scan(&exists); err != nil {
		return false, fmt.Errorf("apply subscription: %w", err)
	}
	if !exists {
		return false, ErrNotFound
	}
	if _, err := tx.Exec(ctx, "SAVEPOINT event"); err != nil {
		return false, err
	}
	_, err = tx.Exec(ctx, "INSERT INTO billing_events (event_id, event_type, org_id) VALUES ($1, $2, $3)", u.EventID, u.EventType, u.OrgID)
	if isUniqueViolation(err) {
		return false, nil // handled before
	}
	if err != nil {
		return false, fmt.Errorf("apply subscription: %w", err)
	}
	tag, err := tx.Exec(ctx, `
		INSERT INTO subscriptions (org_id, plan, status, trial_ends_at, period_end, provider, provider_ref, provider_customer, billing_period, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, now())
		ON CONFLICT (org_id) DO UPDATE SET plan = $2, status = $3, trial_ends_at = $4, period_end = $5,
			provider = $6, provider_ref = $7, provider_customer = $8,
			billing_period = coalesce($9, subscriptions.billing_period), updated_at = now()
		WHERE NOT $10 OR subscriptions.provider_ref IS DISTINCT FROM $7`,
		u.OrgID, string(u.Sub.Plan), string(u.Sub.Status), u.Sub.TrialEndsAt, u.Sub.PeriodEnd, u.Provider, nullable(u.Ref), nullable(u.Customer),
		nullable(u.Period), u.OnlyIfNew)
	if err != nil {
		return false, fmt.Errorf("apply subscription: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return false, nil // OnlyIfNew: a webhook recorded it already
	}
	if err := appendAudit(ctx, tx, AuditEntry{
		OrgID: u.OrgID, Actor: u.Provider, Action: ActionPlanChanged,
		Details: map[string]any{"plan": u.Sub.Plan, "status": u.Sub.Status, "period_end": u.Sub.PeriodEnd,
			"trial_ends_at": u.Sub.TrialEndsAt, "provider": u.Provider, "event": u.EventType, "event_id": u.EventID},
	}); err != nil {
		return false, err
	}
	return true, tx.Commit(ctx)
}

// BillingAccount is what the API needs to open a customer's portal.
type BillingAccount struct {
	Provider, Ref, Customer string
	Period                  string // "monthly", "yearly", or "" when unknown
}

// BillingAccount returns the organization's payment provider account, nil
// when it pays no provider (free, trial, manual).
func (o *Org) BillingAccount(ctx context.Context) (*BillingAccount, error) {
	tx, err := o.begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("billing account: %w", err)
	}
	defer tx.Rollback(ctx)
	var a BillingAccount
	err = tx.QueryRow(ctx, `SELECT provider, coalesce(provider_ref, ''), coalesce(provider_customer, ''), coalesce(billing_period, '')
		FROM subscriptions WHERE org_id = $1 AND provider_customer IS NOT NULL`, o.orgID).Scan(&a.Provider, &a.Ref, &a.Customer, &a.Period)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, tx.Commit(ctx)
	}
	if err != nil {
		return nil, fmt.Errorf("billing account: %w", err)
	}
	return &a, tx.Commit(ctx)
}

// pendingCheckoutTTL is how long a checkout waits for its payment.
const pendingCheckoutTTL = 48 * time.Hour

// AddPendingCheckout records a transaction created for a checkout, so the
// subscription can be recorded once paid even without the webhook.
func (o *Org) AddPendingCheckout(ctx context.Context, transactionID string) error {
	tx, err := o.begin(ctx)
	if err != nil {
		return fmt.Errorf("add pending checkout: %w", err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `INSERT INTO pending_checkouts (org_id, transaction_id) VALUES ($1, $2)
		ON CONFLICT DO NOTHING`, o.orgID, transactionID); err != nil {
		return fmt.Errorf("add pending checkout: %w", err)
	}
	return tx.Commit(ctx)
}

// LatestPendingCheckout returns the organization's latest checkout still
// waiting (under two days old), "" when none. Older ones are forgotten.
func (o *Org) LatestPendingCheckout(ctx context.Context, now time.Time) (string, error) {
	tx, err := o.begin(ctx)
	if err != nil {
		return "", fmt.Errorf("pending checkout: %w", err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, "DELETE FROM pending_checkouts WHERE org_id = $1 AND created_at < $2",
		o.orgID, now.Add(-pendingCheckoutTTL)); err != nil {
		return "", fmt.Errorf("pending checkout: %w", err)
	}
	var id string
	err = tx.QueryRow(ctx, `SELECT transaction_id FROM pending_checkouts WHERE org_id = $1
		ORDER BY created_at DESC LIMIT 1`, o.orgID).Scan(&id)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return "", fmt.Errorf("pending checkout: %w", err)
	}
	return id, tx.Commit(ctx)
}

// ClearPendingCheckouts forgets the organization's checkouts: one was paid
// and recorded.
func (o *Org) ClearPendingCheckouts(ctx context.Context) error {
	tx, err := o.begin(ctx)
	if err != nil {
		return fmt.Errorf("clear pending checkouts: %w", err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, "DELETE FROM pending_checkouts WHERE org_id = $1", o.orgID); err != nil {
		return fmt.Errorf("clear pending checkouts: %w", err)
	}
	return tx.Commit(ctx)
}
