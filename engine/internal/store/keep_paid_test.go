package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/jordyorel/orus-shield/engine/internal/plan"
)

// An organization whose Paddle subscription runs cannot be deleted: its
// subscription would keep running at Paddle (migration 0035).
func TestOrganizationWithRunningSubscriptionIsKept(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	// deleteOrg deletes an organization and returns the error, then rolls
	// back. audit_log is append-only and its foreign key keeps every audited
	// organization; the transaction lifts that, in this test's own schema
	// only, so what is left is migration 0035's trigger. The trigger fires
	// before the foreign key check either way.
	deleteOrg := func(id string) error {
		t.Helper()
		tx, err := s.pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx) //nolint:errcheck // nothing to keep
		if _, err := tx.Exec(ctx, "ALTER TABLE audit_log DISABLE TRIGGER audit_log_no_update_delete"); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, "DELETE FROM audit_log WHERE org_id = $1", id); err != nil {
			t.Fatal(err)
		}
		_, err = tx.Exec(ctx, "DELETE FROM organizations WHERE id = $1", id)
		return err
	}

	// A free organization (manual subscription) goes.
	free, err := s.CreateOrganization(ctx, "Free", "test")
	if err != nil {
		t.Fatal(err)
	}
	if err := deleteOrg(free.ID); err != nil {
		t.Errorf("delete free organization: %v", err)
	}

	paid, err := s.CreateOrganization(ctx, "Paid", "test")
	if err != nil {
		t.Fatal(err)
	}
	end := time.Now().AddDate(0, 0, 14)
	apply := func(event string, sub plan.Subscription) {
		t.Helper()
		if _, err := s.Billing().Apply(ctx, ProviderUpdate{
			EventID: event, EventType: "subscription.updated", OrgID: paid.ID, Sub: sub,
			Provider: "paddle", Ref: "sub_test", Customer: "ctm_test",
		}); err != nil {
			t.Fatal(err)
		}
	}
	for _, step := range []struct {
		event string
		sub   plan.Subscription
	}{
		{"evt_1", plan.Subscription{Plan: plan.Pro, Status: plan.Trialing, TrialEndsAt: &end}},
		{"evt_2", plan.Subscription{Plan: plan.Pro, Status: plan.Active, PeriodEnd: &end}},
	} {
		apply(step.event, step.sub)
		err := deleteOrg(paid.ID)
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "23001" {
			t.Fatalf("%s: delete = %v, want restrict_violation", step.sub.Status, err)
		}
	}
	// The caller's organization setting survives the trigger's lookup.
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, "SELECT set_config('app.org_id', $1, true)", free.ID); err != nil {
		t.Fatal(err)
	}
	_, _ = tx.Exec(ctx, "SAVEPOINT d")
	if _, err := tx.Exec(ctx, "DELETE FROM organizations WHERE id = $1", paid.ID); err == nil {
		t.Fatal("delete in transaction: nil error")
	}
	_, _ = tx.Exec(ctx, "ROLLBACK TO SAVEPOINT d")
	var got string
	if err := tx.QueryRow(ctx, "SELECT current_setting('app.org_id', true)").Scan(&got); err != nil || got != free.ID {
		t.Errorf("app.org_id after the trigger = %q, %v", got, err)
	}
	_ = tx.Rollback(ctx)

	// Canceled at Paddle (now or at the period's end): it may go.
	apply("evt_3", plan.Subscription{Plan: plan.Pro, Status: plan.Canceled, PeriodEnd: &end})
	if err := deleteOrg(paid.ID); err != nil {
		t.Errorf("delete after cancellation: %v", err)
	}
}
