package store

import (
	"context"
	"testing"
	"time"

	"github.com/jordyorel/orus-shield/engine/internal/plan"
)

func TestSubscriptions(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now()

	// Organizations from before the migration keep everything: Pro, no end.
	def := defaultOrg(t, s)
	if eff, err := def.Plan(ctx, now); err != nil || eff.Plan.ID != plan.Pro || eff.Until != nil {
		t.Errorf("Default plan = %+v, %v", eff, err)
	}

	// A new organization starts a 14-day Essentiel trial.
	o, err := s.CreateOrganization(ctx, "Newco", "test")
	if err != nil {
		t.Fatal(err)
	}
	org, _ := s.Org(o.ID)
	sub, err := org.Subscription(ctx)
	if err != nil || sub == nil || sub.Plan != plan.SME || sub.Status != plan.Trialing || sub.TrialEndsAt == nil {
		t.Fatalf("new subscription = %+v, %v", sub, err)
	}
	if d := sub.TrialEndsAt.Sub(now); d < 13*24*time.Hour || d > 15*24*time.Hour {
		t.Errorf("trial ends in %v, want 14 days", d)
	}
	if eff := plan.Resolve(sub, now.AddDate(0, 0, 15)); eff.Plan.ID != plan.Discovery || !eff.Lapsed {
		t.Errorf("after the trial: %+v", eff)
	}

	// orusctl sets a paid period; it is audited.
	end := now.AddDate(0, 1, 0)
	if err := s.SetSubscription(ctx, o.ID, plan.Subscription{Plan: plan.Pro, Status: plan.Active, PeriodEnd: &end}, "manual", "jordy"); err != nil {
		t.Fatal(err)
	}
	if eff, _ := org.Plan(ctx, now); eff.Plan.ID != plan.Pro {
		t.Errorf("after set: %+v", eff)
	}
	if got, err := s.SubscriptionOf(ctx, o.ID); err != nil || got.Plan != plan.Pro || got.PeriodEnd == nil {
		t.Errorf("SubscriptionOf = %+v, %v", got, err)
	}
	audit, _ := org.AuditLog(ctx, "")
	found := false
	for _, e := range audit {
		found = found || e.Action == ActionPlanChanged
	}
	if !found {
		t.Error("no plan.changed audit entry")
	}
	for _, bad := range []plan.Subscription{{Plan: "gold", Status: plan.Active}, {Plan: plan.SME, Status: plan.Trialing}} {
		if err := s.SetSubscription(ctx, o.ID, bad, "manual", "jordy"); err == nil {
			t.Errorf("%+v: nil error", bad)
		}
	}

	// Each organization reads only its own.
	if n, err := org.CountTargets(ctx); err != nil || n != 0 {
		t.Errorf("count = %d, %v", n, err)
	}
	newTarget(t, s, "example.com")
	if n, _ := def.CountTargets(ctx); n != 1 {
		t.Errorf("Default count = %d", n)
	}
	if n, _ := org.CountTargets(ctx); n != 0 {
		t.Errorf("Newco sees %d targets of Default", n)
	}
}
