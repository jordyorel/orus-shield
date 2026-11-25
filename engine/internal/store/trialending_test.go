package store

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/jordyorel/orus-shield/engine/internal/finding"
	"github.com/jordyorel/orus-shield/engine/internal/plan"
)

func TestTrialEndingEmail(t *testing.T) {
	l := newLifecycle(t)
	ctx := context.Background()
	l.member("admin@example.com", RoleAdmin, true)
	l.member("pending-admin@example.com", RoleAdmin, false) // never activated: no email
	l.member("viewer@example.com", RoleViewer, true)
	if _, err := l.s.pool.Exec(ctx, "UPDATE targets SET verify_token = 'x', verified_at = now() WHERE id = $1", l.target.ID); err != nil {
		t.Fatal(err)
	}

	// Scans stamp finished_at with the real clock: the trial is placed on it.
	now := time.Now().UTC().Truncate(time.Second)
	end := now.Add(2*24*time.Hour + time.Hour) // within the 3-day notice
	trial := func(event string, sub plan.Subscription) {
		t.Helper()
		if _, err := l.s.Billing().Apply(ctx, ProviderUpdate{EventID: event, EventType: "subscription.updated",
			OrgID: l.org.ID(), Sub: sub, Provider: "paddle", Ref: "sub_1", Customer: "ctm_1"}); err != nil {
			t.Fatal(err)
		}
	}
	trial("evt_1", plan.Subscription{Plan: plan.Pro, Status: plan.Trialing, TrialEndsAt: &end})

	// The same check failing on two names is one problem line; a medium one
	// is fixed by the second scan.
	crit := withSeverity(makeFinding("tls", "tls-cert-expired", "example.com"), finding.SeverityCritical)
	crit2 := crit
	crit2.Asset = "www.example.com"
	crit2.ID = finding.NewID("tls", "tls-cert-expired", "example.com", crit2.Asset)
	medium := withSeverity(makeFinding("email", "spf-softfail", "example.com"), finding.SeverityMedium)
	low := withSeverity(makeFinding("email", "dmarc-missing", "example.com"), finding.SeverityLow)
	l.mustScan(now.Add(-5*24*time.Hour), []string{"email", "tls"}, nil, crit, crit2, medium, low)
	l.mustScan(now.Add(-4*24*time.Hour), []string{"email", "tls"}, nil, crit, crit2, low)

	// Four days before the end: too early.
	if n, err := l.s.QueueTrialEndings(ctx, end.Add(-4*24*time.Hour)); err != nil || n != 0 {
		t.Fatalf("too early: %d, %v", n, err)
	}
	if n, err := l.s.QueueTrialEndings(ctx, now); err != nil || n != 1 {
		t.Fatalf("queued %d, %v; want 1 (the activated admin)", n, err)
	}
	// Once per trial end.
	if n, err := l.s.QueueTrialEndings(ctx, now.Add(time.Hour)); err != nil || n != 0 {
		t.Fatalf("queued again: %d, %v", n, err)
	}
	var to string
	var raw []byte
	if err := l.s.pool.QueryRow(ctx, "SELECT recipient, payload FROM notifications WHERE kind = $1", NotifyTrialEnding).Scan(&to, &raw); err != nil {
		t.Fatal(err)
	}
	var p TrialEnding
	if err := json.Unmarshal(raw, &p); err != nil {
		t.Fatal(err)
	}
	if to != "admin@example.com" || p.OrgID != l.org.ID() || p.OrgName != "Default" || p.Plan != plan.Pro ||
		!p.TrialEndsAt.Equal(end) || p.Scans != 2 || p.Fixed != 1 || p.Open != 2 || p.Urgent != 1 || p.Domains != 1 {
		t.Errorf("payload = %+v (to %s)", p, to)
	}

	if ok, err := l.s.TrialEndingWanted(ctx, l.org.ID(), end, now); err != nil || !ok {
		t.Errorf("wanted = %v, %v", ok, err)
	}
	if ok, _ := l.s.TrialEndingWanted(ctx, l.org.ID(), end, end); ok {
		t.Error("wanted once the trial is over")
	}
	// The trial moves: the old email is unwanted, the new end gets its own.
	later := end.Add(time.Hour)
	trial("evt_2", plan.Subscription{Plan: plan.Pro, Status: plan.Trialing, TrialEndsAt: &later})
	if ok, _ := l.s.TrialEndingWanted(ctx, l.org.ID(), end, now); ok {
		t.Error("wanted after the trial moved")
	}
	if n, err := l.s.QueueTrialEndings(ctx, now); err != nil || n != 1 {
		t.Errorf("new end queued %d, %v", n, err)
	}
	// Canceled at Paddle: unwanted.
	trial("evt_3", plan.Subscription{Plan: plan.Pro, Status: plan.Canceled, PeriodEnd: &later})
	if ok, _ := l.s.TrialEndingWanted(ctx, l.org.ID(), later, now); ok {
		t.Error("wanted after cancellation")
	}

	// A manual trial (orusctl): nobody charges at its end, no email.
	l.clearNotifications()
	if err := l.s.SetSubscription(ctx, l.org.ID(), plan.Subscription{Plan: plan.SME, Status: plan.Trialing, TrialEndsAt: &end}, "manual", "test"); err != nil {
		t.Fatal(err)
	}
	if n, err := l.s.QueueTrialEndings(ctx, now); err != nil || n != 0 {
		t.Errorf("manual trial queued %d, %v", n, err)
	}
}
