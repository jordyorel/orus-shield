package store

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
	"slices"
	"testing"
	"time"

	"github.com/jordyorel/orus-shield/engine/internal/finding"
	"github.com/jordyorel/orus-shield/engine/internal/plan"
)

// member adds a user to the lifecycle's organization; activated users
// have a password.
func (l *lifecycle) member(email, role string, activated bool) {
	l.t.Helper()
	ctx := context.Background()
	u, err := l.s.CreateUser(ctx, email)
	if err != nil {
		l.t.Fatal(err)
	}
	if err := l.s.SetMembership(ctx, u.ID, l.org.ID(), role, "test"); err != nil {
		l.t.Fatal(err)
	}
	if activated {
		token, err := l.s.IssueSetupToken(ctx, u.ID, time.Hour, "test")
		if err != nil {
			l.t.Fatal(err)
		}
		if _, err := l.s.Auth().SetPasswordWithToken(ctx, token, "$argon2id$x", ""); err != nil {
			l.t.Fatal(err)
		}
	}
}

// pending returns the queued new_findings notifications, by recipient.
func (l *lifecycle) pending() map[string]NewFindingsAlert {
	l.t.Helper()
	rows, err := l.s.pool.Query(context.Background(),
		"SELECT recipient, payload FROM notifications WHERE sent_at IS NULL AND failed_at IS NULL AND kind = $1", NotifyNewFindings)
	if err != nil {
		l.t.Fatal(err)
	}
	defer rows.Close()
	out := map[string]NewFindingsAlert{}
	for rows.Next() {
		var to string
		var raw []byte
		if err := rows.Scan(&to, &raw); err != nil {
			l.t.Fatal(err)
		}
		var a NewFindingsAlert
		if err := json.Unmarshal(raw, &a); err != nil {
			l.t.Fatal(err)
		}
		out[to] = a
	}
	return out
}

func (l *lifecycle) clearNotifications() {
	l.t.Helper()
	if _, err := l.s.pool.Exec(context.Background(), "DELETE FROM notifications"); err != nil {
		l.t.Fatal(err)
	}
}

func withSeverity(f finding.Finding, sev finding.Severity) finding.Finding {
	f.Severity = sev
	return f
}

func TestScansQueueAlertsForAdmins(t *testing.T) {
	l := newLifecycle(t)
	l.member("admin@example.com", RoleAdmin, true)
	l.member("pending-admin@example.com", RoleAdmin, false) // never activated: no email
	l.member("viewer@example.com", RoleViewer, true)        // viewers get no alerts yet
	both := []string{"email", "tls"}

	crit := withSeverity(makeFinding("tls", "tls-cert-expired", "example.com"), finding.SeverityCritical)
	high := withSeverity(makeFinding("email", "dmarc-missing", "example.com"), finding.SeverityHigh)
	medium := withSeverity(makeFinding("email", "spf-softfail", "example.com"), finding.SeverityMedium)

	// Scan 1: three new findings, two worth an alert.
	l.mustScan(t1, both, nil, crit, high, medium)
	got := l.pending()
	if len(got) != 1 {
		t.Fatalf("notifications to %v, want admin@example.com only", slices.Collect(maps.Keys(got)))
	}
	a := got["admin@example.com"]
	if a.Total != 2 || len(a.Findings) != 2 || a.Findings[0].Severity != finding.SeverityCritical ||
		a.Domain != "example.com" || a.OrgName != "Default" || a.OrgID != l.org.ID() {
		t.Errorf("alert = %+v", a)
	}

	// Scan 2: the same findings again: nothing new, no alert.
	l.clearNotifications()
	l.mustScan(t2, both, nil, crit, high, medium)
	if n := len(l.pending()); n != 0 {
		t.Errorf("findings seen again queued %d alerts", n)
	}

	// Scan 3: the high one is fixed. Scan 4: it is back: an alert, marked
	// as a regression.
	l.mustScan(t3, both, nil, crit, medium)
	l.mustScan(t4, both, nil, crit, high, medium)
	a = l.pending()["admin@example.com"]
	if a.Total != 1 || len(a.Findings) != 1 || !a.Findings[0].Reopened || a.Findings[0].ID != high.ID {
		t.Errorf("regression alert = %+v", a)
	}
}

func TestAlertsAreBounded(t *testing.T) {
	l := newLifecycle(t)
	l.member("admin@example.com", RoleAdmin, true)
	var many []finding.Finding
	for i := range maxAlertFindings + 5 {
		f := makeFinding("email", "dmarc-missing", "example.com")
		f.Asset = "h" + string(rune('a'+i)) + ".example.com"
		f.ID = finding.NewID("email", "dmarc-missing", "example.com", f.Asset)
		many = append(many, withSeverity(f, finding.SeverityHigh))
	}
	l.mustScan(t1, []string{"email", "tls"}, nil, many...)
	a := l.pending()["admin@example.com"]
	if a.Total != maxAlertFindings+5 || len(a.Findings) != maxAlertFindings {
		t.Errorf("total %d, listed %d; want %d and %d", a.Total, len(a.Findings), maxAlertFindings+5, maxAlertFindings)
	}
}

func TestNotificationDelivery(t *testing.T) {
	l := newLifecycle(t)
	ctx := context.Background()
	l.member("a@example.com", RoleAdmin, true)
	l.member("b@example.com", RoleAdmin, true)
	l.mustScan(t1, []string{"email"}, nil, withSeverity(makeFinding("email", "dmarc-missing", "example.com"), finding.SeverityHigh))
	// The first scan's summaries are tested in TestFirstScanSummary.
	if _, err := l.s.pool.Exec(ctx, "DELETE FROM notifications WHERE kind = $1", NotifyFirstScan); err != nil {
		t.Fatal(err)
	}

	// A second ahead: the database stamps next_attempt_at with its own
	// clock, which may run a few milliseconds ahead of ours (Docker VM).
	now := time.Now().Add(time.Second)
	claimed, err := l.s.ClaimNotifications(ctx, now, 5*time.Minute, 10)
	if err != nil || len(claimed) != 2 || claimed[0].Attempts != 1 {
		t.Fatalf("claim = %+v, %v", claimed, err)
	}
	// Leased: a second claim gets nothing.
	if again, err := l.s.ClaimNotifications(ctx, now, 5*time.Minute, 10); err != nil || len(again) != 0 {
		t.Errorf("second claim = %d, %v; want none while leased", len(again), err)
	}

	if err := l.s.MarkNotificationSent(ctx, claimed[0].ID, now); err != nil {
		t.Fatal(err)
	}
	if err := l.s.RetryNotification(ctx, claimed[1].ID, "connection refused", now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	// Due again a minute later; the sent one never comes back.
	retry, err := l.s.ClaimNotifications(ctx, now.Add(2*time.Minute), 5*time.Minute, 10)
	if err != nil || len(retry) != 1 || retry[0].ID != claimed[1].ID || retry[0].Attempts != 2 {
		t.Fatalf("retry claim = %+v, %v", retry, err)
	}
	if err := l.s.AbandonNotification(ctx, retry[0].ID, "gave up", now); err != nil {
		t.Fatal(err)
	}
	if rest, _ := l.s.ClaimNotifications(ctx, now.Add(24*time.Hour), time.Minute, 10); len(rest) != 0 {
		t.Errorf("abandoned or sent notifications claimed again: %d", len(rest))
	}
	if err := l.s.MarkNotificationSent(ctx, "not-a-uuid", now); err == nil {
		t.Error("bad id: nil error")
	}
}

// firstScanSummaries returns the queued first_scan notifications, by
// recipient.
func (l *lifecycle) firstScanSummaries() map[string]FirstScanSummary {
	l.t.Helper()
	rows, err := l.s.pool.Query(context.Background(),
		"SELECT recipient, payload FROM notifications WHERE kind = $1", NotifyFirstScan)
	if err != nil {
		l.t.Fatal(err)
	}
	defer rows.Close()
	out := map[string]FirstScanSummary{}
	for rows.Next() {
		var to string
		var raw []byte
		if err := rows.Scan(&to, &raw); err != nil {
			l.t.Fatal(err)
		}
		var p FirstScanSummary
		if err := json.Unmarshal(raw, &p); err != nil {
			l.t.Fatal(err)
		}
		out[to] = p
	}
	return out
}

func TestFirstScanSummary(t *testing.T) {
	l := newLifecycle(t)
	l.member("admin@example.com", RoleAdmin, true)
	l.member("pending-admin@example.com", RoleAdmin, false) // never activated: no email
	l.member("viewer@example.com", RoleViewer, true)

	crit := withSeverity(makeFinding("tls", "tls-cert-expired", "example.com"), finding.SeverityCritical)
	medium := withSeverity(makeFinding("email", "spf-softfail", "example.com"), finding.SeverityMedium)
	low := withSeverity(makeFinding("email", "dmarc-missing", "example.com"), finding.SeverityLow)

	// The first scan to finish sends one summary per activated admin, with
	// the open findings by severity, whatever the alert level.
	l.mustScan(t1, []string{"email", "tls"}, nil, crit, medium, low)
	got := l.firstScanSummaries()
	if len(got) != 1 {
		t.Fatalf("summaries to %v, want admin@example.com only", slices.Collect(maps.Keys(got)))
	}
	p := got["admin@example.com"]
	if p.Critical != 1 || p.High != 0 || p.Medium != 1 || p.Low != 1 || p.Domain != "example.com" ||
		p.OrgName != "Default" || p.OrgID != l.org.ID() || p.ScanID == "" {
		t.Errorf("summary = %+v", p)
	}

	// Later scans send none, even with new findings.
	l.clearNotifications()
	l.mustScan(t2, []string{"email", "tls"}, nil, crit, medium, low, withSeverity(makeFinding("email", "spf-missing", "example.com"), finding.SeverityHigh))
	if got := l.firstScanSummaries(); len(got) != 0 {
		t.Errorf("second scan queued summaries: %+v", got)
	}
}

func TestFirstScanSummaryFollowsEmailSwitch(t *testing.T) {
	l := newLifecycle(t)
	l.member("admin@example.com", RoleAdmin, true)
	if _, err := l.s.pool.Exec(context.Background(),
		"INSERT INTO org_settings (org_id, email_alerts) VALUES ($1, false)", l.org.ID()); err != nil {
		t.Fatal(err)
	}
	l.mustScan(t1, []string{"email", "tls"}, nil)
	if got := l.firstScanSummaries(); len(got) != 0 {
		t.Errorf("email switched off, summaries queued: %+v", got)
	}
}

func TestTrialNudgesAfterFreeAudit(t *testing.T) {
	l := newLifecycle(t)
	ctx := context.Background()
	l.member("admin@example.com", RoleAdmin, true)
	if err := l.s.SetSubscription(ctx, l.org.ID(), plan.Subscription{Plan: plan.Discovery, Status: plan.Active}, "manual", "test"); err != nil {
		t.Fatal(err)
	}
	high := withSeverity(makeFinding("email", "dmarc-missing", "example.com"), finding.SeverityHigh)
	l.mustScan(t1, []string{"email", "tls"}, nil, high)

	if p := l.firstScanSummaries()["admin@example.com"]; !p.Free {
		t.Errorf("summary after the free audit = %+v, want Free", p)
	}
	rows, err := l.s.pool.Query(ctx, "SELECT payload, created_at, next_attempt_at FROM notifications WHERE kind = $1 ORDER BY created_at", NotifyTrialNudge)
	if err != nil {
		t.Fatal(err)
	}
	var nudges []TrialNudge
	for rows.Next() {
		var raw []byte
		var created, next time.Time
		if err := rows.Scan(&raw, &created, &next); err != nil {
			t.Fatal(err)
		}
		var n TrialNudge
		if err := json.Unmarshal(raw, &n); err != nil {
			t.Fatal(err)
		}
		if want := t1.AddDate(0, 0, n.Day); !created.Equal(want) || !next.Equal(want) {
			t.Errorf("day %d due at %v / %v, want %v", n.Day, created, next, want)
		}
		nudges = append(nudges, n)
	}
	rows.Close()
	if len(nudges) != 2 || nudges[0].Day != 3 || nudges[1].Day != 10 || nudges[0].High != 1 || nudges[0].Open != 1 ||
		nudges[0].Top != high.Title || nudges[0].Unsubscribe == "" {
		t.Fatalf("nudges = %+v", nudges)
	}

	now := t1.AddDate(0, 0, 3)
	if ok, err := l.s.TrialNudgeWanted(ctx, l.org.ID(), "admin@example.com", now); err != nil || !ok {
		t.Errorf("wanted on Gratuit = %v, %v", ok, err)
	}
	// Unsubscribed (twice: idempotent): no more reminders.
	for range 2 {
		if err := l.s.Auth().Unsubscribe(ctx, nudges[0].Unsubscribe); err != nil {
			t.Fatalf("Unsubscribe: %v", err)
		}
	}
	if ok, _ := l.s.TrialNudgeWanted(ctx, l.org.ID(), "Admin@Example.com", now); ok {
		t.Error("wanted after unsubscribing")
	}
	if err := l.s.Auth().Unsubscribe(ctx, "not-a-token"); !errors.Is(err, ErrUnknownToken) {
		t.Errorf("unknown token = %v", err)
	}
	// Another admin, still subscribed, but the trial started: none either.
	end := now.AddDate(0, 0, 14)
	if err := l.s.SetSubscription(ctx, l.org.ID(), plan.Subscription{Plan: plan.SME, Status: plan.Trialing, TrialEndsAt: &end}, "manual", "test"); err != nil {
		t.Fatal(err)
	}
	if ok, _ := l.s.TrialNudgeWanted(ctx, l.org.ID(), "other@example.com", now); ok {
		t.Error("wanted during the trial")
	}

	// A paid organization's first scan: a summary, no reminders.
	l2 := newLifecycle(t)
	l2.member("admin@example.com", RoleAdmin, true)
	l2.mustScan(t1, []string{"email"}, nil)
	var n int
	if err := l2.s.pool.QueryRow(ctx, "SELECT count(*) FROM notifications WHERE kind = $1", NotifyTrialNudge).Scan(&n); err != nil || n != 0 {
		t.Errorf("paid organization's reminders = %d, %v", n, err)
	}
}
