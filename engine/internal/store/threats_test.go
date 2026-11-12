package store

import (
	"github.com/jordyorel/orus-shield/engine/internal/plan"

	"context"
	"encoding/json"
	"testing"
	"time"
)

// verify marks a target verified and gives it a hostname with detected
// technologies, as the vulns module would.
func verifyWithTech(t *testing.T, s *Store, target Target, tech string) {
	t.Helper()
	ctx := context.Background()
	if _, err := s.pool.Exec(ctx, `UPDATE targets SET verify_token = 'tok', verified_at = now() WHERE id = $1`, target.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.pool.Exec(ctx, `
		INSERT INTO assets (org_id, target_id, kind, value, details, sources, first_seen, last_seen)
		VALUES ($1, $2, 'hostname', $3, jsonb_build_object('technologies', $4::text), '{vulns}', now(), now())`,
		target.OrgID, target.ID, "www."+target.Domain, tech); err != nil {
		t.Fatal(err)
	}
}

func TestThreats(t *testing.T) {
	l := newLifecycle(t)
	s, ctx := l.s, context.Background()
	l.member("admin@example.com", RoleAdmin, true)
	now := time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC)

	// First sync: the baseline. Only the template marked New is emerging.
	n, err := s.SyncThreatTemplates(ctx, []ThreatTemplate{
		{ID: "CVE-2020-1", CVE: "CVE-2020-1", Name: "Old WordPress bug", Severity: "high", Products: []string{"wordpress"}},
		{ID: "CVE-2026-1", CVE: "CVE-2026-1", Name: "New WordPress RCE", Severity: "critical", Products: []string{"wordpress"}, KEV: true, EPSS: 0.4, New: true},
	}, now)
	if err != nil || n != 2 {
		t.Fatalf("first sync: %d, %v", n, err)
	}
	// A later sync: every template not seen before is emerging.
	if n, err := s.SyncThreatTemplates(ctx, []ThreatTemplate{
		{ID: "CVE-2026-1", Name: "again", Severity: "critical", Products: []string{"wordpress"}},
		{ID: "CVE-2026-2", CVE: "CVE-2026-2", Name: "Jira bug", Severity: "high", Products: []string{"jira"}},
	}, now.Add(time.Hour)); err != nil || n != 1 {
		t.Fatalf("second sync: %d, %v", n, err)
	}
	pending, err := s.PendingThreats(ctx, 10)
	if err != nil || len(pending) != 2 || pending[0].ID != "CVE-2026-1" || pending[1].ID != "CVE-2026-2" || !pending[0].KEV {
		t.Fatalf("pending = %+v, %v", pending, err)
	}

	// Technologies: only verified targets count.
	verifyWithTech(t, s, l.target, "WordPress 6.1, nginx")
	other := newTarget(t, s, "unverified.example")
	if _, err := s.pool.Exec(ctx, `
		INSERT INTO assets (org_id, target_id, kind, value, details, sources, first_seen, last_seen)
		VALUES ($1, $2, 'hostname', 'unverified.example', '{"technologies": "WordPress"}', '{vulns}', now(), now())`,
		other.OrgID, other.ID); err != nil {
		t.Fatal(err)
	}
	techs, err := s.VerifiedTargetTechnologies(ctx)
	if err != nil || len(techs) != 1 || techs[0].TargetID != l.target.ID || techs[0].Technologies[0] != "WordPress 6.1, nginx" {
		t.Fatalf("technologies = %+v, %v", techs, err)
	}

	match := []ThreatMatch{{TemplateID: "CVE-2026-1", TargetID: l.target.ID, Products: []string{"wordpress"}}}
	rescans, err := s.RecordThreats(ctx, []string{"CVE-2026-1", "CVE-2026-2"}, match, now)
	if err != nil || rescans != 1 {
		t.Fatalf("record: %d, %v", rescans, err)
	}
	// Both templates are processed, the matched one and the unmatched one.
	if p, _ := s.PendingThreats(ctx, 10); len(p) != 0 {
		t.Errorf("still pending: %+v", p)
	}
	// One vulns scan, requested by "threats", with its audit entry.
	scans, err := l.org.ListScans(ctx, l.target.ID, 10)
	if err != nil || len(scans) != 1 || scans[0].RequestedBy != ActorThreats || scans[0].Modules[0] != "vulns" {
		t.Fatalf("scans = %+v, %v", scans, err)
	}
	audit, _ := l.org.AuditLog(ctx, l.target.Domain)
	found := false
	for _, e := range audit {
		found = found || (e.Actor == ActorThreats && e.Action == ActionScanRequested)
	}
	if !found {
		t.Error("no audit entry for the rescan")
	}
	// One email to the activated admin.
	var kind, recipient string
	var payload []byte
	if err := s.pool.QueryRow(ctx, `SELECT kind, recipient, payload FROM notifications`).Scan(&kind, &recipient, &payload); err != nil {
		t.Fatal(err)
	}
	var a EmergingThreatAlert
	_ = json.Unmarshal(payload, &a)
	if kind != NotifyEmergingThreat || recipient != "admin@example.com" || a.Domain != "example.com" || a.ScanID != scans[0].ID ||
		a.Total != 1 || a.Threats[0].CVE != "CVE-2026-1" || !a.Threats[0].KEV || a.Threats[0].Products[0] != "wordpress" {
		t.Errorf("notification %s to %s: %+v", kind, recipient, a)
	}

	// The dashboard's list, for this organization only.
	views, err := l.org.ListThreats(ctx, 10)
	if err != nil || len(views) != 1 || views[0].CVE != "CVE-2026-1" || views[0].ScanID != scans[0].ID ||
		views[0].ScanStatus != "queued" || views[0].Domain != "example.com" {
		t.Fatalf("views = %+v, %v", views, err)
	}
	stranger, err := s.CreateOrganization(ctx, "Stranger", "test")
	if err != nil {
		t.Fatal(err)
	}
	so, _ := s.Org(stranger.ID)
	if v, err := so.ListThreats(ctx, 10); err != nil || len(v) != 0 {
		t.Errorf("another organization sees %d threats, %v", len(v), err)
	}

	// Recording the same match again (a retry): no second rescan.
	if _, err := s.pool.Exec(ctx, `UPDATE threat_templates SET processed_at = NULL`); err != nil {
		t.Fatal(err)
	}
	if rescans, err := s.RecordThreats(ctx, []string{"CVE-2026-1"}, match, now); err != nil || rescans != 0 {
		t.Errorf("retry: %d rescans, %v; want none", rescans, err)
	}

	// A new threat while the rescan still waits in the queue: the queued
	// vulns scan is reused, the admin is told.
	if _, err := s.SyncThreatTemplates(ctx, []ThreatTemplate{{ID: "CVE-2026-3", Name: "Another", Severity: "high", Products: []string{"nginx"}}}, now); err != nil {
		t.Fatal(err)
	}
	if rescans, err := s.RecordThreats(ctx, []string{"CVE-2026-3"},
		[]ThreatMatch{{TemplateID: "CVE-2026-3", TargetID: l.target.ID, Products: []string{"nginx"}}}, now); err != nil || rescans != 0 {
		t.Errorf("queued scan reused: %d rescans, %v", rescans, err)
	}
	if scans, _ := l.org.ListScans(ctx, l.target.ID, 10); len(scans) != 1 {
		t.Errorf("%d scans, want the queued one reused", len(scans))
	}
	var notes int
	_ = s.pool.QueryRow(ctx, `SELECT count(*) FROM notifications`).Scan(&notes)
	if notes != 2 {
		t.Errorf("%d notifications, want 2", notes)
	}
}

// An organization whose offer has no emerging threats (the free one) gets
// neither a match, nor a rescan, nor an email.
func TestThreatsFollowTheOffer(t *testing.T) {
	l := newLifecycle(t)
	s, ctx := l.s, context.Background()
	l.member("admin@example.com", RoleAdmin, true)
	now := time.Now()
	if err := s.SetSubscription(ctx, l.target.OrgID, plan.Subscription{Plan: plan.Discovery, Status: plan.Active}, "manual", "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SyncThreatTemplates(ctx, []ThreatTemplate{
		{ID: "CVE-2026-9", CVE: "CVE-2026-9", Name: "New WordPress RCE", Severity: "critical", Products: []string{"wordpress"}, New: true},
	}, now); err != nil {
		t.Fatal(err)
	}
	verifyWithTech(t, s, l.target, "WordPress 6.1")
	match := []ThreatMatch{{TemplateID: "CVE-2026-9", TargetID: l.target.ID, Products: []string{"wordpress"}}}
	rescans, err := s.RecordThreats(ctx, []string{"CVE-2026-9"}, match, now)
	if err != nil || rescans != 0 {
		t.Fatalf("record on the free offer: %d rescans, %v", rescans, err)
	}
	var matches, notes, scans int
	if err := s.pool.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM threat_matches WHERE target_id = $1),
		(SELECT count(*) FROM notifications WHERE target_id = $1 AND kind = $2),
		(SELECT count(*) FROM scans WHERE target_id = $1 AND requested_by = $3)`,
		l.target.ID, NotifyEmergingThreat, ActorThreats).Scan(&matches, &notes, &scans); err != nil {
		t.Fatal(err)
	}
	if matches != 0 || notes != 0 || scans != 0 {
		t.Errorf("free offer: %d matches, %d emails, %d rescans; want none", matches, notes, scans)
	}
	// Processed anyway: the template is not retried forever.
	if pending, err := s.PendingThreats(ctx, 10); err != nil || len(pending) != 0 {
		t.Errorf("pending = %+v, %v", pending, err)
	}
}
