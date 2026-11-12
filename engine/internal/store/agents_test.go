package store

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func TestAgentLifecycle(t *testing.T) {
	s := newTestStore(t)
	org := defaultOrg(t, s)
	ctx := context.Background()
	g := s.Agents()

	a, code, err := org.CreateAgent(ctx, "Bureau Brazzaville", []string{"10.0.0.0/24"}, "jordy")
	if err != nil || code == "" || a.EnrollExpiresAt == nil || a.Domain == "" {
		t.Fatalf("create = %+v %q, %v", a, code, err)
	}
	// The internal network is a verified, internal target.
	var internal bool
	var verified *time.Time
	if err := s.pool.QueryRow(ctx, "SELECT internal, verified_at FROM targets WHERE id = $1", a.TargetID).Scan(&internal, &verified); err != nil || !internal || verified == nil {
		t.Fatalf("internal target: %v %v, %v", internal, verified, err)
	}

	if _, _, err := g.Enrol(ctx, "wrong", "h", "linux", "1"); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("wrong code = %v", err)
	}
	info, token, err := g.Enrol(ctx, code, "srv-01", "linux/amd64", "0.1.0")
	if err != nil || token == "" || info.ID != a.ID || info.TargetID != a.TargetID {
		t.Fatalf("enrol = %+v %q, %v", info, token, err)
	}
	if _, _, err := g.Enrol(ctx, code, "again", "linux", "1"); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("code reused = %v", err)
	}
	if got, err := g.Authenticate(ctx, token, "0.1.1"); err != nil || got.ID != a.ID {
		t.Fatalf("authenticate = %+v, %v", got, err)
	}

	// A scan of the internal network goes to the agent, never to a worker.
	if _, err := org.EnqueueScan(ctx, a.TargetID, []string{"ports"}, "jordy"); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := s.ClaimScan(ctx, "worker", time.Minute, 3); err != nil || ok {
		t.Fatalf("worker claimed an internal scan: %v %v", ok, err)
	}
	job, ok, err := g.ClaimScan(ctx, info, time.Minute, 3)
	if err != nil || !ok || job.Scan.TargetID != a.TargetID || job.RatePerSec <= 0 {
		t.Fatalf("agent claim = %+v %v, %v", job, ok, err)
	}
	if err := g.ExtendLease(ctx, info, job.Scan.ID, job.Scan.Attempt, time.Minute); err != nil {
		t.Errorf("extend = %v", err)
	}
	payload := json.RawMessage(`{"results":{}}`)
	if err := g.SubmitResult(ctx, info, job.Scan.ID, job.Scan.Attempt+1, payload); !errors.Is(err, ErrLeaseLost) {
		t.Errorf("stale attempt = %v", err)
	}
	if err := g.SubmitResult(ctx, info, job.Scan.ID, job.Scan.Attempt, payload); err != nil {
		t.Fatal(err)
	}
	r, ok, err := s.ClaimAgentResult(ctx)
	if err != nil || !ok || r.Scan.ID != job.Scan.ID || r.AgentID != a.ID || len(r.Ranges) != 1 {
		t.Fatalf("claim result = %+v %v, %v", r, ok, err)
	}
	if _, ok, _ := s.ClaimAgentResult(ctx); ok {
		t.Error("a result was claimed twice")
	}

	// Another organization's agent cannot see this one's scans.
	other, err := s.CreateOrganization(ctx, "Other", "test")
	if err != nil {
		t.Fatal(err)
	}
	oorg, _ := s.Org(other.ID)
	b, bcode, err := oorg.CreateAgent(ctx, "Other office", []string{"192.168.1.0/24"}, "x")
	if err != nil {
		t.Fatal(err)
	}
	binfo, _, err := g.Enrol(ctx, bcode, "h", "linux", "1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := org.EnqueueScan(ctx, a.TargetID, []string{"tls"}, "jordy"); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := g.ClaimScan(ctx, binfo, time.Minute, 3); err != nil || ok {
		t.Errorf("another org's agent claimed: %v %v", ok, err)
	}
	if list, _ := oorg.ListAgents(ctx); len(list) != 1 || list[0].ID != b.ID {
		t.Errorf("other org lists %+v", list)
	}

	// Revoked: the token stops working at once.
	if err := org.RevokeAgent(ctx, a.ID, "jordy"); err != nil {
		t.Fatal(err)
	}
	if _, err := g.Authenticate(ctx, token, ""); !errors.Is(err, ErrRevoked) {
		t.Errorf("revoked agent = %v", err)
	}
	if _, err := org.NewEnrolmentCode(ctx, a.ID, "jordy"); !errors.Is(err, ErrNotFound) {
		t.Errorf("code for a revoked agent = %v", err)
	}
}
