package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

func newTarget(t *testing.T, s *Store, domain string) Target {
	t.Helper()
	target, err := defaultOrg(t, s).CreateTarget(context.Background(), NewTarget{Domain: domain})
	if err != nil {
		t.Fatalf("CreateTarget(%s): %v", domain, err)
	}
	return target
}

func enqueue(t *testing.T, s *Store, target Target, modules ...string) Scan {
	t.Helper()
	sc, err := defaultOrg(t, s).EnqueueScan(context.Background(), target.ID, modules, "jordy")
	if err != nil {
		t.Fatalf("EnqueueScan: %v", err)
	}
	return sc
}

func actions(t *testing.T, s *Store, domain string) []string {
	t.Helper()
	entries, err := defaultOrg(t, s).AuditLog(context.Background(), domain)
	if err != nil {
		t.Fatalf("AuditLog: %v", err)
	}
	var out []string
	for _, e := range entries {
		out = append(out, e.Actor+" "+e.Action)
	}
	return out
}

func TestEnqueueScanIsAudited(t *testing.T) {
	s := newTestStore(t)
	target := newTarget(t, s, "example.com")
	sc := enqueue(t, s, target, "email", "tls")

	if sc.Status != StatusQueued || sc.Attempt != 0 || sc.Domain != "example.com" {
		t.Errorf("scan = %+v", sc)
	}
	entries, err := defaultOrg(t, s).AuditLog(context.Background(), "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Actor != "jordy" || entries[0].Action != ActionScanRequested {
		t.Fatalf("audit = %+v, want one scan.requested by jordy", entries)
	}
	if !strings.Contains(string(entries[0].Details.(json.RawMessage)), sc.ID) {
		t.Errorf("audit details %s do not mention the scan ID", entries[0].Details)
	}
}

func TestEnqueueScanRejects(t *testing.T) {
	s := newTestStore(t)
	target := newTarget(t, s, "example.com")
	ctx := context.Background()

	if _, err := defaultOrg(t, s).EnqueueScan(ctx, target.ID, nil, "jordy"); err == nil {
		t.Error("EnqueueScan without modules = nil, want error")
	}
	if _, err := defaultOrg(t, s).EnqueueScan(ctx, target.ID, []string{"email"}, ""); err == nil {
		t.Error("EnqueueScan without requester = nil, want error")
	}
	_, err := defaultOrg(t, s).EnqueueScan(ctx, "0190a000-0000-7000-8000-000000000000", []string{"email"}, "jordy")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("EnqueueScan(unknown target) = %v, want ErrNotFound", err)
	}
}

func TestClaimOrderAndEmptyQueue(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	target := newTarget(t, s, "example.com")
	first := enqueue(t, s, target, "email")
	second := enqueue(t, s, target, "tls")

	got, ok, err := s.ClaimScan(ctx, "worker:a", time.Minute, 3)
	if err != nil || !ok || got.ID != first.ID {
		t.Fatalf("first claim = %+v, %v, %v; want scan %s", got, ok, err, first.ID)
	}
	if got.Status != StatusRunning || got.Attempt != 1 || got.StartedAt == nil {
		t.Errorf("claimed scan = %+v, want running, attempt 1, started", got)
	}
	got, ok, err = s.ClaimScan(ctx, "worker:b", time.Minute, 3)
	if err != nil || !ok || got.ID != second.ID {
		t.Fatalf("second claim = %+v, %v, %v; want scan %s", got, ok, err, second.ID)
	}
	if _, ok, err := s.ClaimScan(ctx, "worker:c", time.Minute, 3); err != nil || ok {
		t.Errorf("claim on empty queue = %v, %v; want nothing", ok, err)
	}

	want := []string{"jordy scan.requested", "jordy scan.requested", "worker:a scan.started", "worker:b scan.started"}
	if got := actions(t, s, "example.com"); strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("audit = %v, want %v", got, want)
	}
}

// Many workers claiming at once must each get a different scan.
func TestConcurrentClaimsNeverShareAScan(t *testing.T) {
	s := newTestStore(t)
	const n = 10
	// One scan per target: scans of one target with the same modules are
	// merged while they wait (TestEnqueueReusesWaitingScan).
	for i := range n {
		enqueue(t, s, newTarget(t, s, fmt.Sprintf("example%d.com", i)), "email")
	}

	var mu sync.Mutex
	claimed := make(map[string]int)
	var wg sync.WaitGroup
	for range n + 5 { // more workers than scans
		wg.Go(func() {
			sc, ok, err := s.ClaimScan(context.Background(), "worker", time.Minute, 3)
			if err != nil {
				t.Errorf("ClaimScan: %v", err)
				return
			}
			if ok {
				mu.Lock()
				claimed[sc.ID]++
				mu.Unlock()
			}
		})
	}
	wg.Wait()

	if len(claimed) != n {
		t.Errorf("%d distinct scans claimed, want %d", len(claimed), n)
	}
	for id, count := range claimed {
		if count != 1 {
			t.Errorf("scan %s claimed %d times", id, count)
		}
	}
}

// A crashed worker's scan is taken over once its lease expires, and the old
// worker can no longer touch it.
func TestExpiredLeaseIsReclaimedAndFenced(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	target := newTarget(t, s, "example.com")
	sc := enqueue(t, s, target, "email")

	old, _, err := s.ClaimScan(ctx, "worker:old", 50*time.Millisecond, 3)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := s.ClaimScan(ctx, "worker:new", time.Minute, 3); ok {
		t.Fatal("scan was claimed again while its lease was valid")
	}
	time.Sleep(150 * time.Millisecond)

	taken, ok, err := s.ClaimScan(ctx, "worker:new", time.Minute, 3)
	if err != nil || !ok || taken.ID != sc.ID || taken.Attempt != 2 {
		t.Fatalf("reclaim = %+v, %v, %v; want scan %s at attempt 2", taken, ok, err, sc.ID)
	}

	if err := s.ExtendLease(ctx, sc.ID, old.Attempt, time.Minute); !errors.Is(err, ErrLeaseLost) {
		t.Errorf("old worker ExtendLease = %v, want ErrLeaseLost", err)
	}
	if err := s.FailScan(ctx, sc.ID, old.Attempt, "worker:old", "late"); !errors.Is(err, ErrLeaseLost) {
		t.Errorf("old worker FailScan = %v, want ErrLeaseLost", err)
	}
	if err := s.ExtendLease(ctx, sc.ID, taken.Attempt, time.Minute); err != nil {
		t.Errorf("new worker ExtendLease = %v", err)
	}
}

func TestScanAbandonedAfterMaxAttempts(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	target := newTarget(t, s, "example.com")
	sc := enqueue(t, s, target, "email")

	if _, _, err := s.ClaimScan(ctx, "worker:a", 50*time.Millisecond, 1); err != nil {
		t.Fatal(err)
	}
	time.Sleep(150 * time.Millisecond)

	if _, ok, err := s.ClaimScan(ctx, "worker:b", time.Minute, 1); err != nil || ok {
		t.Fatalf("claim = %v, %v; want nothing (attempts exhausted)", ok, err)
	}
	got, err := defaultOrg(t, s).GetScan(ctx, sc.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != StatusFailed || !strings.Contains(got.Error, "abandoned") || got.FinishedAt == nil {
		t.Errorf("scan = %+v, want failed/abandoned", got)
	}
	audit := actions(t, s, "example.com")
	if audit[len(audit)-1] != "queue scan.failed" {
		t.Errorf("last audit entry = %q, want queue scan.failed", audit[len(audit)-1])
	}
}

func TestFailScan(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	target := newTarget(t, s, "example.com")
	enqueue(t, s, target, "email")
	sc, _, err := s.ClaimScan(ctx, "worker:a", time.Minute, 3)
	if err != nil {
		t.Fatal(err)
	}

	long := strings.Repeat("é", maxErrorChars+500)
	if err := s.FailScan(ctx, sc.ID, sc.Attempt, "worker:a", long); err != nil {
		t.Fatalf("FailScan: %v", err)
	}
	got, err := defaultOrg(t, s).GetScan(ctx, sc.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != StatusFailed || len([]rune(got.Error)) != maxErrorChars {
		t.Errorf("scan = status %s, error of %d characters; want failed, %d", got.Status, len([]rune(got.Error)), maxErrorChars)
	}
	if err := s.FailScan(ctx, sc.ID, sc.Attempt, "worker:a", "again"); !errors.Is(err, ErrLeaseLost) {
		t.Errorf("second FailScan = %v, want ErrLeaseLost", err)
	}
}

// A scan still waiting with at least the requested modules answers a new
// request; once it started, a new scan is queued. Every request is audited.
func TestEnqueueReusesWaitingScan(t *testing.T) {
	s := newTestStore(t)
	org := defaultOrg(t, s)
	target := newTarget(t, s, "example.com")
	ctx := context.Background()
	first, err := org.EnqueueScan(ctx, target.ID, []string{"email", "tls"}, "jordy")
	if err != nil {
		t.Fatal(err)
	}
	again, err := org.EnqueueScan(ctx, target.ID, []string{"tls"}, "alice")
	if err != nil || again.ID != first.ID {
		t.Errorf("covered request = %s, %v; want the waiting scan %s", again.ID, err, first.ID)
	}
	other, err := org.EnqueueScan(ctx, target.ID, []string{"ports"}, "alice")
	if err != nil || other.ID == first.ID {
		t.Errorf("other modules = %s, %v; want a new scan", other.ID, err)
	}
	if _, ok, err := s.ClaimScan(ctx, "worker", time.Minute, 3); err != nil || !ok {
		t.Fatalf("claim: %v %v", ok, err)
	}
	after, err := org.EnqueueScan(ctx, target.ID, []string{"tls"}, "jordy")
	if err != nil || after.ID == first.ID {
		t.Errorf("after the claim = %s, %v; want a new scan", after.ID, err)
	}
	entries, err := org.AuditLog(ctx, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	requests := 0
	for _, e := range entries {
		if e.Action == ActionScanRequested {
			requests++
		}
	}
	if requests != 4 {
		t.Errorf("%d scan requests audited, want 4", requests)
	}
}
