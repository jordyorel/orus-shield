package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestDeepScans(t *testing.T) {
	l := newLifecycle(t)
	s, ctx := l.s, context.Background()
	if _, err := l.org.EnqueueScan(ctx, l.target.ID, []string{"ports"}, "jordy"); err != nil {
		t.Fatal(err)
	}
	sc, ok, err := s.ClaimScan(ctx, "worker:test", time.Minute, 3)
	if err != nil || !ok {
		t.Fatalf("claim: %v, %v", ok, err)
	}
	// A stale attempt cannot mark it: fenced like every scan update.
	if err := s.MarkScanDeep(ctx, sc.ID, sc.Attempt+1); !errors.Is(err, ErrLeaseLost) {
		t.Errorf("stale attempt = %v, want ErrLeaseLost", err)
	}
	if err := s.MarkScanDeep(ctx, sc.ID, sc.Attempt); err != nil {
		t.Fatal(err)
	}
	month := MonthStart(time.Now())
	if n, err := s.DeepScansSince(ctx, l.target.OrgID, month); err != nil || n != 1 {
		t.Errorf("worker count = %d, %v", n, err)
	}
	if n, err := l.org.DeepScansSince(ctx, month); err != nil || n != 1 {
		t.Errorf("org count = %d, %v", n, err)
	}
	if n, err := s.DeepScansSince(ctx, l.target.OrgID, month.AddDate(0, 1, 0)); err != nil || n != 0 {
		t.Errorf("next month = %d, %v", n, err)
	}
	if got := MonthStart(time.Date(2026, 11, 30, 23, 30, 0, 0, time.FixedZone("UTC-2", -2*3600))); !got.Equal(time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("MonthStart = %v, want December in UTC", got)
	}
}
