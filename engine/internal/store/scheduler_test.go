package store

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/jordyorel/orus-shield/engine/internal/schedule"
)

func weeklySchedule(next time.Time) *TargetSchedule {
	return &TargetSchedule{
		Schedule:   schedule.Schedule{Frequency: schedule.Weekly, Weekday: time.Sunday, Hour: 2, TimeZone: "Europe/Paris"},
		Modules:    []string{"email", "tls"},
		NextScanAt: next,
	}
}

func setSchedule(t *testing.T, org *Org, targetID string, ts TargetSettings) Target {
	t.Helper()
	got, err := org.UpdateTargetSettings(context.Background(), targetID, ts)
	if err != nil {
		t.Fatalf("UpdateTargetSettings: %v", err)
	}
	return got
}

func scansOf(t *testing.T, org *Org, targetID string) []Scan {
	t.Helper()
	scans, err := org.ListScans(context.Background(), targetID, 100)
	if err != nil {
		t.Fatalf("ListScans: %v", err)
	}
	return scans
}

func TestScheduleIsStoredAndCleared(t *testing.T) {
	s := newTestStore(t)
	org := defaultOrg(t, s)
	target := newTarget(t, s, "example.com")
	if target.Schedule != nil {
		t.Fatalf("new target has a schedule: %+v", target.Schedule)
	}

	next := time.Date(2026, 11, 15, 1, 0, 0, 0, time.UTC)
	got := setSchedule(t, org, target.ID, TargetSettings{Schedule: weeklySchedule(next)})
	if got.Schedule == nil || got.Schedule.Frequency != schedule.Weekly || got.Schedule.Weekday != time.Sunday ||
		got.Schedule.Hour != 2 || got.Schedule.TimeZone != "Europe/Paris" ||
		!slices.Equal(got.Schedule.Modules, []string{"email", "tls"}) || !got.Schedule.NextScanAt.Equal(next) {
		t.Fatalf("stored schedule = %+v", got.Schedule)
	}

	// Changing only the rate keeps the schedule.
	rate := 10.0
	if got = setSchedule(t, org, target.ID, TargetSettings{RatePerSec: &rate}); got.Schedule == nil {
		t.Fatal("updating the rate removed the schedule")
	}

	if got = setSchedule(t, org, target.ID, TargetSettings{ClearSchedule: true}); got.Schedule != nil {
		t.Fatalf("after ClearSchedule: %+v", got.Schedule)
	}

	bad := weeklySchedule(next)
	bad.TimeZone = "Mars/Olympus"
	if _, err := org.UpdateTargetSettings(context.Background(), target.ID, TargetSettings{Schedule: bad}); !errors.Is(err, schedule.ErrInvalid) {
		t.Errorf("invalid time zone: err = %v, want schedule.ErrInvalid", err)
	}
}

func TestEnqueueDueScans(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	org := defaultOrg(t, s)
	due := newTarget(t, s, "due.example")
	later := newTarget(t, s, "later.example")
	newTarget(t, s, "manual.example") // no schedule: never queued

	now := time.Date(2026, 11, 15, 1, 30, 0, 0, time.UTC) // Sunday 02:30 in Paris
	setSchedule(t, org, due.ID, TargetSettings{Schedule: weeklySchedule(now.Add(-30 * time.Minute))})
	setSchedule(t, org, later.ID, TargetSettings{Schedule: weeklySchedule(now.Add(time.Hour))})

	n, err := s.EnqueueDueScans(ctx, now, 100)
	if err != nil || n != 1 {
		t.Fatalf("EnqueueDueScans = %d, %v; want 1 scan", n, err)
	}
	scans := scansOf(t, org, due.ID)
	if len(scans) != 1 || scans[0].RequestedBy != ActorScheduler || !slices.Equal(scans[0].Modules, []string{"email", "tls"}) {
		t.Fatalf("scans of the due target = %+v", scans)
	}
	if len(scansOf(t, org, later.ID)) != 0 {
		t.Error("a target not yet due was queued")
	}
	if got := actions(t, s, "due.example"); !slices.Contains(got, ActorScheduler+" "+ActionScanRequested) {
		t.Errorf("audit = %v, want a scan.requested entry by the scheduler", got)
	}

	// next_scan_at moved to the following Sunday 02:00 in Paris.
	reloaded, err := org.GetTarget(ctx, due.ID)
	if err != nil {
		t.Fatal(err)
	}
	wantNext := time.Date(2026, 11, 22, 1, 0, 0, 0, time.UTC)
	if !reloaded.Schedule.NextScanAt.Equal(wantNext) {
		t.Errorf("next scan at %v, want %v", reloaded.Schedule.NextScanAt, wantNext)
	}

	// Called again at once: nothing more is due.
	if n, err := s.EnqueueDueScans(ctx, now, 100); err != nil || n != 0 {
		t.Errorf("second call = %d, %v; want 0", n, err)
	}

	// A week later the first scan is still queued (no worker ran): no
	// second scan piles up, but the schedule moves on.
	weekLater := wantNext.Add(time.Minute)
	// Only later.example (due an hour after the first call) gets a scan.
	if n, err := s.EnqueueDueScans(ctx, weekLater, 100); err != nil || n != 1 {
		t.Errorf("with a scan still queued = %d, %v; want 1 (later.example only)", n, err)
	}
	if got := len(scansOf(t, org, due.ID)); got != 1 {
		t.Errorf("scans = %d, want still 1", got)
	}
	reloaded, _ = org.GetTarget(ctx, due.ID)
	if !reloaded.Schedule.NextScanAt.After(weekLater) {
		t.Errorf("next scan at %v, want after %v", reloaded.Schedule.NextScanAt, weekLater)
	}
}

func TestEnqueueDueScansLimit(t *testing.T) {
	s := newTestStore(t)
	org := defaultOrg(t, s)
	now := time.Date(2026, 11, 15, 1, 30, 0, 0, time.UTC)
	for _, d := range []string{"a.example", "b.example", "c.example"} {
		setSchedule(t, org, newTarget(t, s, d).ID, TargetSettings{Schedule: weeklySchedule(now.Add(-time.Minute))})
	}
	if n, err := s.EnqueueDueScans(context.Background(), now, 2); err != nil || n != 2 {
		t.Fatalf("first batch = %d, %v; want 2", n, err)
	}
	if n, err := s.EnqueueDueScans(context.Background(), now, 2); err != nil || n != 1 {
		t.Fatalf("second batch = %d, %v; want the last 1", n, err)
	}
}
