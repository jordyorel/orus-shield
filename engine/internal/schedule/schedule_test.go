package schedule

import (
	"errors"
	"testing"
	"time"
)

func mustLoc(t *testing.T, name string) *time.Location {
	t.Helper()
	loc, err := time.LoadLocation(name)
	if err != nil {
		t.Fatal(err)
	}
	return loc
}

func TestNext(t *testing.T) {
	paris := mustLoc(t, "Europe/Paris")
	douala := mustLoc(t, "Africa/Douala")
	// Wednesday 11 November 2026, 20:30 in Paris.
	wed := time.Date(2026, 11, 11, 20, 30, 0, 0, paris)

	tests := []struct {
		name  string
		s     Schedule
		after time.Time
		want  time.Time
	}{
		{"daily, later today", Schedule{Daily, 0, 22, "Europe/Paris"}, wed, time.Date(2026, 11, 11, 22, 0, 0, 0, paris)},
		{"daily, hour passed: tomorrow", Schedule{Daily, 0, 2, "Europe/Paris"}, wed, time.Date(2026, 11, 12, 2, 0, 0, 0, paris)},
		{"daily, exactly now: next day", Schedule{Daily, 0, 20, "Europe/Paris"}, time.Date(2026, 11, 11, 20, 0, 0, 0, paris), time.Date(2026, 11, 12, 20, 0, 0, 0, paris)},
		{"weekly, Sunday 02:00", Schedule{Weekly, time.Sunday, 2, "Europe/Paris"}, wed, time.Date(2026, 11, 15, 2, 0, 0, 0, paris)},
		{"weekly, same day later", Schedule{Weekly, time.Wednesday, 23, "Europe/Paris"}, wed, time.Date(2026, 11, 11, 23, 0, 0, 0, paris)},
		{"weekly, same day passed: next week", Schedule{Weekly, time.Wednesday, 6, "Europe/Paris"}, wed, time.Date(2026, 11, 18, 6, 0, 0, 0, paris)},
		{"monthly, first Sunday of next month", Schedule{Monthly, time.Sunday, 2, "Europe/Paris"}, wed, time.Date(2026, 12, 6, 2, 0, 0, 0, paris)},
		{"monthly, across the year", Schedule{Monthly, time.Monday, 2, "Europe/Paris"}, time.Date(2026, 12, 8, 0, 0, 0, 0, paris), time.Date(2027, 1, 4, 2, 0, 0, 0, paris)},
		{"monthly, first weekday still ahead this month", Schedule{Monthly, time.Friday, 9, "Europe/Paris"}, time.Date(2026, 11, 1, 0, 0, 0, 0, paris), time.Date(2026, 11, 6, 9, 0, 0, 0, paris)},
		{"other time zone", Schedule{Daily, 0, 2, "Africa/Douala"}, wed, time.Date(2026, 11, 12, 2, 0, 0, 0, douala)},
		// 29 March 2026: Paris skips from 02:00 to 03:00. The run moves to
		// 03:00 that day, and stays at 02:00 local afterwards.
		{"daylight saving: missing hour", Schedule{Daily, 0, 2, "Europe/Paris"}, time.Date(2026, 3, 28, 12, 0, 0, 0, paris), time.Date(2026, 3, 29, 3, 0, 0, 0, paris)},
		{"daylight saving: local hour kept", Schedule{Daily, 0, 2, "Europe/Paris"}, time.Date(2026, 3, 29, 12, 0, 0, 0, paris), time.Date(2026, 3, 30, 2, 0, 0, 0, paris)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.s.Next(tt.after)
			if err != nil {
				t.Fatal(err)
			}
			if !got.Equal(tt.want) {
				t.Errorf("Next(%v) = %v, want %v", tt.after, got.In(tt.want.Location()), tt.want)
			}
			if !got.After(tt.after) {
				t.Errorf("Next(%v) = %v, not after", tt.after, got)
			}
		})
	}
}

// A schedule asked again from its own run time advances: the scheduler
// never fires twice for the same slot.
func TestNextAdvances(t *testing.T) {
	for _, s := range []Schedule{
		{Daily, 0, 2, "UTC"}, {Weekly, time.Sunday, 2, "Europe/Paris"}, {Monthly, time.Monday, 23, "America/New_York"},
	} {
		at := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
		for range 30 {
			next, err := s.Next(at)
			if err != nil {
				t.Fatal(err)
			}
			if !next.After(at) {
				t.Fatalf("%+v: Next(%v) = %v", s, at, next)
			}
			at = next
		}
	}
}

func TestValidate(t *testing.T) {
	ok := Schedule{Weekly, time.Sunday, 2, "Europe/Paris"}
	if err := ok.Validate(); err != nil {
		t.Fatalf("valid schedule: %v", err)
	}
	tests := []struct {
		name string
		mod  func(*Schedule)
	}{
		{"unknown frequency", func(s *Schedule) { s.Frequency = "hourly" }},
		{"empty frequency", func(s *Schedule) { s.Frequency = "" }},
		{"weekday too big", func(s *Schedule) { s.Weekday = 7 }},
		{"negative weekday", func(s *Schedule) { s.Weekday = -1 }},
		{"hour 24", func(s *Schedule) { s.Hour = 24 }},
		{"negative hour", func(s *Schedule) { s.Hour = -1 }},
		{"no time zone", func(s *Schedule) { s.TimeZone = "" }},
		{"server-dependent zone", func(s *Schedule) { s.TimeZone = "Local" }},
		{"unknown zone", func(s *Schedule) { s.TimeZone = "Mars/Olympus" }},
		{"path in zone", func(s *Schedule) { s.TimeZone = "../../etc/passwd" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := ok
			tt.mod(&s)
			if err := s.Validate(); !errors.Is(err, ErrInvalid) {
				t.Errorf("Validate() = %v, want ErrInvalid", err)
			}
			if _, err := s.Next(time.Now()); err == nil {
				t.Error("Next on an invalid schedule: nil error")
			}
		})
	}
}
