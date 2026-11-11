// Package schedule computes when a target's next scheduled scan is due.
//
// It is pure: no clock, no database. The API computes the first run when a
// customer saves a schedule, and the worker's scheduler the following runs.
//
// Times are wall-clock times in the customer's time zone ("every Sunday at
// 02:00, Africa/Douala"), not fixed offsets: a schedule keeps its local hour
// across daylight saving changes.
package schedule

import (
	"errors"
	"fmt"
	"time"
	// Embeds the time zone database (about 450 KB) so time zones resolve
	// the same way on every server, even a minimal container without
	// /usr/share/zoneinfo.
	_ "time/tzdata"
)

// Frequency is how often a target is scanned.
type Frequency string

const (
	Daily  Frequency = "daily"
	Weekly Frequency = "weekly"
	// Monthly runs on the first given weekday of each month (the first
	// Sunday, for example), so it never falls on a missing 31st.
	Monthly Frequency = "monthly"
)

// Schedule is when a target is scanned.
type Schedule struct {
	Frequency Frequency
	// Weekday is the day of weekly and monthly runs; ignored for daily.
	Weekday time.Weekday
	Hour    int // 0-23, local time in TimeZone
	// TimeZone is an IANA name such as "Europe/Paris" or "Africa/Douala".
	TimeZone string
}

// ErrInvalid wraps every validation error.
var ErrInvalid = errors.New("invalid schedule")

// Validate checks every field, including that the time zone exists.
func (s Schedule) Validate() error {
	_, err := s.location()
	return err
}

func (s Schedule) location() (*time.Location, error) {
	switch s.Frequency {
	case Daily, Weekly, Monthly:
	default:
		return nil, fmt.Errorf("%w: frequency %q", ErrInvalid, s.Frequency)
	}
	if s.Weekday < time.Sunday || s.Weekday > time.Saturday {
		return nil, fmt.Errorf("%w: weekday %d", ErrInvalid, s.Weekday)
	}
	if s.Hour < 0 || s.Hour > 23 {
		return nil, fmt.Errorf("%w: hour %d", ErrInvalid, s.Hour)
	}
	// "" and "Local" would depend on the server's settings: refused.
	if s.TimeZone == "" || s.TimeZone == "Local" {
		return nil, fmt.Errorf("%w: time zone required", ErrInvalid)
	}
	loc, err := time.LoadLocation(s.TimeZone)
	if err != nil {
		return nil, fmt.Errorf("%w: time zone %q", ErrInvalid, s.TimeZone)
	}
	return loc, nil
}

// Next returns the first run strictly after after.
//
// A run that was missed (the workers were stopped) is not caught up: the
// scheduler starts one scan when it notices, then asks Next from that
// moment, so a long outage never produces a burst of scans.
func (s Schedule) Next(after time.Time) (time.Time, error) {
	loc, err := s.location()
	if err != nil {
		return time.Time{}, err
	}
	local := after.In(loc)
	y, m, d := local.Date()

	switch s.Frequency {
	case Daily:
		for i := 0; ; i++ {
			if t := at(y, m, d+i, s.Hour, loc); t.After(after) {
				return t, nil
			}
		}
	case Weekly:
		for i := 0; ; i++ {
			day := at(y, m, d+i, 0, loc)
			if day.Weekday() != s.Weekday {
				continue
			}
			if t := at(y, m, d+i, s.Hour, loc); t.After(after) {
				return t, nil
			}
		}
	default: // Monthly
		for i := 0; ; i++ {
			if t := firstWeekday(y, m+time.Month(i), s.Weekday, s.Hour, loc); t.After(after) {
				return t, nil
			}
		}
	}
}

// at builds a local time; time.Date normalizes day and month overflow.
// An hour that does not exist (skipped by a daylight saving change) is
// moved forward by time.Date, which is what a customer expects.
func at(y int, m time.Month, d, hour int, loc *time.Location) time.Time {
	return time.Date(y, m, d, hour, 0, 0, 0, loc)
}

// firstWeekday returns the first wd of month m at hour.
func firstWeekday(y int, m time.Month, wd time.Weekday, hour int, loc *time.Location) time.Time {
	first := at(y, m, 1, 0, loc)
	offset := (int(wd) - int(first.Weekday()) + 7) % 7
	return at(y, m, 1+offset, hour, loc)
}
