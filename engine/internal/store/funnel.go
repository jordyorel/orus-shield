package store

import (
	"context"
	"fmt"
	"time"
)

// Funnel counts the steps from the home page's public test to a paying
// customer, measured on our own data: no tracker, no cookie, no third
// party (the privacy policy promises no audience measurement).
type Funnel struct {
	Tests     int // public tests asked since the start (cached ones included)
	Domains   int // distinct domains among them
	Leads     int // emails left for the full report
	Marketing int // of which agreed to receive our messages
	Signups   int // signups completed (account and organization created)
	// Trialing and Paying: organizations whose Paddle subscription is in
	// its trial, or paid, now (not limited to the period).
	Trialing, Paying int
}

// Funnel returns the funnel since since. Tests older than
// QuickTestRetention are deleted, so a longer period undercounts them.
func (s *Store) Funnel(ctx context.Context, since time.Time) (f Funnel, err error) {
	err = s.pool.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM quick_tests WHERE created_at >= $1),
		(SELECT count(DISTINCT domain) FROM quick_tests WHERE created_at >= $1),
		(SELECT count(*) FROM quick_test_leads WHERE created_at >= $1),
		(SELECT count(*) FROM quick_test_leads WHERE created_at >= $1 AND marketing),
		(SELECT count(*) FROM signup_requests WHERE used_at >= $1),
		(SELECT count(*) FROM subscriptions WHERE provider = 'paddle' AND status = 'trialing'),
		(SELECT count(*) FROM subscriptions WHERE provider = 'paddle' AND status = 'active')`, since).
		Scan(&f.Tests, &f.Domains, &f.Leads, &f.Marketing, &f.Signups, &f.Trialing, &f.Paying)
	if err != nil {
		return Funnel{}, fmt.Errorf("funnel: %w", err)
	}
	return f, nil
}
