package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const publicRole = "orus_public"

// QuickTestRetention is how long a public test's result is kept.
const QuickTestRetention = 30 * 24 * time.Hour

// Public is the store handle of the public domain test (package
// quicktest): it reads and writes quick_tests and quick_test_leads,
// nothing else. No organization, user or finding is reachable from it.
type Public struct{ pool *pgxpool.Pool }

// Public returns the public test's handle.
func (s *Store) Public() *Public { return &Public{pool: s.pool} }

func (p *Public) inTx(ctx context.Context, f func(pgx.Tx) error) error {
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	// publicRole is a constant: no injection possible.
	if _, err := tx.Exec(ctx, "SET LOCAL ROLE "+publicRole); err != nil {
		return err
	}
	if err := f(tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// QuickTestCounts are the inputs of the public test's rate limits since a
// moment: the tests one address asked, and the tests actually run (not
// served from the cache) by everyone.
type QuickTestCounts struct{ ByIP, Run int }

// QuickTestCounts counts the tests since since.
func (p *Public) QuickTestCounts(ctx context.Context, ip string, since time.Time) (c QuickTestCounts, err error) {
	err = p.inTx(ctx, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT
			(SELECT count(*) FROM quick_tests WHERE ip = $1 AND created_at > $2),
			(SELECT count(*) FROM quick_tests WHERE NOT cached AND created_at > $2)`, ip, since).Scan(&c.ByIP, &c.Run)
	})
	if err != nil {
		return QuickTestCounts{}, fmt.Errorf("quick test counts: %w", err)
	}
	return c, nil
}

// CachedQuickTest is the latest result for domain since since, if any.
func (p *Public) CachedQuickTest(ctx context.Context, domain string, since time.Time) (result []byte, ok bool, err error) {
	err = p.inTx(ctx, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT result FROM quick_tests WHERE domain = $1 AND created_at > $2
			ORDER BY created_at DESC LIMIT 1`, domain, since).Scan(&result)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("cached quick test: %w", err)
	}
	return result, true, nil
}

// RecordQuickTest stores one test asked by ip and returns its ID. It also
// deletes the results older than QuickTestRetention.
func (p *Public) RecordQuickTest(ctx context.Context, domain, ip string, result []byte, cached bool, now time.Time) (id string, err error) {
	err = p.inTx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "DELETE FROM quick_tests WHERE created_at < $1", now.Add(-QuickTestRetention)); err != nil {
			return err
		}
		return tx.QueryRow(ctx, `INSERT INTO quick_tests (domain, ip, result, cached, created_at)
			VALUES ($1, $2, $3, $4, $5) RETURNING id::text`, domain, ip, result, cached, now).Scan(&id)
	})
	if err != nil {
		return "", fmt.Errorf("record quick test: %w", err)
	}
	return id, nil
}

// QuickTest returns a test's domain and result, if it was made since
// since. An unknown or older test is ErrNotFound.
func (p *Public) QuickTest(ctx context.Context, id string, since time.Time) (domain string, result []byte, err error) {
	if !isUUID(id) {
		return "", nil, ErrNotFound
	}
	err = p.inTx(ctx, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, "SELECT domain, result FROM quick_tests WHERE id = $1 AND created_at > $2", id, since).Scan(&domain, &result)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil, ErrNotFound
	}
	if err != nil {
		return "", nil, fmt.Errorf("quick test: %w", err)
	}
	return domain, result, nil
}

// Lead is a visitor who left an email for a test's full report.
type Lead struct {
	TestID    string
	Email     string
	Domain    string
	Lang      string // "fr", "en" or ""
	Marketing bool   // consents to receive our messages
	IP        string
}

// LeadCounts counts the leads left since since by one address and for one
// email: the inputs of their rate limits.
func (p *Public) LeadCounts(ctx context.Context, ip, email string, since time.Time) (byIP, byEmail int, err error) {
	e, _ := NormalizeEmail(email)
	err = p.inTx(ctx, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT
			(SELECT count(*) FROM quick_test_leads WHERE ip = $1 AND created_at > $3),
			(SELECT count(*) FROM quick_test_leads WHERE email = $2 AND created_at > $3)`, ip, e, since).Scan(&byIP, &byEmail)
	})
	if err != nil {
		return 0, 0, fmt.Errorf("lead counts: %w", err)
	}
	return byIP, byEmail, nil
}

// AddLead records a lead; an invalid email is refused (NormalizeEmail).
func (p *Public) AddLead(ctx context.Context, l Lead) error {
	e, err := NormalizeEmail(l.Email)
	if err != nil {
		return err
	}
	lang := l.Lang
	if lang != "fr" && lang != "en" {
		lang = ""
	}
	err = p.inTx(ctx, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO quick_test_leads (test_id, email, domain, lang, marketing, ip)
			VALUES ($1, $2, $3, NULLIF($4, ''), $5, $6)`, l.TestID, e, l.Domain, lang, l.Marketing, l.IP)
		return err
	})
	if err != nil {
		return fmt.Errorf("add lead: %w", err)
	}
	return nil
}
