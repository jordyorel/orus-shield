package store

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"
)

// newTestStore returns a Store working in a fresh, private PostgreSQL schema,
// dropped when the test ends. Tests are skipped when ORUS_TEST_DATABASE_URL
// is not set, so "go test ./..." works without a database.
func newTestStore(t *testing.T) *Store {
	t.Helper()
	base := os.Getenv("ORUS_TEST_DATABASE_URL")
	if base == "" {
		t.Skip("ORUS_TEST_DATABASE_URL not set; skipping PostgreSQL integration test")
	}
	ctx := context.Background()

	suffix := make([]byte, 6)
	if _, err := rand.Read(suffix); err != nil {
		t.Fatal(err)
	}
	// Only hex characters: safe to put in SQL as an identifier.
	schema := "test_" + hex.EncodeToString(suffix)

	admin, err := pgx.Connect(ctx, base)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatalf("create schema: %v", err)
	}

	u, err := url.Parse(base)
	if err != nil {
		t.Fatalf("parse ORUS_TEST_DATABASE_URL: %v", err)
	}
	q := u.Query()
	q.Set("search_path", schema) // pgx sends unknown parameters as session settings
	u.RawQuery = q.Encode()

	s, err := Open(ctx, u.String())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() {
		s.Close()
		if _, err := admin.Exec(ctx, "DROP SCHEMA "+schema+" CASCADE"); err != nil {
			t.Errorf("drop schema: %v", err)
		}
		admin.Close(ctx)
	})
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	return s
}

func TestOpenHidesPassword(t *testing.T) {
	_, err := Open(context.Background(), "postgres://orus:s3cret-pass@127.0.0.1:1/x?connect_timeout=1&bogus_%%")
	if err == nil {
		t.Fatal("Open() = nil, want error")
	}
	if strings.Contains(err.Error(), "s3cret-pass") {
		t.Errorf("error leaks the password: %v", err)
	}
}

func TestMigrateIsIdempotent(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("second Migrate: %v", err)
	}
	var n int
	if err := s.pool.QueryRow(ctx, "SELECT count(*) FROM schema_migrations").Scan(&n); err != nil {
		t.Fatal(err)
	}
	files, err := fs.Glob(migrationFS, "migrations/*.sql")
	if err != nil {
		t.Fatal(err)
	}
	if n != len(files) {
		t.Errorf("schema_migrations has %d rows, want %d (one per migration file)", n, len(files))
	}
}

func TestConcurrentMigrate(t *testing.T) {
	s := newTestStore(t)
	var wg sync.WaitGroup
	errs := make(chan error, 4)
	for range 4 {
		wg.Go(func() { errs <- s.Migrate(context.Background()) })
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Errorf("concurrent Migrate: %v", err)
		}
	}
}

func TestCreateAndGetTarget(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	created, err := s.CreateTarget(ctx, NewTarget{Domain: " Example.COM. "})
	if err != nil {
		t.Fatalf("CreateTarget: %v", err)
	}
	if created.Domain != "example.com" {
		t.Errorf("domain = %q, want normalized example.com", created.Domain)
	}
	if created.Verified() {
		t.Error("a new target must not be verified")
	}
	if created.RatePerSec != DefaultRatePerSec || string(created.Exclusions) != "{}" {
		t.Errorf("defaults: rate %v, exclusions %s", created.RatePerSec, created.Exclusions)
	}

	got, err := s.GetTarget(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	if got.ID != created.ID || got.Domain != created.Domain {
		t.Errorf("GetTarget = %+v, want %+v", got, created)
	}
	byDomain, err := s.TargetByDomain(ctx, "EXAMPLE.com")
	if err != nil || byDomain.ID != created.ID {
		t.Errorf("TargetByDomain = %+v, %v", byDomain, err)
	}
}

func TestCreateTargetRejects(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	if _, err := s.CreateTarget(ctx, NewTarget{Domain: "example.com"}); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		nt   NewTarget
	}{
		{"duplicate domain", NewTarget{Domain: "EXAMPLE.COM"}},
		{"invalid domain", NewTarget{Domain: "not a domain"}},
		{"rate too high", NewTarget{Domain: "fast.example", RatePerSec: 1000}},
		{"negative rate", NewTarget{Domain: "neg.example", RatePerSec: -1}},
		{"exclusions not JSON", NewTarget{Domain: "bad.example", Exclusions: json.RawMessage("{")}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := s.CreateTarget(ctx, tt.nt); err == nil {
				t.Error("CreateTarget() = nil, want error")
			}
		})
	}
}

func TestGetTargetNotFound(t *testing.T) {
	s := newTestStore(t)
	_, err := s.GetTarget(context.Background(), "0190a000-0000-7000-8000-000000000000")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("GetTarget error = %v, want ErrNotFound", err)
	}
}

func TestAuditLogIsAppendOnly(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	entry := AuditEntry{Actor: "jordy", Action: ActionScanRequested, Target: "example.com",
		Details: map[string]any{"modules": []string{"email"}}}
	if err := s.AppendAudit(ctx, entry); err != nil {
		t.Fatalf("AppendAudit: %v", err)
	}

	entries, err := s.AuditLog(ctx, "example.com")
	if err != nil {
		t.Fatalf("AuditLog: %v", err)
	}
	if len(entries) != 1 || entries[0].Actor != "jordy" || entries[0].At.IsZero() {
		t.Fatalf("AuditLog = %+v", entries)
	}
	if details := string(entries[0].Details.(json.RawMessage)); !strings.Contains(details, `"email"`) {
		t.Errorf("details = %s, want the modules", details)
	}

	for _, stmt := range []string{
		"UPDATE audit_log SET actor = 'someone else'",
		"DELETE FROM audit_log",
		"TRUNCATE audit_log",
	} {
		if _, err := s.pool.Exec(ctx, stmt); err == nil || !strings.Contains(err.Error(), "append-only") {
			t.Errorf("%s: error = %v, want append-only refusal", stmt, err)
		}
	}
}
