// Package storetest gives tests of other packages a migrated store in a
// private PostgreSQL schema, dropped when the test ends. Tests are skipped
// when ORUS_TEST_DATABASE_URL is not set (and fail in CI, where a missing
// database is a configuration error).
package storetest

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/url"
	"os"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/jordyorel/orus-shield/engine/internal/store"
)

// New returns a migrated store for t.
func New(t *testing.T) *store.Store {
	t.Helper()
	base := os.Getenv("ORUS_TEST_DATABASE_URL")
	if base == "" {
		if os.Getenv("CI") == "true" {
			t.Fatal("ORUS_TEST_DATABASE_URL must be set in CI")
		}
		t.Skip("ORUS_TEST_DATABASE_URL not set; skipping PostgreSQL integration test")
	}
	ctx := context.Background()
	suffix := make([]byte, 6)
	if _, err := rand.Read(suffix); err != nil {
		t.Fatal(err)
	}
	schema := "test_" + hex.EncodeToString(suffix) // hex only: safe as an identifier

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
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()

	s, err := store.Open(ctx, u.String())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() {
		s.Close()
		if _, err := admin.Exec(ctx, "DROP SCHEMA "+schema+" CASCADE"); err != nil {
			t.Errorf("drop schema: %v", err)
		}
		_ = admin.Close(ctx)
	})
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	return s
}
