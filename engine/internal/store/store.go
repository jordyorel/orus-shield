// Package store persists targets, the scan queue, findings and the audit log
// in PostgreSQL.
//
// It uses pgx directly rather than database/sql: the standard library ships
// no PostgreSQL driver, and pgx handles JSONB, arrays and connection pooling
// natively.
package store

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrNotFound is returned when a requested row does not exist.
var ErrNotFound = errors.New("not found")

// Store is the PostgreSQL storage across every organization. Only the
// worker (and administration commands) should hold one: API code works with
// an *Org from Store.Org instead (see "Tenant isolation" in org.go). It is
// safe for concurrent use.
type Store struct {
	scope // orgID empty: every organization
}

// querier is what pgxpool.Pool and pgx.Tx have in common, so helpers can run
// either alone or inside a transaction.
type querier interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// Open connects to the database at url and checks the connection.
//
// Errors never include url: it contains the database password.
func Open(ctx context.Context, url string) (*Store, error) {
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		return nil, errors.New("parse database url: invalid format")
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("open database pool: %w", err)
	}
	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := pool.Ping(pingCtx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("connect to database: %w", err)
	}
	return &Store{scope{pool: pool}}, nil
}

// Close releases all connections.
func (s *Store) Close() {
	s.pool.Close()
}

//go:embed migrations/*.sql
var migrationFS embed.FS

// migrationLockID is an arbitrary constant ("orus" in ASCII) identifying
// our advisory lock, so that concurrent workers starting together do not
// apply the same migration twice.
const migrationLockID = 0x6f727573

// Migrate applies the embedded migrations that have not been applied yet, in
// file name order, in a single transaction. PostgreSQL DDL is transactional:
// if one migration fails, none is applied.
func (s *Store) Migrate(ctx context.Context) error {
	return s.migrate(ctx, "")
}

// migrate applies migrations up to and including version last ("": all).
// Tests use last to build a database as it was before a migration.
func (s *Store) migrate(ctx context.Context, last string) error {
	files, err := fs.Glob(migrationFS, "migrations/*.sql")
	if err != nil {
		return fmt.Errorf("list migrations: %w", err)
	}
	sort.Strings(files)

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin migration: %w", err)
	}
	defer tx.Rollback(ctx) // no-op after Commit

	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", migrationLockID); err != nil {
		return fmt.Errorf("lock migrations: %w", err)
	}
	if _, err := tx.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version    text PRIMARY KEY,
		applied_at timestamptz NOT NULL DEFAULT now()
	)`); err != nil {
		return fmt.Errorf("create schema_migrations: %w", err)
	}

	applied := make(map[string]bool)
	rows, err := tx.Query(ctx, "SELECT version FROM schema_migrations")
	if err != nil {
		return fmt.Errorf("read applied migrations: %w", err)
	}
	versions, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return fmt.Errorf("read applied migrations: %w", err)
	}
	for _, v := range versions {
		applied[v] = true
	}

	for _, file := range files {
		version := strings.TrimSuffix(path.Base(file), ".sql")
		if last != "" && version > last {
			break
		}
		if applied[version] {
			continue
		}
		sql, err := migrationFS.ReadFile(file)
		if err != nil {
			return fmt.Errorf("read migration %s: %w", version, err)
		}
		// No arguments: pgx uses the simple protocol, which accepts several
		// statements in one call.
		if _, err := tx.Exec(ctx, string(sql)); err != nil {
			return fmt.Errorf("apply migration %s: %w", version, err)
		}
		if _, err := tx.Exec(ctx, "INSERT INTO schema_migrations (version) VALUES ($1)", version); err != nil {
			return fmt.Errorf("record migration %s: %w", version, err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit migrations: %w", err)
	}
	return nil
}
