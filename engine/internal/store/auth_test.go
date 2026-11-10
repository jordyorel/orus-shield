package store

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func newUser(t *testing.T, s *Store, email string) User {
	t.Helper()
	u, err := s.CreateUser(context.Background(), email)
	if err != nil {
		t.Fatalf("CreateUser(%s): %v", email, err)
	}
	return u
}

func TestCreateUserAndMembership(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	org := defaultOrg(t, s)

	u := newUser(t, s, " Alice@Example.COM ")
	if u.Email != "alice@example.com" {
		t.Errorf("email = %q, want lowercased", u.Email)
	}
	if _, err := s.CreateUser(ctx, "alice@example.com"); !errors.Is(err, ErrExists) {
		t.Errorf("duplicate user = %v, want ErrExists", err)
	}
	for _, bad := range []string{"", "alice", "@example.com", "alice@", "a b@example.com"} {
		if _, err := s.CreateUser(ctx, bad); err == nil {
			t.Errorf("CreateUser(%q) = nil, want error", bad)
		}
	}

	if err := s.SetMembership(ctx, u.ID, org.ID(), RoleViewer, "cli:jordy"); err != nil {
		t.Fatal(err)
	}
	if err := s.SetMembership(ctx, u.ID, org.ID(), RoleAdmin, "cli:jordy"); err != nil {
		t.Fatalf("changing the role: %v", err)
	}
	if err := s.SetMembership(ctx, u.ID, org.ID(), "owner", "cli:jordy"); err == nil {
		t.Error("unknown role accepted")
	}
	if err := s.SetMembership(ctx, u.ID, "0190a000-0000-7000-8000-000000000000", RoleAdmin, "cli:jordy"); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown organization = %v, want ErrNotFound", err)
	}

	auth := s.Auth()
	if role, err := auth.Role(ctx, u.ID, org.ID()); err != nil || role != RoleAdmin {
		t.Errorf("Role = %q, %v; want admin", role, err)
	}
	ms, err := auth.Memberships(ctx, u.ID)
	if err != nil || len(ms) != 1 || ms[0].OrgName != "Default" || ms[0].Role != RoleAdmin {
		t.Errorf("Memberships = %+v, %v", ms, err)
	}
	other := newOrg(t, s, "Other")
	if _, err := auth.Role(ctx, u.ID, other.ID()); !errors.Is(err, ErrNotFound) {
		t.Errorf("Role in a foreign organization = %v, want ErrNotFound", err)
	}
	entries, _ := org.AuditLog(ctx, "")
	if len(entries) == 0 || entries[len(entries)-1].Action != ActionMemberAdded {
		t.Errorf("membership not audited: %+v", entries)
	}
}

func TestSetupTokenFlow(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	u := newUser(t, s, "alice@example.com")
	auth := s.Auth()

	old, err := s.IssueSetupToken(ctx, u.ID, time.Hour, "cli:jordy")
	if err != nil {
		t.Fatal(err)
	}
	token, err := s.IssueSetupToken(ctx, u.ID, time.Hour, "cli:jordy")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := auth.SetPasswordWithToken(ctx, old, "$argon2id$x", "192.0.2.1"); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("superseded token = %v, want ErrInvalidToken", err)
	}

	session, err := auth.CreateSession(ctx, u.ID, "192.0.2.1", "test", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	got, err := auth.SetPasswordWithToken(ctx, token, "$argon2id$x", "192.0.2.1")
	if err != nil || got.Email != "alice@example.com" {
		t.Fatalf("SetPasswordWithToken = %+v, %v", got, err)
	}
	if u2, _ := auth.UserByEmail(ctx, "ALICE@example.com"); u2.PasswordHash != "$argon2id$x" {
		t.Errorf("password hash = %q", u2.PasswordHash)
	}
	if _, err := auth.SessionUser(ctx, session, time.Hour); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("session after a password change = %v, want closed", err)
	}
	if _, err := auth.SetPasswordWithToken(ctx, token, "$argon2id$y", "192.0.2.1"); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("reused token = %v, want ErrInvalidToken", err)
	}
	expired, _ := s.IssueSetupToken(ctx, u.ID, -time.Minute, "cli:jordy")
	if _, err := auth.SetPasswordWithToken(ctx, expired, "$argon2id$y", "192.0.2.1"); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("expired token = %v, want ErrInvalidToken", err)
	}
}

func TestSessions(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	u := newUser(t, s, "alice@example.com")
	auth := s.Auth()

	token, err := auth.CreateSession(ctx, u.ID, "192.0.2.1", strings.Repeat("u", 2000), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	sess, err := auth.SessionUser(ctx, token, time.Hour)
	if err != nil || sess.UserID != u.ID || sess.Email != u.Email {
		t.Fatalf("SessionUser = %+v, %v", sess, err)
	}
	// The database keeps only the hash of the token.
	var stored int
	if err := s.pool.QueryRow(ctx, "SELECT count(*) FROM sessions WHERE token_hash = $1", []byte(token)).Scan(&stored); err != nil || stored != 0 {
		t.Errorf("token stored in clear: %d, %v", stored, err)
	}

	for name, tok := range map[string]string{"unknown": "nope", "empty": ""} {
		if _, err := auth.SessionUser(ctx, tok, time.Hour); !errors.Is(err, ErrInvalidToken) {
			t.Errorf("%s token = %v, want ErrInvalidToken", name, err)
		}
	}
	// Idle limit: last use older than idle.
	if _, err := s.pool.Exec(ctx, "UPDATE sessions SET last_seen_at = now() - interval '2 hours'"); err != nil {
		t.Fatal(err)
	}
	if _, err := auth.SessionUser(ctx, token, time.Hour); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("idle session = %v, want ErrInvalidToken", err)
	}
	// Absolute limit.
	expired, _ := auth.CreateSession(ctx, u.ID, "192.0.2.1", "t", time.Now().Add(-time.Second))
	if _, err := auth.SessionUser(ctx, expired, time.Hour); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("expired session = %v, want ErrInvalidToken", err)
	}
	// Disabled user.
	live, _ := auth.CreateSession(ctx, u.ID, "192.0.2.1", "t", time.Now().Add(time.Hour))
	if _, err := s.pool.Exec(ctx, "UPDATE users SET disabled_at = now()"); err != nil {
		t.Fatal(err)
	}
	if _, err := auth.SessionUser(ctx, live, time.Hour); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("session of a disabled user = %v, want ErrInvalidToken", err)
	}
	if _, err := s.pool.Exec(ctx, "UPDATE users SET disabled_at = NULL"); err != nil {
		t.Fatal(err)
	}
	if err := auth.DeleteSession(ctx, live); err != nil {
		t.Fatal(err)
	}
	if _, err := auth.SessionUser(ctx, live, time.Hour); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("deleted session = %v, want ErrInvalidToken", err)
	}
}

func TestRecentFailures(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	auth := s.Auth()
	for _, e := range []AuthEvent{
		{Email: "a@example.com", Action: AuthLoginFailed, IP: "192.0.2.1"},
		{Email: "a@example.com", Action: AuthLoginFailed, IP: "192.0.2.2"},
		{Email: "b@example.com", Action: AuthLoginFailed, IP: "192.0.2.1"},
		{Email: "a@example.com", Action: AuthLoginOK, IP: "192.0.2.1"},
	} {
		if err := auth.Log(ctx, e); err != nil {
			t.Fatal(err)
		}
	}
	byEmail, byIP, err := auth.RecentFailures(ctx, "a@example.com", "192.0.2.1", time.Now().Add(-time.Minute))
	if err != nil || byEmail != 2 || byIP != 2 {
		t.Errorf("RecentFailures = %d, %d, %v; want 2, 2", byEmail, byIP, err)
	}
	if _, err := s.pool.Exec(ctx, "DELETE FROM auth_log"); err == nil || !strings.Contains(err.Error(), "append-only") {
		t.Errorf("DELETE auth_log = %v, want append-only refusal", err)
	}
}

// The auth role sees accounts, never customer data.
func TestAuthRoleCannotReadCustomerData(t *testing.T) {
	c := newCrossTenant(t)
	ctx := context.Background()
	tx, err := c.s.Auth().begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	for _, table := range []string{"targets", "findings", "assets", "audit_log", "scans"} {
		if _, err := tx.Exec(ctx, "SAVEPOINT s"); err != nil {
			t.Fatal(err)
		}
		_, err := tx.Exec(ctx, "SELECT 1 FROM "+table+" LIMIT 1")
		if err == nil || !strings.Contains(err.Error(), "permission denied") {
			t.Errorf("auth role reading %s = %v, want permission denied", table, err)
		}
		if _, err := tx.Exec(ctx, "ROLLBACK TO SAVEPOINT s"); err != nil {
			t.Fatal(err)
		}
	}
	// Since migration 0009 it may invite (create an account with its email
	// only), but never write a password or any other column on insert, nor
	// create organizations.
	for name, stmt := range map[string]string{
		"user with a password": "INSERT INTO users (email, password_hash) VALUES ('x@example.com', 'hash')",
		"disabled user":        "INSERT INTO users (email, disabled_at) VALUES ('y@example.com', now())",
		"organization":         "INSERT INTO organizations (name) VALUES ('Evil')",
	} {
		if _, err := tx.Exec(ctx, "SAVEPOINT s"); err != nil {
			t.Fatal(err)
		}
		_, err := tx.Exec(ctx, stmt)
		if err == nil || !strings.Contains(err.Error(), "permission denied") {
			t.Errorf("auth role creating a %s = %v, want permission denied", name, err)
		}
		if _, err := tx.Exec(ctx, "ROLLBACK TO SAVEPOINT s"); err != nil {
			t.Fatal(err)
		}
	}
}
