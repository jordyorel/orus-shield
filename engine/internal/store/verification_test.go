package store

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

const token = "0123456789abcdef0123456789abcdef"

func TestVerificationFlow(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	target := newTarget(t, s, "example.com")

	expires := time.Now().Add(time.Hour).UTC().Truncate(time.Microsecond)
	if err := s.IssueVerificationToken(ctx, target.ID, token, expires, "cli:jordy"); err != nil {
		t.Fatalf("IssueVerificationToken: %v", err)
	}
	got, err := s.GetTarget(ctx, target.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.VerifyToken != token || got.VerifyTokenExpiresAt == nil || !got.VerifyTokenExpiresAt.Equal(expires) || got.Verified() {
		t.Fatalf("after issue: %+v", got)
	}

	// A wrong token never verifies.
	if err := s.MarkVerified(ctx, target.ID, "wrong", "cli:jordy"); !errors.Is(err, ErrTokenMismatch) {
		t.Errorf("MarkVerified(wrong token) = %v, want ErrTokenMismatch", err)
	}
	if err := s.MarkVerified(ctx, target.ID, token, "cli:jordy"); err != nil {
		t.Fatalf("MarkVerified: %v", err)
	}
	got, _ = s.GetTarget(ctx, target.ID)
	if !got.Verified() || got.VerifyCheckedAt == nil || got.VerifyTokenExpiresAt != nil {
		t.Fatalf("after verify: %+v", got)
	}

	// The token of a verified target cannot be replaced.
	if err := s.IssueVerificationToken(ctx, target.ID, "other", expires, "cli:jordy"); !errors.Is(err, ErrAlreadyVerified) {
		t.Errorf("IssueVerificationToken on verified target = %v, want ErrAlreadyVerified", err)
	}
	if err := s.TouchVerification(ctx, target.ID); err != nil {
		t.Errorf("TouchVerification: %v", err)
	}

	// Revocation keeps the token, with a new deadline, so the same record
	// can verify the target again.
	if err := s.RevokeVerification(ctx, target.ID, "worker:a", "record missing", time.Hour); err != nil {
		t.Fatalf("RevokeVerification: %v", err)
	}
	got, _ = s.GetTarget(ctx, target.ID)
	if got.Verified() || got.VerifyToken != token || got.VerifyTokenExpiresAt == nil {
		t.Fatalf("after revoke: %+v", got)
	}
	if err := s.MarkVerified(ctx, target.ID, token, "cli:jordy"); err != nil {
		t.Errorf("MarkVerified after revoke: %v", err)
	}

	want := []string{
		"cli:jordy " + ActionVerifyTokenIssued,
		"cli:jordy " + ActionVerified,
		"worker:a " + ActionVerificationRevoked,
		"cli:jordy " + ActionVerified,
	}
	if got := actions(t, s, "example.com"); strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("audit = %v, want %v", got, want)
	}
}

func TestExpiredTokenCannotVerify(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	target := newTarget(t, s, "example.com")
	if err := s.IssueVerificationToken(ctx, target.ID, token, time.Now().Add(-time.Minute), "cli:jordy"); err != nil {
		t.Fatal(err)
	}
	if err := s.MarkVerified(ctx, target.ID, token, "cli:jordy"); !errors.Is(err, ErrTokenMismatch) {
		t.Errorf("MarkVerified(expired token) = %v, want ErrTokenMismatch", err)
	}
}

// The database itself refuses a verified target without a token.
func TestVerifiedNeedsTokenConstraint(t *testing.T) {
	s := newTestStore(t)
	target := newTarget(t, s, "example.com")
	_, err := s.pool.Exec(context.Background(), "UPDATE targets SET verified_at = now() WHERE id = $1", target.ID)
	if err == nil || !strings.Contains(err.Error(), "verified_needs_token") {
		t.Errorf("direct UPDATE = %v, want the verified_needs_token constraint", err)
	}
}

func TestVerificationNotFound(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	const unknown = "0190a000-0000-7000-8000-000000000000"
	target := newTarget(t, s, "example.com")

	if err := s.IssueVerificationToken(ctx, unknown, token, time.Now().Add(time.Hour), "x"); !errors.Is(err, ErrNotFound) {
		t.Errorf("IssueVerificationToken(unknown) = %v", err)
	}
	if err := s.TouchVerification(ctx, target.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("TouchVerification(unverified) = %v, want ErrNotFound", err)
	}
	if err := s.RevokeVerification(ctx, target.ID, "x", "y", time.Hour); !errors.Is(err, ErrNotFound) {
		t.Errorf("RevokeVerification(unverified) = %v, want ErrNotFound", err)
	}
}
