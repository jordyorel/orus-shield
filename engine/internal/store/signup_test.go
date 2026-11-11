package store

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

func TestSignup(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	auth := s.Auth() // runs as orus_auth: proves the grants are enough

	token, existing, err := auth.RequestSignup(ctx, " New@Example.com ", "  Acme   Microfinance ", "192.0.2.1", time.Hour)
	if err != nil || existing || token == "" {
		t.Fatalf("RequestSignup = %q, %v, %v", token, existing, err)
	}
	// Nothing exists before the link is used.
	if _, err := s.UserByEmail(ctx, "new@example.com"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("account created before confirmation: %v", err)
	}

	u, orgID, err := auth.CompleteSignup(ctx, token, "$argon2id$x", "192.0.2.1")
	if err != nil || u.Email != "new@example.com" || orgID == "" {
		t.Fatalf("CompleteSignup = %+v, %q, %v", u, orgID, err)
	}
	ms, err := auth.Memberships(ctx, u.ID)
	if err != nil || len(ms) != 1 || ms[0].OrgID != orgID || ms[0].Role != RoleAdmin || ms[0].OrgName != "Acme Microfinance" {
		t.Errorf("memberships = %+v, %v", ms, err)
	}
	stored, err := s.UserByEmail(ctx, "new@example.com")
	if err != nil || stored.PasswordHash != "$argon2id$x" {
		t.Errorf("user = %+v, %v", stored, err)
	}
	// The link works once.
	if _, _, err := auth.CompleteSignup(ctx, token, "$argon2id$y", ""); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("token reused: %v, want ErrInvalidToken", err)
	}

	// An address with an account: no request, existing reported.
	token, existing, err = auth.RequestSignup(ctx, "new@example.com", "Other", "192.0.2.1", time.Hour)
	if err != nil || !existing || token != "" {
		t.Errorf("existing address = %q, %v, %v", token, existing, err)
	}

	// A newer request revokes the older one; an expired one never works.
	first, _, _ := auth.RequestSignup(ctx, "two@example.com", "Two", "192.0.2.2", time.Hour)
	second, _, _ := auth.RequestSignup(ctx, "two@example.com", "Two", "192.0.2.2", time.Hour)
	if _, _, err := auth.CompleteSignup(ctx, first, "h", ""); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("revoked request: %v", err)
	}
	expired, _, _ := auth.RequestSignup(ctx, "three@example.com", "Three", "192.0.2.3", -time.Minute)
	if _, _, err := auth.CompleteSignup(ctx, expired, "h", ""); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("expired request: %v", err)
	}
	// The address got an account by another path before the link was used.
	if _, err := s.CreateUser(ctx, "two@example.com"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := auth.CompleteSignup(ctx, second, "h", ""); !errors.Is(err, ErrExists) {
		t.Errorf("address taken meanwhile: %v, want ErrExists", err)
	}

	byEmail, byIP, err := auth.RecentSignupRequests(ctx, "two@example.com", "192.0.2.2", time.Now().Add(-time.Hour))
	if err != nil || byEmail != 2 || byIP != 2 {
		t.Errorf("recent requests = %d, %d, %v; want 2, 2", byEmail, byIP, err)
	}

	if n, err := NormalizeOrgName(" Acme\n\tSA "); err != nil || n != "Acme SA" {
		t.Errorf("NormalizeOrgName = %q, %v; line breaks and tabs become one space", n, err)
	}
	for _, bad := range []string{"", "   ", "a\x00b", "a\x1bb", string(make([]rune, MaxOrgNameChars+1))} {
		if _, _, err := auth.RequestSignup(ctx, "x@example.com", bad, "", time.Hour); err == nil {
			t.Errorf("org name %q accepted", bad)
		}
	}
}

// The function is the only way for the auth role to create an
// organization, and only for a request consumed in the same transaction.
func TestSignupFunctionNeedsAConsumedRequest(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	token, _, err := s.Auth().RequestSignup(ctx, "x@example.com", "X", "", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	err = s.Auth().inTx(ctx, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, "SELECT signup_create_organization($1)", tokenHash(token))
		return err
	})
	if err == nil || !strings.Contains(err.Error(), "no signup request consumed") {
		t.Errorf("function on an unconsumed request = %v, want refused", err)
	}
	// Once used, the same token cannot create a second organization.
	if _, _, err := s.Auth().CompleteSignup(ctx, token, "h", ""); err != nil {
		t.Fatal(err)
	}
	err = s.Auth().inTx(ctx, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, "SELECT signup_create_organization($1)", tokenHash(token))
		return err
	})
	if err == nil {
		t.Error("function reused on a completed request: nil error")
	}
}
