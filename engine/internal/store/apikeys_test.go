package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestAPIKeyStore(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	oa, err := s.CreateOrganization(ctx, "A", "test")
	if err != nil {
		t.Fatal(err)
	}
	ob, err := s.CreateOrganization(ctx, "B", "test")
	if err != nil {
		t.Fatal(err)
	}
	a, _ := s.Org(oa.ID)
	b, _ := s.Org(ob.ID)
	now := time.Now()

	k, secret, err := a.CreateAPIKey(ctx, " CI ", ScopeRead, nil, "user:x")
	if err != nil || k.Name != "CI" || k.Prefix != secret[:12] {
		t.Fatalf("create = %+v, %v", k, err)
	}
	if _, _, err := a.CreateAPIKey(ctx, "", ScopeRead, nil, "user:x"); !errors.Is(err, ErrBadKeyRequest) {
		t.Errorf("no name: %v", err)
	}
	if _, _, err := a.CreateAPIKey(ctx, "x", "admin", nil, "user:x"); !errors.Is(err, ErrBadKeyRequest) {
		t.Errorf("bad scope: %v", err)
	}
	ka, err := s.Auth().KeyAccess(ctx, secret, now)
	if err != nil || ka.OrgID != oa.ID || ka.Scope != ScopeRead || ka.Name != "CI" {
		t.Fatalf("access = %+v, %v", ka, err)
	}

	// Row-level security: B neither sees nor revokes A's keys.
	if keys, err := b.APIKeys(ctx); err != nil || len(keys) != 0 {
		t.Errorf("B sees %d keys, %v", len(keys), err)
	}
	if err := b.RevokeAPIKey(ctx, k.ID, "user:y"); !errors.Is(err, ErrNotFound) {
		t.Errorf("B revokes A's key: %v", err)
	}

	// An expired key no longer works.
	past := now.Add(-time.Minute)
	_, old, err := a.CreateAPIKey(ctx, "old", ScopeWrite, &past, "user:x")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Auth().KeyAccess(ctx, old, now); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("expired key: %v", err)
	}
	if err := a.RevokeAPIKey(ctx, k.ID, "user:x"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Auth().KeyAccess(ctx, secret, now); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("revoked key: %v", err)
	}
	if keys, _ := a.APIKeys(ctx); len(keys) != 2 || keys[1].RevokedAt == nil && keys[0].RevokedAt == nil {
		t.Errorf("A's keys = %+v", keys)
	}
}
