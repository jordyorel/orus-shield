package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestTeam(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	auth := s.Auth()
	org := defaultOrg(t, s)
	other, err := s.CreateOrganization(ctx, "Other", "test")
	if err != nil {
		t.Fatal(err)
	}
	admin, err := s.CreateUser(ctx, "admin@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetMembership(ctx, admin.ID, org.ID(), RoleAdmin, "test"); err != nil {
		t.Fatal(err)
	}

	// A new address: account, membership and a setup token.
	inv, err := auth.Invite(ctx, org.ID(), "New@Example.com", RoleViewer, time.Hour, "admin@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if inv.Token == "" || inv.Member.Email != "new@example.com" || inv.Member.Role != RoleViewer || inv.Member.Activated {
		t.Fatalf("invitation = %+v", inv)
	}
	if _, err := auth.Invite(ctx, org.ID(), "new@example.com", RoleAdmin, time.Hour, "x"); !errors.Is(err, ErrExists) {
		t.Errorf("second invitation = %v, want ErrExists", err)
	}
	// The token works once, and a reissued one revokes it.
	again, err := auth.ReissueSetupToken(ctx, org.ID(), inv.Member.UserID, time.Hour, "x")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := auth.SetPasswordWithToken(ctx, inv.Token, "hash", ""); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("revoked token = %v, want ErrInvalidToken", err)
	}
	if _, err := auth.SetPasswordWithToken(ctx, again, "hash", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := auth.ReissueSetupToken(ctx, org.ID(), inv.Member.UserID, time.Hour, "x"); !errors.Is(err, ErrExists) {
		t.Errorf("token for an activated account = %v, want ErrExists", err)
	}

	// An activated account joins another organization without a token.
	inv2, err := auth.Invite(ctx, other.ID, "new@example.com", RoleAdmin, time.Hour, "x")
	if err != nil || inv2.Token != "" || !inv2.Member.Activated {
		t.Errorf("activated account invited elsewhere = %+v, %v", inv2, err)
	}

	ms, err := auth.Members(ctx, org.ID())
	if err != nil || len(ms) != 2 || ms[0].Email != "admin@example.com" || ms[1].Email != "new@example.com" {
		t.Fatalf("members = %+v, %v", ms, err)
	}

	// The last admin cannot be demoted or removed; with two, one can.
	if err := auth.SetMemberRole(ctx, org.ID(), admin.ID, RoleViewer); !errors.Is(err, ErrLastAdmin) {
		t.Errorf("demote last admin = %v, want ErrLastAdmin", err)
	}
	if err := auth.RemoveMember(ctx, org.ID(), admin.ID); !errors.Is(err, ErrLastAdmin) {
		t.Errorf("remove last admin = %v, want ErrLastAdmin", err)
	}
	if err := auth.SetMemberRole(ctx, org.ID(), inv.Member.UserID, RoleAdmin); err != nil {
		t.Fatal(err)
	}
	if err := auth.SetMemberRole(ctx, org.ID(), admin.ID, RoleViewer); err != nil {
		t.Errorf("demote with another admin = %v", err)
	}
	if err := auth.RemoveMember(ctx, org.ID(), admin.ID); err != nil {
		t.Fatal(err)
	}
	if err := auth.RemoveMember(ctx, org.ID(), admin.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("remove twice = %v, want ErrNotFound", err)
	}
	// The other organization's member list is not this one's.
	if ms, _ := auth.Members(ctx, other.ID); len(ms) != 1 || ms[0].Email != "new@example.com" {
		t.Errorf("other organization's members = %+v", ms)
	}
}

func TestChangePassword(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	auth := s.Auth()
	u, err := s.CreateUser(ctx, "alice@example.com")
	if err != nil {
		t.Fatal(err)
	}
	expires := time.Now().Add(time.Hour)
	keep, err := auth.CreateSession(ctx, u.ID, "", "", expires)
	if err != nil {
		t.Fatal(err)
	}
	other, err := auth.CreateSession(ctx, u.ID, "", "", expires)
	if err != nil {
		t.Fatal(err)
	}
	if err := auth.ChangePassword(ctx, u.ID, "new-hash", keep, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := auth.SessionUser(ctx, keep, time.Hour); err != nil {
		t.Errorf("current session closed: %v", err)
	}
	if _, err := auth.SessionUser(ctx, other, time.Hour); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("other session still open: %v", err)
	}
	if got, _ := s.UserByEmail(ctx, "alice@example.com"); got.PasswordHash != "new-hash" {
		t.Errorf("hash = %q", got.PasswordHash)
	}
}
