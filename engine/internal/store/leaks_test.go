package store

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// The leaks module checks the members on the domain and the declared
// addresses; an organization never sees or removes another's addresses.
func TestLeakAddresses(t *testing.T) {
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
	ta, err := a.CreateTarget(ctx, NewTarget{Domain: "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range []struct{ email, org string }{
		{"alice@example.com", oa.ID},    // member on the domain: checked
		{"bob@mail.example.com", oa.ID}, // under the domain: checked
		{"carol@gmail.com", oa.ID},      // elsewhere: not checked
		{"dave@example.com", ob.ID},     // another organization: not checked
	} {
		u, err := s.CreateUser(ctx, m.email)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.SetMembership(ctx, u.ID, m.org, "viewer", "test"); err != nil {
			t.Fatal(err)
		}
	}

	added, err := a.AddLeakAddress(ctx, ta.ID, " Compta@Example.com ", "user:x")
	if err != nil || added.Email != "compta@example.com" {
		t.Fatalf("add = %+v, %v", added, err)
	}
	if _, err := a.AddLeakAddress(ctx, ta.ID, "compta@example.com", "user:x"); !errors.Is(err, ErrExists) {
		t.Errorf("duplicate: %v", err)
	}
	if _, err := b.AddLeakAddress(ctx, ta.ID, "x@example.com", "user:y"); err == nil {
		t.Error("B declared an address on A's domain")
	}
	if list, err := b.LeakAddresses(ctx, ta.ID); err != nil || len(list) != 0 {
		t.Errorf("B sees %d addresses, %v", len(list), err)
	}
	if err := b.RemoveLeakAddress(ctx, ta.ID, added.ID, "user:y"); !errors.Is(err, ErrNotFound) {
		t.Errorf("B removes A's address: %v", err)
	}

	got, err := s.LeakEmails(ctx, ta.ID)
	if err != nil {
		t.Fatal(err)
	}
	if want := "alice@example.com,bob@mail.example.com,compta@example.com"; strings.Join(got, ",") != want {
		t.Errorf("LeakEmails = %v, want %s", got, want)
	}

	if err := a.RemoveLeakAddress(ctx, ta.ID, added.ID, "user:x"); err != nil {
		t.Fatal(err)
	}
	if list, _ := a.LeakAddresses(ctx, ta.ID); len(list) != 0 {
		t.Errorf("after removal: %v", list)
	}
}
