package store

import (
	"context"
	"errors"
	"testing"
)

// A connection is per domain and per organization: another organization
// neither sees nor removes it, and one tenant connects to one domain only.
func TestIdentityConnections(t *testing.T) {
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
	ta2, err := a.CreateTarget(ctx, NewTarget{Domain: "example.org"})
	if err != nil {
		t.Fatal(err)
	}
	const tenant = "0b1c2d3e-4f50-6172-8394-a5b6c7d8e9f0"
	c := IdentityConnection{TargetID: ta.ID, Provider: ProviderM365, TenantID: tenant, TenantName: "contoso.onmicrosoft.com", Permissions: []string{"User.Read.All"}}

	if err := b.ConnectIdentity(ctx, c, "user:y"); err == nil {
		t.Error("B connected a tenant to A's domain")
	}
	if err := a.ConnectIdentity(ctx, c, "user:x"); err != nil {
		t.Fatal(err)
	}
	// Reconnecting replaces it.
	if err := a.ConnectIdentity(ctx, c, "user:z"); err != nil {
		t.Fatalf("reconnect: %v", err)
	}
	other := c
	other.TargetID = ta2.ID
	if err := a.ConnectIdentity(ctx, other, "user:x"); !errors.Is(err, ErrTenantInUse) {
		t.Errorf("same tenant on a second domain: %v, want ErrTenantInUse", err)
	}
	bad := c
	bad.TenantID = "contoso"
	if err := a.ConnectIdentity(ctx, bad, "user:x"); err == nil {
		t.Error("a tenant ID that is not a GUID was stored")
	}

	list, err := a.IdentityConnections(ctx)
	if err != nil || len(list) != 1 || list[0].Domain != "example.com" || list[0].ConnectedBy != "user:z" || list[0].TenantName != "contoso.onmicrosoft.com" {
		t.Fatalf("A's connections = %+v, %v", list, err)
	}
	if list, err := b.IdentityConnections(ctx); err != nil || len(list) != 0 {
		t.Errorf("B sees %d connections, %v", len(list), err)
	}
	got, err := s.TargetIdentity(ctx, ta.ID, ProviderM365)
	if err != nil || got == nil || got.TenantID != tenant {
		t.Errorf("worker read = %+v, %v", got, err)
	}
	if got, err := s.TargetIdentity(ctx, ta2.ID, ProviderM365); err != nil || got != nil {
		t.Errorf("unconnected domain = %+v, %v", got, err)
	}

	if err := b.DisconnectIdentity(ctx, ta.ID, ProviderM365, "user:y"); !errors.Is(err, ErrNotFound) {
		t.Errorf("B disconnects A's tenant: %v", err)
	}
	if err := a.DisconnectIdentity(ctx, ta.ID, ProviderM365, "user:x"); err != nil {
		t.Fatal(err)
	}
	if err := a.DisconnectIdentity(ctx, ta.ID, ProviderM365, "user:x"); !errors.Is(err, ErrNotFound) {
		t.Errorf("second disconnect: %v", err)
	}
	entries, err := a.AuditLog(ctx, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	var connected, disconnected int
	for _, e := range entries {
		switch e.Action {
		case ActionIdentityConnected:
			connected++
		case ActionIdentityDisconnected:
			disconnected++
		}
	}
	if connected != 2 || disconnected != 1 {
		t.Errorf("audit: %d connected, %d disconnected; want 2 and 1", connected, disconnected)
	}
}
