package module

import (
	"context"
	"errors"
	"testing"

	"github.com/jordyorel/orus-shield/engine/internal/finding"
)

// fakeModule is a minimal Module used to test the registry and the rules.
type fakeModule struct{ info Info }

func (m fakeModule) Info() Info { return m.info }

func (m fakeModule) Run(ctx context.Context, req Request) ([]finding.Finding, error) {
	return nil, nil
}

func TestKindValid(t *testing.T) {
	tests := []struct {
		in   Kind
		want bool
	}{
		{KindPassive, true},
		{KindActive, true},
		{"", false},
		{"Active", false},
	}
	for _, tt := range tests {
		if got := tt.in.Valid(); got != tt.want {
			t.Errorf("Kind(%q).Valid() = %v, want %v", tt.in, got, tt.want)
		}
	}
}

func TestCheckAllowed(t *testing.T) {
	unverified := Target{Domain: "example.com", Verified: false}
	verified := Target{Domain: "example.com", Verified: true}

	tests := []struct {
		name    string
		kind    Kind
		target  Target
		wantErr error // nil means allowed
	}{
		{"passive on unverified", KindPassive, unverified, nil},
		{"passive on verified", KindPassive, verified, nil},
		{"active on unverified", KindActive, unverified, ErrNotVerified},
		{"active on verified", KindActive, verified, nil},
		// Fail closed: an unknown kind is never allowed to run.
		{"unknown kind on verified", "", verified, ErrInvalidKind},
		{"unknown kind on unverified", "aggressive", unverified, ErrInvalidKind},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info := Info{ID: "test", Name: "Test", Kind: tt.kind}
			err := CheckAllowed(info, tt.target)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("CheckAllowed() = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestRegistryRegister(t *testing.T) {
	tests := []struct {
		name    string
		module  Module
		wantErr bool
	}{
		{"valid passive", fakeModule{Info{ID: "email", Name: "Email", Kind: KindPassive}}, false},
		{"valid active", fakeModule{Info{ID: "ports", Name: "Ports", Kind: KindActive}}, false},
		{"nil module", nil, true},
		{"empty id", fakeModule{Info{ID: "", Name: "X", Kind: KindPassive}}, true},
		{"id not a slug", fakeModule{Info{ID: "Email Check", Name: "X", Kind: KindPassive}}, true},
		{"empty name", fakeModule{Info{ID: "x", Name: "", Kind: KindPassive}}, true},
		{"invalid kind", fakeModule{Info{ID: "x", Name: "X", Kind: "aggressive"}}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := NewRegistry()
			err := r.Register(tt.module)
			if (err != nil) != tt.wantErr {
				t.Errorf("Register() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestRegistryRejectsDuplicate(t *testing.T) {
	r := NewRegistry()
	m := fakeModule{Info{ID: "email", Name: "Email", Kind: KindPassive}}
	if err := r.Register(m); err != nil {
		t.Fatalf("first Register() = %v", err)
	}
	if err := r.Register(m); err == nil {
		t.Fatal("second Register() with the same ID = nil, want error")
	}
}

func TestRegistryGetAndAll(t *testing.T) {
	r := NewRegistry()
	for _, id := range []string{"tls", "email", "ports"} {
		if err := r.Register(fakeModule{Info{ID: id, Name: id, Kind: KindPassive}}); err != nil {
			t.Fatalf("Register(%q) = %v", id, err)
		}
	}

	if m, ok := r.Get("email"); !ok || m.Info().ID != "email" {
		t.Errorf("Get(\"email\") = %v, %v; want the email module", m, ok)
	}
	if _, ok := r.Get("missing"); ok {
		t.Error("Get(\"missing\") ok = true, want false")
	}

	all := r.All()
	want := []string{"email", "ports", "tls"}
	if len(all) != len(want) {
		t.Fatalf("len(All()) = %d, want %d", len(all), len(want))
	}
	for i, m := range all {
		if m.Info().ID != want[i] {
			t.Errorf("All()[%d] = %q, want %q (sorted by ID)", i, m.Info().ID, want[i])
		}
	}
}
