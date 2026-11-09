package module

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jordyorel/orus-shield/engine/internal/finding"
)

// fakeModule is a minimal Module used to test the registry and the rules.
type fakeModule struct{ info Info }

func (m fakeModule) Info() Info { return m.info }

func (m fakeModule) Run(ctx context.Context, req Request) (Result, error) {
	return Result{}, nil
}

// withCheck gives info a one-check catalog, which Register requires.
func withCheck(info Info) Info {
	info.Checks = []Check{{ID: info.ID + "-check", Category: CategoryEmail, Severity: finding.SeverityLow, Title: "A check"}}
	return info
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
		{"valid passive", fakeModule{withCheck(Info{ID: "email", Name: "Email", Kind: KindPassive})}, false},
		{"valid active", fakeModule{withCheck(Info{ID: "ports", Name: "Ports", Kind: KindActive})}, false},
		{"nil module", nil, true},
		{"empty id", fakeModule{withCheck(Info{ID: "", Name: "X", Kind: KindPassive})}, true},
		{"id not a slug", fakeModule{withCheck(Info{ID: "Email Check", Name: "X", Kind: KindPassive})}, true},
		{"empty name", fakeModule{withCheck(Info{ID: "x", Name: "", Kind: KindPassive})}, true},
		{"invalid kind", fakeModule{withCheck(Info{ID: "x", Name: "X", Kind: "aggressive"})}, true},
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
	m := fakeModule{withCheck(Info{ID: "email", Name: "Email", Kind: KindPassive})}
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
		if err := r.Register(fakeModule{withCheck(Info{ID: id, Name: id, Kind: KindPassive})}); err != nil {
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

func TestNormalizeDomain(t *testing.T) {
	tests := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{"example.com", "example.com", false},
		{" Example.COM. ", "example.com", false},
		{"", "", true},
		{"example..com", "", true},
		{"exa mple.com", "", true},
		{"https://example.com", "", true},
		{strings.Repeat("a.", 127) + "com", "", true},
	}
	for _, tt := range tests {
		got, err := NormalizeDomain(tt.in)
		if (err != nil) != tt.wantErr {
			t.Errorf("NormalizeDomain(%q) error = %v, wantErr %v", tt.in, err, tt.wantErr)
			continue
		}
		if got != tt.want {
			t.Errorf("NormalizeDomain(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestRegistryValidatesCatalog(t *testing.T) {
	check := func(mut func(*Check)) []Check {
		c := Check{ID: "x-check", Category: CategoryTLS, Severity: finding.SeverityHigh, Title: "X"}
		mut(&c)
		return []Check{c}
	}
	tests := []struct {
		name   string
		checks []Check
	}{
		{"no checks", nil},
		{"check id not a slug", check(func(c *Check) { c.ID = "X Check" })},
		{"unknown category", check(func(c *Check) { c.Category = "printers" })},
		{"unknown severity", check(func(c *Check) { c.Severity = "severe" })},
		{"empty title", check(func(c *Check) { c.Title = "" })},
		{"declared twice", append(check(func(*Check) {}), check(func(*Check) {})...)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := NewRegistry().Register(fakeModule{Info{ID: "x", Name: "X", Kind: KindPassive, Checks: tt.checks}})
			if err == nil {
				t.Error("Register() = nil, want error")
			}
		})
	}

	r := NewRegistry()
	if err := r.Register(fakeModule{withCheck(Info{ID: "a", Name: "A", Kind: KindPassive})}); err != nil {
		t.Fatal(err)
	}
	other := Info{ID: "b", Name: "B", Kind: KindPassive, Checks: withCheck(Info{ID: "a"}).Checks}
	if err := r.Register(fakeModule{other}); err == nil || !strings.Contains(err.Error(), "already declared by module") {
		t.Errorf("check ID shared by two modules: Register() = %v, want error", err)
	}
}

func TestEvaluate(t *testing.T) {
	info := Info{ID: "email", Checks: []Check{
		{ID: "spf-missing", Severity: finding.SeverityHigh},
		{ID: "spf-pass-all", Severity: finding.SeverityCritical},
		{ID: "dmarc-missing", Severity: finding.SeverityHigh},
		{ID: "dmarc-policy-none", Severity: finding.SeverityMedium},
	}}
	f := func(check string) finding.Finding { return finding.Finding{CheckID: check} }

	got, err := Evaluate(info, Result{
		Findings:  []finding.Finding{f("dmarc-missing"), f("dmarc-missing")},
		Evaluated: []string{"spf-missing", "spf-pass-all", "dmarc-missing"},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]CheckStatus{
		"spf-missing":       CheckPassed,
		"spf-pass-all":      CheckPassed,
		"dmarc-missing":     CheckFailed,
		"dmarc-policy-none": CheckNotApplicable, // never claimed: not passed
	}
	if len(got) != len(want) {
		t.Fatalf("Evaluate = %+v, want one outcome per catalog check", got)
	}
	for _, o := range got {
		if o.Status != want[o.ID] {
			t.Errorf("%s = %s, want %s", o.ID, o.Status, want[o.ID])
		}
		if o.ID == "dmarc-missing" && o.Findings != 2 {
			t.Errorf("dmarc-missing findings = %d, want 2", o.Findings)
		}
	}

	if _, err := Evaluate(info, Result{Findings: []finding.Finding{f("dkim-typo")}}); err == nil {
		t.Error("finding for an undeclared check: Evaluate() = nil, want error")
	}
	if _, err := Evaluate(info, Result{Evaluated: []string{"dkim-typo"}}); err == nil {
		t.Error("undeclared evaluated check: Evaluate() = nil, want error")
	}
}
