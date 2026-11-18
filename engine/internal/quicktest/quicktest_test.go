package quicktest

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/jordyorel/orus-shield/engine/internal/finding"
	"github.com/jordyorel/orus-shield/engine/internal/module"
)

func TestNormalizeDomain(t *testing.T) {
	for in, want := range map[string]string{
		"Example.COM":        "example.com",
		" shop.example.cg. ": "shop.example.cg",
		"localhost":          "",
		"intranet":           "",
		"127.0.0.1":          "",
		"10.0.0.1":           "",
		"printer.local":      "",
		"db.internal":        "",
		"router.home.arpa":   "",
		"x.onion":            "",
		"exa mple.com":       "",
		"":                   "",
	} {
		got, err := NormalizeDomain(in)
		if want == "" {
			if !errors.Is(err, ErrInvalidDomain) {
				t.Errorf("NormalizeDomain(%q) = %q, %v; want ErrInvalidDomain", in, got, err)
			}
			continue
		}
		if err != nil || got != want {
			t.Errorf("NormalizeDomain(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
}

// Public decides which addresses a test may connect to: the guard against
// server-side request forgery.
func TestPublic(t *testing.T) {
	for in, want := range map[string]bool{
		"93.184.216.34":        true,
		"2606:4700::6810:84e5": true,
		"127.0.0.1":            false,
		"10.1.2.3":             false,
		"172.16.0.1":           false,
		"192.168.1.1":          false,
		"169.254.169.254":      false, // cloud metadata
		"100.64.0.1":           false,
		"0.0.0.0":              false,
		"255.255.255.255":      false,
		"224.0.0.1":            false,
		"192.0.2.10":           false,
		"198.18.0.1":           false,
		"::1":                  false,
		"fe80::1":              false,
		"fd00::1":              false,
		"::ffff:127.0.0.1":     false, // IPv4-mapped loopback
		"::ffff:93.184.216.34": true,
		"64:ff9b::a00:1":       false, // NAT64 of 10.0.0.1
		"2002:a00:1::1":        false, // 6to4 of 10.0.0.1
		"2001:db8::1":          false,
	} {
		if got := Public(netip.MustParseAddr(in)); got != want {
			t.Errorf("Public(%s) = %v, want %v", in, got, want)
		}
	}
}

func TestGateRefusesPrivateAddresses(t *testing.T) {
	g, err := NewGate(1000)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := g.Allow(ctx, module.Destination{Host: "evil.example", IP: netip.MustParseAddr("127.0.0.1"), Port: 443}); !errors.Is(err, module.ErrExcluded) {
		t.Errorf("loopback allowed: %v", err)
	}
	if err := g.Allow(ctx, module.Destination{Host: "example.com", IP: netip.MustParseAddr("93.184.216.34"), Port: 443}); err != nil {
		t.Errorf("public address refused: %v", err)
	}
	if err := g.Allow(ctx, module.Destination{Host: "example.com"}); err != nil {
		t.Errorf("DNS lookup refused: %v", err)
	}
}

// fakeModule returns a fixed result, or an error.
type fakeModule struct {
	info module.Info
	res  module.Result
	err  error
	got  module.Request
}

func (f *fakeModule) Info() module.Info { return f.info }
func (f *fakeModule) Run(_ context.Context, req module.Request) (module.Result, error) {
	f.got = req
	return f.res, f.err
}

func emailModule() *fakeModule {
	info := module.Info{ID: "email", Name: "Email", Kind: module.KindPassive, Checks: []module.Check{
		{ID: "dmarc-missing", Category: module.CategoryEmail, Severity: finding.SeverityHigh, Title: "DMARC record published", TitleFR: "Enregistrement DMARC publié"},
		{ID: "spf-missing", Category: module.CategoryEmail, Severity: finding.SeverityHigh, Title: "SPF record published", TitleFR: "Enregistrement SPF publié"},
		{ID: "dkim", Category: module.CategoryEmail, Severity: finding.SeverityLow, Title: "DKIM", TitleFR: "DKIM"},
	}}
	f := finding.Finding{ModuleID: "email", CheckID: "dmarc-missing", Title: "No DMARC record", Severity: finding.SeverityHigh}
	return &fakeModule{info: info, res: module.Result{Findings: []finding.Finding{f}, Evaluated: []string{"spf-missing"}}}
}

func TestRun(t *testing.T) {
	now := time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)
	email := emailModule()
	broken := &fakeModule{info: module.Info{ID: "web", Name: "Web", Kind: module.KindPassive}, err: errors.New("boom")}
	rep, err := Run(context.Background(), []module.Module{email, broken}, " Example.com ", now)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	// The name and its www only, behind the public gate.
	if got := email.got.Target; got.Domain != "example.com" || len(got.Hosts) != 2 || got.Hosts[1] != "www.example.com" || got.Verified {
		t.Errorf("target = %+v", got)
	}
	if _, ok := email.got.Gate.(*Gate); !ok {
		t.Errorf("gate = %T, want the public gate", email.got.Gate)
	}
	// One high check failed, one passed, DKIM not applicable: 6 of 12.
	if rep.Score == nil || *rep.Score != 50 {
		t.Errorf("score = %v, want 50", rep.Score)
	}
	if len(rep.Checks) != 2 || len(rep.Findings) != 1 || rep.Domain != "example.com" || !rep.At.Equal(now) {
		t.Errorf("report = %+v", rep)
	}
}

func TestRunRefusesActiveModulesAndBadNames(t *testing.T) {
	active := &fakeModule{info: module.Info{ID: "ports", Name: "Ports", Kind: module.KindActive}}
	if _, err := Run(context.Background(), []module.Module{active}, "example.com", time.Now()); err == nil {
		t.Error("an active module ran in a public test")
	}
	if active.got.Target.Domain != "" {
		t.Error("the active module was called")
	}
	if _, err := Run(context.Background(), []module.Module{emailModule()}, "localhost", time.Now()); !errors.Is(err, ErrInvalidDomain) {
		t.Errorf("localhost: %v", err)
	}
	broken := &fakeModule{info: module.Info{ID: "web", Name: "Web", Kind: module.KindPassive}, err: errors.New("boom")}
	if _, err := Run(context.Background(), []module.Module{broken}, "example.com", time.Now()); err == nil {
		t.Error("a test where nothing ran succeeded")
	}
}
