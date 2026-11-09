package email

import (
	"context"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jordyorel/orus-shield/engine/internal/finding"
	"github.com/jordyorel/orus-shield/engine/internal/module"
	"github.com/jordyorel/orus-shield/engine/internal/resolver"
)

// fakeDNS is an in-memory DNS. Names missing from the maps answer
// ErrNotFound, like NXDOMAIN. No real DNS server is ever queried.
type fakeDNS struct {
	txt   map[string][]string
	mx    map[string][]*net.MX
	fail  map[string]error // forced errors (timeouts, SERVFAIL), by name
	calls []string
}

func (f *fakeDNS) LookupTXT(ctx context.Context, name string) ([]string, error) {
	f.calls = append(f.calls, name)
	if err := f.fail[name]; err != nil {
		return nil, err
	}
	records, ok := f.txt[name]
	if !ok {
		return nil, fmt.Errorf("lookup %s: %w", name, resolver.ErrNotFound)
	}
	return records, nil
}

func (f *fakeDNS) LookupAddr(ctx context.Context, ip netip.Addr) ([]string, error) {
	return nil, fmt.Errorf("lookup %s: %w", ip, resolver.ErrNotFound)
}

func (f *fakeDNS) LookupMX(ctx context.Context, name string) ([]*net.MX, error) {
	f.calls = append(f.calls, name)
	if err := f.fail[name]; err != nil {
		return nil, err
	}
	records, ok := f.mx[name]
	if !ok {
		return nil, fmt.Errorf("lookup %s: %w", name, resolver.ErrNotFound)
	}
	return records, nil
}

// LookupIP is part of resolver.Resolver; the email module never calls it.
func (f *fakeDNS) LookupIP(ctx context.Context, host string) ([]netip.Addr, error) {
	f.calls = append(f.calls, host)
	return nil, fmt.Errorf("lookup %s: %w", host, resolver.ErrNotFound)
}

// countingGate allows everything (or nothing) and counts requests.
type countingGate struct {
	calls int
	deny  error
}

func (g *countingGate) Allow(ctx context.Context, dest module.Destination) error {
	g.calls++
	return g.deny
}

// rsaKey returns a base64 DER (PKIX) RSA public key whose modulus has the
// given size. Only the size matters for these tests, so the modulus is not a
// real product of primes: this is instant and works below 1024 bits, which
// crypto/rsa refuses to generate.
func rsaKey(t *testing.T, bits int) string {
	t.Helper()
	n := new(big.Int).Lsh(big.NewInt(1), uint(bits-1))
	n.Add(n, big.NewInt(1))
	der, err := x509.MarshalPKIXPublicKey(&rsa.PublicKey{N: n, E: 65537})
	if err != nil {
		t.Fatalf("marshal RSA key: %v", err)
	}
	return base64.StdEncoding.EncodeToString(der)
}

func ed25519Key(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate ed25519 key: %v", err)
	}
	return base64.StdEncoding.EncodeToString(pub)
}

// goodDNS returns a correctly configured example.com: MX, strict SPF with one
// include, enforced DMARC with reporting, and a 2048-bit DKIM key.
func goodDNS(t *testing.T) *fakeDNS {
	return &fakeDNS{
		txt: map[string][]string{
			"example.com": {
				"v=spf1 include:_spf.example.net -all",
				"google-site-verification=abc123",
			},
			"_spf.example.net":                 {"v=spf1 ip4:192.0.2.0/24 -all"},
			"_dmarc.example.com":               {"v=DMARC1; p=reject; rua=mailto:dmarc@example.com"},
			"selector1._domainkey.example.com": {"v=DKIM1; k=rsa; p=" + rsaKey(t, 2048)},
		},
		mx: map[string][]*net.MX{
			"example.com": {{Host: "mx.example.com.", Pref: 10}},
		},
	}
}

func run(t *testing.T, dns *fakeDNS, domain string) ([]finding.Finding, error) {
	t.Helper()
	m := New(dns)
	res, err := m.Run(context.Background(), module.Request{
		Target: module.Target{Domain: domain},
		Gate:   &countingGate{},
	})
	if len(res.Assets) != 0 {
		t.Errorf("email reported assets %v, want none", res.Assets)
	}
	// Every scenario also checks the catalog: no finding may use an
	// undeclared check.
	if err == nil {
		if _, evalErr := module.Evaluate(m.Info(), res); evalErr != nil {
			t.Errorf("Evaluate: %v", evalErr)
		}
	}
	return res.Findings, err
}

// statuses runs the module and returns the status of every catalog check.
func statuses(t *testing.T, dns *fakeDNS) map[string]module.CheckStatus {
	t.Helper()
	m := New(dns)
	res, err := m.Run(context.Background(), module.Request{Target: module.Target{Domain: "example.com"}, Gate: &countingGate{}})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	outcomes, err := module.Evaluate(m.Info(), res)
	if err != nil {
		t.Fatal(err)
	}
	out := make(map[string]module.CheckStatus)
	for _, o := range outcomes {
		out[o.ID] = o.Status
	}
	return out
}

func checkIDs(findings []finding.Finding) []string {
	ids := make([]string, 0, len(findings))
	for _, f := range findings {
		ids = append(ids, f.CheckID)
	}
	slices.Sort(ids)
	return ids
}

func TestInfo(t *testing.T) {
	info := New(&fakeDNS{}).Info()
	if info.ID != ID {
		t.Errorf("ID = %q, want %q", info.ID, ID)
	}
	if info.Kind != module.KindPassive {
		t.Errorf("Kind = %q, want passive: this module only reads public DNS", info.Kind)
	}
	if err := module.NewRegistry().Register(New(&fakeDNS{})); err != nil {
		t.Errorf("Register() = %v", err)
	}
}

func TestRunScenarios(t *testing.T) {
	const (
		apex  = "example.com"
		dmarc = "_dmarc.example.com"
		dkim1 = "selector1._domainkey.example.com"
	)
	// tooManyTerms has 9 DNS-querying terms; with the include that points to
	// it, the total is exactly 10, the RFC 7208 limit.
	const tooManyTerms = "v=spf1 a mx a:a.example.net mx:b.example.net a:c.example.net " +
		"mx:d.example.net a:e.example.net mx:f.example.net exists:g.example.net -all"

	tests := []struct {
		name   string
		mutate func(d *fakeDNS)
		want   []string
	}{
		{"well configured", func(d *fakeDNS) {}, nil},

		// Nothing published.
		{"nothing published, receives mail", func(d *fakeDNS) {
			delete(d.txt, apex)
			delete(d.txt, dmarc)
			delete(d.txt, dkim1)
		}, []string{CheckDKIMNotFound, CheckDMARCMissing, CheckSPFMissing}},
		{"nothing published, no MX", func(d *fakeDNS) {
			delete(d.txt, apex)
			delete(d.txt, dmarc)
			delete(d.txt, dkim1)
			delete(d.mx, apex)
		}, []string{CheckDMARCMissing, CheckSPFMissing}},
		{"nothing published, null MX", func(d *fakeDNS) {
			delete(d.txt, apex)
			delete(d.txt, dmarc)
			delete(d.txt, dkim1)
			d.mx[apex] = []*net.MX{{Host: ".", Pref: 0}}
		}, []string{CheckDMARCMissing, CheckSPFMissing}},

		// SPF.
		{"spf +all", func(d *fakeDNS) { d.txt[apex] = []string{"v=spf1 +all"} },
			[]string{CheckSPFPassAll}},
		{"spf all without qualifier", func(d *fakeDNS) { d.txt[apex] = []string{"v=spf1 a all"} },
			[]string{CheckSPFPassAll}},
		{"spf ?all", func(d *fakeDNS) { d.txt[apex] = []string{"v=spf1 mx ?all"} },
			[]string{CheckSPFNeutralAll}},
		{"spf ~all", func(d *fakeDNS) { d.txt[apex] = []string{"v=spf1 mx ~all"} },
			[]string{CheckSPFSoftfailAll}},
		{"spf without all", func(d *fakeDNS) { d.txt[apex] = []string{"v=spf1 mx"} },
			[]string{CheckSPFNoAll}},
		{"spf redirect replaces all", func(d *fakeDNS) {
			d.txt[apex] = []string{"v=spf1 redirect=_spf.example.net"}
		}, nil},
		{"spf uppercase", func(d *fakeDNS) { d.txt[apex] = []string{"V=SPF1 MX -ALL"} }, nil},
		{"spf multiple records", func(d *fakeDNS) {
			d.txt[apex] = []string{"v=spf1 mx -all", "v=spf1 a -all"}
		}, []string{CheckSPFMultiple}},
		{"spf unknown mechanism", func(d *fakeDNS) { d.txt[apex] = []string{"v=spf1 mx foo -all"} },
			[]string{CheckSPFInvalid}},
		{"spf include without domain", func(d *fakeDNS) { d.txt[apex] = []string{"v=spf1 include: -all"} },
			[]string{CheckSPFInvalid}},
		{"spf exactly 10 lookups", func(d *fakeDNS) {
			d.txt["_spf.example.net"] = []string{tooManyTerms}
		}, nil},
		{"spf 11 lookups", func(d *fakeDNS) {
			d.txt[apex] = []string{"v=spf1 a include:_spf.example.net -all"}
			d.txt["_spf.example.net"] = []string{tooManyTerms}
		}, []string{CheckSPFTooManyLookups}},
		{"spf include loop", func(d *fakeDNS) {
			d.txt[apex] = []string{"v=spf1 include:loop.example.net -all"}
			d.txt["loop.example.net"] = []string{"v=spf1 include:example.com -all"}
		}, []string{CheckSPFTooManyLookups}},
		{"spf macro include is not followed", func(d *fakeDNS) {
			d.txt[apex] = []string{"v=spf1 include:%{d}.spf.example.net -all"}
		}, nil},

		// DMARC.
		{"dmarc p=none", func(d *fakeDNS) {
			d.txt[dmarc] = []string{"v=DMARC1; p=none; rua=mailto:dmarc@example.com"}
		}, []string{CheckDMARCPolicyNone}},
		{"dmarc without rua", func(d *fakeDNS) { d.txt[dmarc] = []string{"v=DMARC1; p=reject"} },
			[]string{CheckDMARCNoReporting}},
		{"dmarc pct 50", func(d *fakeDNS) {
			d.txt[dmarc] = []string{"v=DMARC1; p=quarantine; pct=50; rua=mailto:dmarc@example.com"}
		}, []string{CheckDMARCPartialEnforcement}},
		{"dmarc sp=none", func(d *fakeDNS) {
			d.txt[dmarc] = []string{"v=DMARC1; p=reject; sp=none; rua=mailto:dmarc@example.com"}
		}, []string{CheckDMARCSubdomainNone}},
		{"dmarc without p", func(d *fakeDNS) {
			d.txt[dmarc] = []string{"v=DMARC1; rua=mailto:dmarc@example.com"}
		}, []string{CheckDMARCInvalid}},
		{"dmarc unknown p", func(d *fakeDNS) {
			d.txt[dmarc] = []string{"v=DMARC1; p=block; rua=mailto:dmarc@example.com"}
		}, []string{CheckDMARCInvalid}},
		{"dmarc multiple records", func(d *fakeDNS) {
			d.txt[dmarc] = []string{"v=DMARC1; p=reject", "v=DMARC1; p=none"}
		}, []string{CheckDMARCMultiple}},
		{"dmarc only unrelated txt", func(d *fakeDNS) { d.txt[dmarc] = []string{"hello"} },
			[]string{CheckDMARCMissing}},
		{"dmarc with spaces and case", func(d *fakeDNS) {
			d.txt[dmarc] = []string{" v = dmarc1 ; P = Reject ; rua = mailto:dmarc@example.com ;"}
		}, nil},

		// DKIM.
		{"dkim 1024-bit key", func(d *fakeDNS) {
			d.txt[dkim1] = []string{"v=DKIM1; k=rsa; p=" + rsaKey(t, 1024)}
		}, []string{CheckDKIMShortKey}},
		{"dkim 512-bit key", func(d *fakeDNS) {
			d.txt[dkim1] = []string{"v=DKIM1; k=rsa; p=" + rsaKey(t, 512)}
		}, []string{CheckDKIMWeakKey}},
		{"dkim key without k tag defaults to rsa", func(d *fakeDNS) {
			d.txt[dkim1] = []string{"v=DKIM1; p=" + rsaKey(t, 2048)}
		}, nil},
		{"dkim key split by whitespace", func(d *fakeDNS) {
			k := rsaKey(t, 2048)
			d.txt[dkim1] = []string{"v=DKIM1; k=rsa; p=" + k[:100] + " " + k[100:]}
		}, nil},
		{"dkim ed25519 key", func(d *fakeDNS) {
			d.txt[dkim1] = []string{"v=DKIM1; k=ed25519; p=" + ed25519Key(t)}
		}, nil},
		{"dkim unparsable key", func(d *fakeDNS) {
			d.txt[dkim1] = []string{"v=DKIM1; k=rsa; p=bm90IGEga2V5"}
		}, []string{CheckDKIMInvalidKey}},
		{"dkim only revoked key", func(d *fakeDNS) {
			d.txt[dkim1] = []string{"v=DKIM1; k=rsa; p="}
		}, []string{CheckDKIMNotFound}},
		{"dkim found on another selector", func(d *fakeDNS) {
			delete(d.txt, dkim1)
			d.txt["google._domainkey.example.com"] = []string{"v=DKIM1; p=" + rsaKey(t, 2048)}
		}, nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dns := goodDNS(t)
			tt.mutate(dns)
			findings, err := run(t, dns, "example.com")
			if err != nil {
				t.Fatalf("Run() error = %v", err)
			}
			if got := checkIDs(findings); !slices.Equal(got, tt.want) {
				t.Errorf("check IDs = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSeverityDependsOnMail(t *testing.T) {
	tests := []struct {
		name    string
		withMX  bool
		wantSev finding.Severity
		wantFix string // expected in the remediation
	}{
		{"domain that receives mail", true, finding.SeverityHigh, "include"},
		{"domain without mail", false, finding.SeverityMedium, "v=spf1 -all"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dns := goodDNS(t)
			delete(dns.txt, "example.com")
			if !tt.withMX {
				delete(dns.mx, "example.com")
			}
			findings, err := run(t, dns, "example.com")
			if err != nil {
				t.Fatalf("Run() error = %v", err)
			}
			i := slices.IndexFunc(findings, func(f finding.Finding) bool { return f.CheckID == CheckSPFMissing })
			if i < 0 {
				t.Fatalf("no %s finding in %v", CheckSPFMissing, checkIDs(findings))
			}
			f := findings[i]
			if f.Severity != tt.wantSev {
				t.Errorf("severity = %q, want %q", f.Severity, tt.wantSev)
			}
			if !strings.Contains(strings.Join(f.Remediation, " "), tt.wantFix) {
				t.Errorf("remediation %q does not mention %q", f.Remediation, tt.wantFix)
			}
		})
	}
}

func TestSPFPassAllIsCritical(t *testing.T) {
	dns := goodDNS(t)
	dns.txt["example.com"] = []string{"v=spf1 +all"}
	findings, err := run(t, dns, "example.com")
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if len(findings) != 1 || findings[0].Severity != finding.SeverityCritical {
		t.Fatalf("findings = %+v, want one critical finding", findings)
	}
	if !strings.Contains(findings[0].Evidence, "v=spf1 +all") {
		t.Errorf("evidence %q should contain the raw record", findings[0].Evidence)
	}
}

// A lookup that fails (timeout, SERVFAIL) must fail the run. Reporting
// "DMARC missing" because the DNS server timed out would be a false positive.
func TestTransientDNSErrorFailsRun(t *testing.T) {
	for _, name := range []string{"example.com", "_dmarc.example.com", "_spf.example.net", "google._domainkey.example.com"} {
		t.Run(name, func(t *testing.T) {
			dns := goodDNS(t)
			timeout := &net.DNSError{Err: "i/o timeout", Name: name, IsTimeout: true}
			dns.fail = map[string]error{name: timeout}
			findings, err := run(t, dns, "example.com")
			if !errors.Is(err, timeout) {
				t.Errorf("Run() error = %v, want the DNS timeout", err)
			}
			if findings != nil {
				t.Errorf("Run() returned findings %v with an error", checkIDs(findings))
			}
		})
	}
}

func TestEveryLookupGoesThroughGate(t *testing.T) {
	dns := goodDNS(t)
	gate := &countingGate{}
	_, err := New(dns).Run(context.Background(), module.Request{
		Target: module.Target{Domain: "example.com"},
		Gate:   gate,
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if len(dns.calls) == 0 {
		t.Fatal("no DNS lookups were made")
	}
	if gate.calls != len(dns.calls) {
		t.Errorf("gate saw %d requests but DNS saw %d lookups", gate.calls, len(dns.calls))
	}
}

func TestGateRefusalStopsRun(t *testing.T) {
	dns := goodDNS(t)
	errExcluded := errors.New("excluded")
	_, err := New(dns).Run(context.Background(), module.Request{
		Target: module.Target{Domain: "example.com"},
		Gate:   &countingGate{deny: errExcluded},
	})
	if !errors.Is(err, errExcluded) {
		t.Errorf("Run() error = %v, want the gate refusal", err)
	}
	if len(dns.calls) != 0 {
		t.Errorf("DNS saw %d lookups after the gate refused", len(dns.calls))
	}
}

func TestRunWithoutGateFails(t *testing.T) {
	dns := goodDNS(t)
	_, err := New(dns).Run(context.Background(), module.Request{
		Target: module.Target{Domain: "example.com"},
	})
	if !errors.Is(err, resolver.ErrNoGate) {
		t.Errorf("Run() error = %v, want ErrNoGate", err)
	}
}

func TestCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	dns := goodDNS(t)
	_, err := New(dns).Run(ctx, module.Request{
		Target: module.Target{Domain: "example.com"},
		Gate:   &countingGate{},
	})
	if !errors.Is(err, context.Canceled) {
		t.Errorf("Run() error = %v, want context.Canceled", err)
	}
}

// Every finding the module produces must pass the schema validation once the
// engine has stamped the history fields.
func TestFindingsAreValid(t *testing.T) {
	dns := goodDNS(t)
	delete(dns.txt, "_dmarc.example.com")
	delete(dns.txt, "selector1._domainkey.example.com")
	dns.txt["example.com"] = []string{"v=spf1 +all"}
	findings, err := run(t, dns, "example.com")
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected findings")
	}
	now := time.Now()
	for _, f := range findings {
		f.FirstSeen, f.LastSeen, f.Status = now, now, finding.StatusOpen
		if err := f.Validate(); err != nil {
			t.Errorf("finding %s is invalid: %v", f.CheckID, err)
		}
		if f.ModuleID != ID || f.Target != "example.com" {
			t.Errorf("finding %s: module %q, target %q", f.CheckID, f.ModuleID, f.Target)
		}
	}
}

// Missing DMARC reporting matters for a domain that handles mail; for one
// without mail it is only information.
func TestNoReportingSeverityDependsOnMail(t *testing.T) {
	tests := []struct {
		name   string
		withMX bool
		want   finding.Severity
	}{
		{"domain with mail", true, finding.SeverityLow},
		{"domain without mail", false, finding.SeverityInfo},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dns := goodDNS(t)
			dns.txt["_dmarc.example.com"] = []string{"v=DMARC1; p=reject"}
			if !tt.withMX {
				delete(dns.mx, "example.com")
			}
			findings, err := run(t, dns, "example.com")
			if err != nil {
				t.Fatalf("Run() error = %v", err)
			}
			i := slices.IndexFunc(findings, func(f finding.Finding) bool { return f.CheckID == CheckDMARCNoReporting })
			if i < 0 {
				t.Fatalf("no %s finding in %v", CheckDMARCNoReporting, checkIDs(findings))
			}
			if findings[i].Severity != tt.want {
				t.Errorf("severity = %s, want %s", findings[i].Severity, tt.want)
			}
		})
	}
}

func TestCatalogRegisters(t *testing.T) {
	if err := module.NewRegistry().Register(New(&fakeDNS{})); err != nil {
		t.Fatalf("Register: %v", err)
	}
}

func TestEvaluatedChecks(t *testing.T) {
	t.Run("well configured: everything passes", func(t *testing.T) {
		for id, st := range statuses(t, goodDNS(t)) {
			if st != module.CheckPassed {
				t.Errorf("%s = %s, want passed", id, st)
			}
		}
	})

	t.Run("no DMARC: policy checks are not applicable", func(t *testing.T) {
		dns := goodDNS(t)
		delete(dns.txt, "_dmarc.example.com")
		got := statuses(t, dns)
		want := map[string]module.CheckStatus{
			CheckDMARCMissing:            module.CheckFailed,
			CheckDMARCMultiple:           module.CheckNotApplicable,
			CheckDMARCPolicyNone:         module.CheckNotApplicable,
			CheckDMARCPartialEnforcement: module.CheckNotApplicable,
			CheckDMARCNoReporting:        module.CheckNotApplicable,
			CheckSPFPassAll:              module.CheckPassed,
		}
		for id, st := range want {
			if got[id] != st {
				t.Errorf("%s = %s, want %s", id, got[id], st)
			}
		}
	})

	t.Run("p=none: enforcement details are not applicable", func(t *testing.T) {
		dns := goodDNS(t)
		dns.txt["_dmarc.example.com"] = []string{"v=DMARC1; p=none; rua=mailto:d@example.com"}
		got := statuses(t, dns)
		if got[CheckDMARCPolicyNone] != module.CheckFailed || got[CheckDMARCPartialEnforcement] != module.CheckNotApplicable {
			t.Errorf("policy none = %s, partial = %s", got[CheckDMARCPolicyNone], got[CheckDMARCPartialEnforcement])
		}
	})

	t.Run("SPF redirect without all: the all checks are not applicable", func(t *testing.T) {
		dns := goodDNS(t)
		dns.txt["example.com"] = []string{"v=spf1 redirect=_spf.example.net"}
		got := statuses(t, dns)
		if got[CheckSPFNoAll] != module.CheckNotApplicable || got[CheckSPFMissing] != module.CheckPassed {
			t.Errorf("no-all = %s, missing = %s", got[CheckSPFNoAll], got[CheckSPFMissing])
		}
	})

	t.Run("no mail and no DKIM: DKIM checks are not applicable", func(t *testing.T) {
		dns := goodDNS(t)
		delete(dns.mx, "example.com")
		delete(dns.txt, "selector1._domainkey.example.com")
		got := statuses(t, dns)
		for _, id := range []string{CheckDKIMNotFound, CheckDKIMWeakKey} {
			if got[id] != module.CheckNotApplicable {
				t.Errorf("%s = %s, want not_applicable", id, got[id])
			}
		}
	})
}
