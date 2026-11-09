// Package email checks how well a domain is protected against email spoofing:
// SPF, DMARC and DKIM. It is passive: it only reads public DNS records.
//
// All lookups go through a resolver.Gated built from the request's Gate, so
// exclusions and rate limits apply to every query.
package email

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jordyorel/orus-shield/engine/internal/finding"
	"github.com/jordyorel/orus-shield/engine/internal/module"
	"github.com/jordyorel/orus-shield/engine/internal/resolver"
)

// ID is the stable module ID. Never change it: finding IDs depend on it.
const ID = "email"

// Check IDs. They are stable: reports use them to show localized text.
const (
	CheckSPFMissing        = "spf-missing"
	CheckSPFMultiple       = "spf-multiple"
	CheckSPFInvalid        = "spf-invalid"
	CheckSPFPassAll        = "spf-pass-all"
	CheckSPFNeutralAll     = "spf-neutral-all"
	CheckSPFSoftfailAll    = "spf-softfail-all"
	CheckSPFNoAll          = "spf-no-all"
	CheckSPFTooManyLookups = "spf-too-many-lookups"

	CheckDMARCMissing            = "dmarc-missing"
	CheckDMARCMultiple           = "dmarc-multiple"
	CheckDMARCInvalid            = "dmarc-invalid"
	CheckDMARCPolicyNone         = "dmarc-policy-none"
	CheckDMARCPartialEnforcement = "dmarc-partial-enforcement"
	CheckDMARCSubdomainNone      = "dmarc-subdomain-none"
	CheckDMARCNoReporting        = "dmarc-no-reporting"

	CheckDKIMNotFound   = "dkim-not-found"
	CheckDKIMWeakKey    = "dkim-weak-key"
	CheckDKIMShortKey   = "dkim-short-key"
	CheckDKIMInvalidKey = "dkim-invalid-key"
)

// Module is the email security check.
type Module struct {
	dns resolver.Resolver
}

// New returns the email module. dns is the underlying resolver (normally
// resolver.NewSystem()); the module wraps it with the request's Gate on
// every run, so it cannot be used to bypass exclusions or rate limits.
func New(dns resolver.Resolver) *Module {
	return &Module{dns: dns}
}

// Info implements module.Module.
func (m *Module) Info() module.Info {
	return module.Info{ID: ID, Name: "Email security (SPF, DKIM, DMARC)", Kind: module.KindPassive}
}

// Run implements module.Module. It has no configuration yet; req.Config is
// ignored. It reports no assets: the DNS records it reads (SPF, DMARC, DKIM
// TXT records, MX hosts often run by a mail provider) are configuration,
// not exposed systems.
//
// Any DNS failure other than "not found" (timeout, SERVFAIL, gate refusal)
// fails the whole run: reporting "no DMARC record" because a server timed out
// would be a false positive, and false positives destroy customer trust.
func (m *Module) Run(ctx context.Context, req module.Request) (module.Result, error) {
	domain, err := module.NormalizeDomain(req.Target.Domain)
	if err != nil {
		return module.Result{}, fmt.Errorf("email: %w", err)
	}
	dns := resolver.Gated{Gate: req.Gate, Inner: m.dns}

	receivesMail, err := receivesMail(ctx, dns, domain)
	if err != nil {
		return module.Result{}, fmt.Errorf("email: %w", err)
	}

	checks := []func(context.Context, resolver.Resolver, string, bool) ([]issue, error){
		checkSPF, checkDMARC, checkDKIM,
	}
	var findings []finding.Finding
	for _, check := range checks {
		issues, err := check(ctx, dns, domain, receivesMail)
		if err != nil {
			return module.Result{}, fmt.Errorf("email: %w", err)
		}
		for _, i := range issues {
			findings = append(findings, i.finding(domain))
		}
	}
	return module.Result{Findings: findings}, nil
}

// receivesMail reports whether domain has at least one usable MX record.
// A "null MX" (a single "." host, RFC 7505) explicitly says "no mail here".
//
// We use it to tailor advice: a domain that handles no mail should publish
// "v=spf1 -all" and "p=reject" so nobody can send in its name.
func receivesMail(ctx context.Context, dns resolver.Resolver, domain string) (bool, error) {
	records, err := dns.LookupMX(ctx, domain)
	if errors.Is(err, resolver.ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	for _, mx := range records {
		if mx.Host != "." && mx.Host != "" {
			return true, nil
		}
	}
	return false, nil
}

// lookupTXT returns the TXT records of name, or nil if the name does not
// exist. Other errors are returned as is.
func lookupTXT(ctx context.Context, dns resolver.Resolver, name string) ([]string, error) {
	records, err := dns.LookupTXT(ctx, name)
	if errors.Is(err, resolver.ErrNotFound) {
		return nil, nil
	}
	return records, err
}

// issue is what a check detects. It becomes a finding once the target is
// known; FirstSeen, LastSeen and Status are set later by the engine.
type issue struct {
	checkID     string
	asset       string
	severity    finding.Severity
	title       string
	description string
	evidence    string
	remediation []string
	references  []string
}

func (i issue) finding(target string) finding.Finding {
	return finding.Finding{
		SchemaVersion: finding.SchemaVersion,
		ID:            finding.NewID(ID, i.checkID, target, i.asset),
		ModuleID:      ID,
		CheckID:       i.checkID,
		Target:        target,
		Asset:         i.asset,
		Severity:      i.severity,
		Title:         i.title,
		Description:   i.description,
		Evidence:      finding.TruncateEvidence(i.evidence),
		Remediation:   i.remediation,
		References:    i.references,
	}
}

// parseTags parses "name=value; name=value" lists, the syntax shared by
// DMARC and DKIM records. Names are lowercased; values are trimmed but keep
// their case. Entries without "=" are ignored.
func parseTags(record string) []tag {
	var tags []tag
	for _, part := range strings.Split(record, ";") {
		name, value, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		tags = append(tags, tag{
			name:  strings.ToLower(strings.TrimSpace(name)),
			value: strings.TrimSpace(value),
		})
	}
	return tags
}

type tag struct{ name, value string }

// tagMap indexes tags by name. If a name repeats, the first one wins.
func tagMap(tags []tag) map[string]string {
	m := make(map[string]string, len(tags))
	for _, t := range tags {
		if _, seen := m[t.name]; !seen {
			m[t.name] = t.value
		}
	}
	return m
}
