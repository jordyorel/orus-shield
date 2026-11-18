// Package quicktest is the public domain test of the home page: anyone may
// test any domain, without an account, to see its score before signing up.
//
// It is the one place where the engine looks at a domain nobody proved to
// own, so it is deliberately small (decided 2026-11-18):
//
//   - passive checks only, on public data: email (SPF, DMARC...), the TLS
//     certificate and the HTTPS headers, on the name and its www only. No
//     subdomain discovery, no ports, no vulnerabilities: those would turn
//     it into a reconnaissance tool. Everything else still needs an account
//     and a verified domain (security rule 1).
//   - every connection goes through Gate: public addresses only (a name
//     pointing at 127.0.0.1 or 10.x must not make our server talk to our
//     own network: server-side request forgery), and a rate limit.
//   - a short time budget, and the caller (package api) bounds how often
//     and how many run.
//
// It runs in the API process, outside the scan queue: nothing is stored as
// findings, assets or history, and it belongs to no organization.
package quicktest

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/jordyorel/orus-shield/engine/internal/dnsname"
	"github.com/jordyorel/orus-shield/engine/internal/finding"
	"github.com/jordyorel/orus-shield/engine/internal/gate"
	"github.com/jordyorel/orus-shield/engine/internal/module"
	"github.com/jordyorel/orus-shield/engine/internal/posture"
)

const (
	// Budget bounds one test: the visitor waits for it.
	Budget = 20 * time.Second
	// Rate is the requests per second one test may send.
	Rate = 5
)

// ErrInvalidDomain is a name the test refuses: not a plausible public
// domain.
var ErrInvalidDomain = errors.New("not a public domain name")

// localSuffixes are names that never resolve on the internet.
var localSuffixes = []string{".local", ".localhost", ".internal", ".lan", ".home", ".home.arpa", ".corp", ".intranet", ".onion", ".invalid", ".test", ".example"}

// NormalizeDomain checks a visitor's domain: a DNS name with at least two
// labels, a top-level label that is not a number (an IP address written
// as a name) and no local suffix.
func NormalizeDomain(raw string) (string, error) {
	d, err := dnsname.Normalize(raw)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrInvalidDomain, err)
	}
	labels := strings.Split(d, ".")
	tld := labels[len(labels)-1]
	if len(labels) < 2 || strings.Trim(tld, "0123456789") == "" || d == "localhost" {
		return "", ErrInvalidDomain
	}
	for _, s := range localSuffixes {
		if strings.HasSuffix("."+d, s) {
			return "", ErrInvalidDomain
		}
	}
	return d, nil
}

// Gate is the module.Gate of a public test: it refuses every address that
// is not public, then waits on the rate limiter. A refused address is an
// exclusion for the modules (module.ErrExcluded): they skip it and carry
// on, and its name is reported as unreached.
type Gate struct{ limiter *gate.Limiter }

// NewGate returns a gate limiting requests to ratePerSec.
func NewGate(ratePerSec float64) (*Gate, error) {
	l, err := gate.NewLimiter(ratePerSec)
	if err != nil {
		return nil, fmt.Errorf("quick test gate: %w", err)
	}
	return &Gate{limiter: l}, nil
}

// Allow implements module.Gate.
func (g *Gate) Allow(ctx context.Context, dest module.Destination) error {
	if dest.IP.IsValid() && !Public(dest.IP) {
		return fmt.Errorf("address %s is not public: %w", dest.IP, module.ErrExcluded)
	}
	if err := g.limiter.Wait(ctx); err != nil {
		return fmt.Errorf("%w: %w", gate.ErrRateLimitWait, err)
	}
	return nil
}

// nonPublic are the special-purpose ranges that netip's own predicates
// (private, loopback, link-local, multicast) do not cover.
var nonPublic = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),       // "this network"
	netip.MustParsePrefix("100.64.0.0/10"),   // carrier-grade NAT
	netip.MustParsePrefix("192.0.0.0/24"),    // IETF protocol assignments
	netip.MustParsePrefix("192.0.2.0/24"),    // documentation
	netip.MustParsePrefix("198.18.0.0/15"),   // benchmarking
	netip.MustParsePrefix("198.51.100.0/24"), // documentation
	netip.MustParsePrefix("203.0.113.0/24"),  // documentation
	netip.MustParsePrefix("240.0.0.0/4"),     // reserved, and broadcast
	netip.MustParsePrefix("64:ff9b::/96"),    // NAT64: may embed a private IPv4
	netip.MustParsePrefix("64:ff9b:1::/48"),  // local-use NAT64
	netip.MustParsePrefix("2001:db8::/32"),   // documentation
	netip.MustParsePrefix("2002::/16"),       // 6to4: may embed a private IPv4
	netip.MustParsePrefix("100::/64"),        // discard-only
}

// Public reports whether ip is an ordinary internet address. IPv4-mapped
// IPv6 addresses are judged as the IPv4 they carry.
func Public(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsMulticast() {
		return false
	}
	for _, p := range nonPublic {
		if p.Contains(ip) {
			return false
		}
	}
	return true
}

// Check is one catalog check with its outcome.
type Check struct {
	ID       string           `json:"id"`
	Category module.Category  `json:"category"`
	Severity finding.Severity `json:"severity"`
	Title    string           `json:"title"`
	TitleFR  string           `json:"title_fr"`
	Status   string           `json:"status"` // passed, failed
}

// Report is what a test found. Findings carry their explanations and
// steps; the API shows them only once the visitor left an email.
type Report struct {
	Domain   string            `json:"domain"`
	Score    *int              `json:"score"`
	Checks   []Check           `json:"checks"`
	Findings []finding.Finding `json:"findings"`
	// Unreached: names the test could not check (no public address).
	Unreached []string  `json:"unreached"`
	At        time.Time `json:"at"`
}

// Run tests domain with modules, which must all be passive, within
// Budget. A module that fails is left out (its checks count as not
// applicable): a visitor gets what could be checked. Only when nothing at
// all could be checked is it an error.
func Run(ctx context.Context, modules []module.Module, domain string, now time.Time) (Report, error) {
	d, err := NormalizeDomain(domain)
	if err != nil {
		return Report{}, err
	}
	for _, m := range modules {
		if m.Info().Kind != module.KindPassive {
			return Report{}, fmt.Errorf("quick test: module %s is not passive", m.Info().ID)
		}
	}
	g, err := NewGate(Rate)
	if err != nil {
		return Report{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, Budget)
	defer cancel()

	target := module.Target{Domain: d, Hosts: []string{d, "www." + d}}
	rep := Report{Domain: d, Checks: []Check{}, Findings: []finding.Finding{}, Unreached: []string{}, At: now.UTC()}
	var scored []posture.Check
	ran := 0
	for _, m := range modules {
		res, err := m.Run(ctx, module.Request{Target: target, Gate: g})
		if err != nil {
			continue
		}
		outcomes, err := module.Evaluate(m.Info(), res)
		if err != nil {
			continue
		}
		ran++
		rep.Findings = append(rep.Findings, res.Findings...)
		rep.Unreached = append(rep.Unreached, res.Unreached...)
		for _, o := range outcomes {
			if o.Status == module.CheckNotApplicable {
				continue
			}
			rep.Checks = append(rep.Checks, Check{ID: o.ID, Category: o.Category, Severity: o.Severity, Title: o.Title, TitleFR: o.TitleFR, Status: string(o.Status)})
			scored = append(scored, posture.Check{ID: o.ID, Category: o.Category, Severity: o.Severity, Status: o.Status})
		}
	}
	if ran == 0 {
		if ctx.Err() != nil {
			return Report{}, fmt.Errorf("quick test of %s: %w", d, ctx.Err())
		}
		return Report{}, fmt.Errorf("quick test of %s: no check could run", d)
	}
	rep.Score = posture.Compute(scored).Score
	return rep, nil
}
