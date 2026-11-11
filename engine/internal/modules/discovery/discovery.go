// Package discovery finds the subdomains of a target, so that every other
// module scans them too, not only the domain and www.
//
// It is passive and uses two public sources:
//   - Certificate Transparency: every certificate a public authority issues
//     is published in CT logs, with the names it covers. A certificate for
//     vpn.example.com means vpn.example.com existed at some point. The logs
//     are read through a CT search service (crt.sh by default), never
//     through the customer's servers.
//   - A short list of common names (mail, vpn, extranet...) looked up in
//     DNS, through the scan's gate like any other request.
//
// Only names that resolve today are reported: CT keeps names of servers
// shut down years ago. A wildcard DNS record (*.example.com) would make
// every guessed name resolve; guesses that only hit the wildcard are
// dropped.
//
// The module produces no findings. It reports hostname assets; the worker
// gives them to the modules that run after it (module.Info.ProvidesHosts).
package discovery

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"github.com/jordyorel/orus-shield/engine/internal/asset"
	"github.com/jordyorel/orus-shield/engine/internal/module"
	"github.com/jordyorel/orus-shield/engine/internal/resolver"
)

// ID is the stable module ID.
const ID = "discovery"

// DetailSource is the asset detail saying how a name was found: "ct",
// "dns" or "ct,dns".
const DetailSource = "discovered_by"

// maxResolve bounds the candidate names looked up in DNS per run. Each
// lookup goes through the rate limiter: at 5 requests per second, 120
// names take under half a minute.
const maxResolve = 120

// commonNames are the guesses looked up in DNS. Kept short on purpose:
// this is not a brute force, it catches the usual suspects of a small
// company that CT may miss (servers without a public certificate).
var commonNames = []string{
	"admin", "api", "app", "autodiscover", "backup", "blog", "cloud", "crm", "db", "dev",
	"erp", "extranet", "files", "ftp", "git", "gitlab", "grafana", "helpdesk", "imap", "intranet",
	"jenkins", "login", "m", "mail", "mx", "nas", "owa", "portal", "remote", "rdp",
	"shop", "smtp", "sso", "staging", "support", "test", "vpn", "webmail",
}

// CTSource lists the names Certificate Transparency logs hold for a
// domain and its subdomains. Names may be wildcards ("*.example.com"),
// outside the domain or malformed: the module filters them.
type CTSource interface {
	Names(ctx context.Context, domain string) ([]string, error)
}

// Module is the discovery module.
type Module struct {
	dns resolver.Resolver
	ct  CTSource
}

// New returns the module. dns is the underlying resolver (wrapped with the
// request's gate on every run); ct is the Certificate Transparency source.
func New(dns resolver.Resolver, ct CTSource) *Module {
	return &Module{dns: dns, ct: ct}
}

// Info implements module.Module.
func (m *Module) Info() module.Info {
	return module.Info{ID: ID, Name: "Attack surface discovery", Kind: module.KindPassive, ProvidesHosts: true}
}

// Run implements module.Module.
//
// If the CT source fails, the run fails: reporting only the DNS guesses
// would make the inventory forget every name found through CT. The other
// modules then keep scanning the names already in the inventory.
func (m *Module) Run(ctx context.Context, req module.Request) (module.Result, error) {
	domain, err := module.NormalizeDomain(req.Target.Domain)
	if err != nil {
		return module.Result{}, fmt.Errorf("discovery: %w", err)
	}
	dns := resolver.Gated{Gate: req.Gate, Inner: m.dns}

	fromCT, err := m.ct.Names(ctx, domain)
	if err != nil {
		return module.Result{}, fmt.Errorf("discovery: certificate transparency: %w", err)
	}

	sources := make(map[string][]string) // name -> how it was found
	for _, n := range fromCT {
		if name, ok := subdomain(n, domain); ok {
			sources[name] = appendOnce(sources[name], "ct")
		}
	}
	for _, label := range commonNames {
		name := label + "." + domain
		sources[name] = appendOnce(sources[name], "dns")
	}

	wildcard, err := wildcardIPs(ctx, dns, domain)
	if err != nil {
		return module.Result{}, fmt.Errorf("discovery: %w", err)
	}

	var assets asset.Set
	for _, name := range candidates(sources, domain) {
		ips, err := dns.LookupIP(ctx, name)
		switch {
		case errors.Is(err, resolver.ErrNotFound), errors.Is(err, module.ErrExcluded):
			continue // gone, never existed, or excluded by the customer
		case err != nil:
			return module.Result{}, fmt.Errorf("discovery: %w", err)
		}
		src := sources[name]
		// A guess that only lands on the wildcard is not a real server.
		if !slices.Contains(src, "ct") && len(wildcard) > 0 && allIn(ips, wildcard) {
			continue
		}
		a := asset.Hostname(name)
		a.Details = map[string]string{DetailSource: strings.Join(src, ",")}
		assets.Add(a)
	}
	return module.Result{Assets: assets.List()}, nil
}

// subdomain normalizes a CT name and keeps it if it is a subdomain of
// domain. "*.example.com" becomes "example.com" itself, which is dropped:
// the domain and www. are always scanned.
func subdomain(raw, domain string) (string, bool) {
	raw = strings.TrimPrefix(strings.TrimSpace(raw), "*.")
	name, err := module.NormalizeDomain(raw)
	if err != nil || name == domain || name == "www."+domain || !strings.HasSuffix(name, "."+domain) {
		return "", false
	}
	return name, true
}

// candidates orders the names to look up: found in CT first (they are
// facts), then guesses, alphabetically within each group, at most
// maxResolve.
func candidates(sources map[string][]string, domain string) []string {
	var ct, guesses []string
	for name, src := range sources {
		if name == domain || name == "www."+domain {
			continue
		}
		if slices.Contains(src, "ct") {
			ct = append(ct, name)
		} else {
			guesses = append(guesses, name)
		}
	}
	slices.Sort(ct)
	slices.Sort(guesses)
	out := append(ct, guesses...)
	if len(out) > maxResolve {
		out = out[:maxResolve]
	}
	return out
}

// wildcardIPs resolves a random name under domain. If it resolves, the
// domain has a wildcard record and these are its addresses.
func wildcardIPs(ctx context.Context, dns resolver.Gated, domain string) ([]netip.Addr, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("random label: %w", err)
	}
	ips, err := dns.LookupIP(ctx, "orus-"+hex.EncodeToString(b)+"."+domain)
	if errors.Is(err, resolver.ErrNotFound) || errors.Is(err, module.ErrExcluded) {
		return nil, nil
	}
	return ips, err
}

func allIn(ips, set []netip.Addr) bool {
	for _, ip := range ips {
		if !slices.Contains(set, ip.Unmap()) && !slices.Contains(set, ip) {
			return false
		}
	}
	return true
}

func appendOnce(list []string, v string) []string {
	if slices.Contains(list, v) {
		return list
	}
	return append(list, v)
}
