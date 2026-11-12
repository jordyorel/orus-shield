// Package vulns finds known vulnerabilities (CVEs), exposed sensitive files,
// exposed administration panels, subdomain takeovers and server
// misconfigurations, with Nuclei and its community templates.
//
// Nuclei is an external program (MIT), pinned and installed next to the
// worker (ORUS_NUCLEI_BIN, ORUS_NUCLEI_TEMPLATES). It is not imported as a
// library: that would add hundreds of dependencies to the engine. What makes
// it safe to run is how it is started:
//
//   - its only way out is a gateproxy.Proxy for this scan: every request goes
//     through the scan's gate (exclusions, rate limit, per-IP ownership), one
//     gate call per request, with its path;
//   - only HTTP templates run (-type http), never code, file, headless,
//     JavaScript or raw network ones, and templates tagged as intrusive, DoS,
//     brute force, default logins or fuzzing are excluded;
//   - no out-of-band interaction server (-no-interactsh), no update check, no
//     environment variables in templates, a throwaway HOME;
//   - it is active: verified targets only (rule 1).
//
// Production must also run it without direct network access (a network
// namespace or container whose only route is the proxy): the flags make it
// use the proxy, the sandbox makes sure it cannot do otherwise.
//
// Its JSON output is converted to the standard finding schema; nothing
// downstream knows about Nuclei.
package vulns

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jordyorel/orus-shield/engine/internal/asset"
	"github.com/jordyorel/orus-shield/engine/internal/dialer"
	"github.com/jordyorel/orus-shield/engine/internal/dnsname"
	"github.com/jordyorel/orus-shield/engine/internal/finding"
	"github.com/jordyorel/orus-shield/engine/internal/gateproxy"
	"github.com/jordyorel/orus-shield/engine/internal/module"
	"github.com/jordyorel/orus-shield/engine/internal/resolver"
)

// ID is the stable module ID. Never change it: finding IDs depend on it.
const ID = "vulns"

// Check IDs. They are stable: reports use them to show localized text.
const (
	CheckKnownCVE      = "vuln-known-cve"
	CheckExposedData   = "vuln-exposed-data"
	CheckTakeover      = "vuln-subdomain-takeover"
	CheckMisconfig     = "vuln-misconfiguration"
	CheckExposedPanel  = "vuln-exposed-panel"
	CheckOutdatedOrEOL = "vuln-outdated-software"
)

// Checks is the module's catalog. A finding's severity is the template's;
// the catalog severity is the check's weight in the posture score.
var Checks = []module.Check{
	{ID: CheckKnownCVE, Category: module.CategoryWeb, Severity: finding.SeverityCritical, Title: "No software with a known vulnerability (CVE) is exposed"},
	{ID: CheckExposedData, Category: module.CategoryWeb, Severity: finding.SeverityHigh, Title: "No sensitive file or data is publicly reachable"},
	{ID: CheckTakeover, Category: module.CategoryDNS, Severity: finding.SeverityHigh, Title: "Subdomains cannot be taken over"},
	{ID: CheckMisconfig, Category: module.CategoryWeb, Severity: finding.SeverityMedium, Title: "No known server misconfiguration"},
	{ID: CheckExposedPanel, Category: module.CategoryWeb, Severity: finding.SeverityLow, Title: "Administration interfaces are not exposed to the internet"},
	{ID: CheckOutdatedOrEOL, Category: module.CategoryWeb, Severity: finding.SeverityMedium, Title: "No end-of-life software is exposed"},
}

const (
	// Timeout bounds one run (Info.Timeout). At the default rate of 5
	// requests per second, one site takes about 20 minutes (some 5000
	// requests over both passes).
	Timeout = 2 * time.Hour
	// maxURLs bounds the sites (name and scheme) one run scans.
	maxURLs       = 8
	maxIPsPerHost = 4
	probeTimeout  = 5 * time.Second
	// maxResults bounds what we read from Nuclei (rule 7: its output
	// carries data extracted from the target).
	maxResults = 2000
	// maxTechsPerHost bounds the technologies listed on one host.
	maxTechsPerHost = 20
	// userAgent is sent instead of Nuclei's browser-like default, so the
	// customer's logs say who is scanning.
	userAgent = "OrusShield/1 (+security check of a site you registered)"
)

// excludedTags are templates we never run, whatever their tags say
// otherwise: they change state, try passwords, flood, or fuzz inputs.
var excludedTags = []string{
	"intrusive", "dos", "fuzz", "fuzzing", "dast", "bruteforce", "brute-force",
	"default-login", "token-spray", "credential-stuffing", "headless", "osint", "oast",
}

// Config is where Nuclei and its templates are installed.
type Config struct {
	Binary    string // path to the pinned nuclei binary
	Templates string // path to the pinned nuclei-templates directory
	// WorkDir holds the per-run temporary files; empty: the system's.
	WorkDir string
}

// ErrNotInstalled is returned when Nuclei is not configured on this worker.
var ErrNotInstalled = errors.New("nuclei is not installed on this worker (ORUS_NUCLEI_BIN, ORUS_NUCLEI_TEMPLATES)")

// Module is the known-vulnerabilities check.
type Module struct {
	cfg    Config
	dns    resolver.Resolver
	dial   dialer.Dialer
	runner Runner
	// urls gives the candidate URLs of a host; tests point it at local
	// servers on random ports.
	urls func(host string) []string
}

// defaultURLs scans both schemes: a site may answer on one only, and
// HTTP-only findings (cleartext login panels) matter.
func defaultURLs(host string) []string { return []string{"https://" + host, "http://" + host} }

// New returns the module. dns and dial are the underlying resolver and
// dialer the proxy wraps with each scan's gate.
func New(dns resolver.Resolver, dial dialer.Dialer, cfg Config) *Module {
	return &Module{cfg: cfg, dns: dns, dial: dial, runner: Exec{}, urls: defaultURLs}
}

// Info implements module.Module.
func (m *Module) Info() module.Info {
	return module.Info{ID: ID, Name: "Known vulnerabilities", Kind: module.KindActive, Checks: Checks, Timeout: Timeout}
}

// Run implements module.Module.
//
// It first finds which of the scan's names answer on 443 and 80 (one gated
// TCP connection each), then runs Nuclei on those URLs in two passes:
//
//  1. "detect": Nuclei's automatic scan identifies the technologies of each
//     site and runs only the templates for them (CVEs, panels, end-of-life
//     versions of what the site really runs);
//  2. "generic": exposed files, misconfigurations and subdomain takeovers,
//     medium severity and above, whatever the technology.
//
// Every catalog check is evaluated once a request reached the target: "no
// template matched" is then a pass. When nothing answered (names excluded,
// unverified or silent), nothing is evaluated. A run cut short (timeout,
// cancellation) is an error, never a partial pass: it would mark findings
// fixed that were simply not checked again.
func (m *Module) Run(ctx context.Context, req module.Request) (module.Result, error) {
	if m.cfg.Binary == "" || m.cfg.Templates == "" {
		return module.Result{}, ErrNotInstalled
	}
	domain, err := module.NormalizeDomain(req.Target.Domain)
	if err != nil {
		return module.Result{}, fmt.Errorf("vulns: %w", err)
	}
	// Defense in depth: the worker checks this too (module.CheckAllowed).
	if !req.Target.Verified {
		return module.Result{}, fmt.Errorf("vulns on %s: %w", domain, module.ErrNotVerified)
	}

	urls, unreached, err := m.reachable(ctx, req.Gate, req.Target.ScanHosts(domain))
	if err != nil {
		return module.Result{}, fmt.Errorf("vulns: %w", err)
	}
	if len(urls) == 0 {
		return module.Result{Unreached: unreached}, nil
	}

	proxy, err := gateproxy.Start(ctx, gateproxy.Config{Domain: domain, Gate: req.Gate, DNS: m.dns, Dial: m.dial})
	if err != nil {
		return module.Result{}, fmt.Errorf("vulns: %w", err)
	}
	defer func() { _ = proxy.Close() }()

	dir, err := os.MkdirTemp(m.cfg.WorkDir, "orus-vulns-")
	if err != nil {
		return module.Result{}, fmt.Errorf("vulns: work dir: %w", err)
	}
	defer func() { _ = os.RemoveAll(dir) }()
	if err := writeInputs(dir, urls, proxy.URL()); err != nil {
		return module.Result{}, fmt.Errorf("vulns: %w", err)
	}

	parse := parser{domain: domain}
	for _, p := range m.passes() {
		if err := m.runner.Run(ctx, m.cfg.Binary, append(p.args, commonArgs(dir)...), dir, &parse); err != nil {
			if ctx.Err() != nil {
				return module.Result{}, fmt.Errorf("vulns: %s pass: %w", p.name, ctx.Err())
			}
			return module.Result{}, fmt.Errorf("vulns: %s pass: nuclei: %w", p.name, err)
		}
	}
	_ = proxy.Close() // wait for the last requests before reading the counters
	if err := proxy.Err(); err != nil {
		return module.Result{}, fmt.Errorf("vulns: scan stopped: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return module.Result{}, fmt.Errorf("vulns: %w", err)
	}
	if parse.err != nil {
		return module.Result{}, fmt.Errorf("vulns: read nuclei output: %w", parse.err)
	}

	res := convert(domain, parse.results)
	res.Unreached = append(unreached, proxy.Unreached()...)
	if proxy.Stats().Answered > 0 {
		for _, c := range Checks {
			res.Evaluated = append(res.Evaluated, c.ID)
		}
	}
	return res, nil
}

// convert turns Nuclei results into findings, and technology detections
// into hostname details.
func convert(domain string, results []result) module.Result {
	var res module.Result
	var assets asset.Set
	seen := map[string]int{}
	techs := map[string][]string{} // host -> technology labels, in order
	for _, r := range results {
		if t, host, ok := r.technology(domain); ok {
			if !slices.Contains(techs[host], t.label) && len(techs[host]) < maxTechsPerHost {
				techs[host] = append(techs[host], t.label)
			}
			continue
		}
		f, ok := r.finding(domain)
		if !ok {
			continue
		}
		// Several matchers of one template on one URL: keep one finding,
		// the most severe.
		if i, dup := seen[f.ID]; dup {
			if f.Severity.Rank() > res.Findings[i].Severity.Rank() {
				res.Findings[i] = f
			}
			continue
		}
		seen[f.ID] = len(res.Findings)
		res.Findings = append(res.Findings, f)
		if n, err := dnsname.Normalize(hostOf(f.Asset)); err == nil {
			assets.Add(asset.Hostname(n))
		}
	}
	for host, labels := range techs {
		if n, err := dnsname.Normalize(host); err == nil {
			assets.Add(asset.Asset{Kind: asset.KindHostname, Value: n,
				Details: map[string]string{"technologies": asset.TruncateDetail(strings.Join(labels, ", "))}})
		}
	}
	res.Assets = assets.List()
	return res
}

// reachable returns the URLs worth scanning: those whose host resolves and
// whose port accepts a TCP connection, through the gate (so exclusions and
// per-IP ownership apply to the probe too), at most maxURLs. unreached are
// the names the gate refused entirely.
func (m *Module) reachable(ctx context.Context, g module.Gate, hosts []string) (urls, unreached []string, err error) {
	dns := resolver.Gated{Gate: g, Inner: m.dns}
	dial := dialer.Gated{Gate: g, Inner: m.dial}
	for _, h := range hosts {
		addrs, err := dns.LookupIP(ctx, h)
		switch {
		case errors.Is(err, resolver.ErrNotFound):
			continue
		case errors.Is(err, module.ErrExcluded):
			unreached = append(unreached, h)
			continue
		case err != nil:
			return nil, nil, fmt.Errorf("resolve %s: %w", h, err)
		}
		if len(addrs) > maxIPsPerHost {
			addrs = addrs[:maxIPsPerHost]
		}
		refusedAll := true
		for _, u := range m.urls(h) {
			port, ok := urlPort(u)
			if !ok {
				continue
			}
			for _, ip := range addrs {
				pctx, cancel := context.WithTimeout(ctx, probeTimeout)
				conn, err := dial.Dial(pctx, module.Destination{Host: h, IP: ip.Unmap(), Port: port})
				cancel()
				if err == nil {
					_ = conn.Close()
					refusedAll = false
					if len(urls) < maxURLs {
						urls = append(urls, u)
					}
					break
				}
				if !errors.Is(err, module.ErrExcluded) {
					refusedAll = false
				}
				if errors.Is(err, dialer.ErrGateRefused) && !errors.Is(err, module.ErrExcluded) {
					return nil, nil, err // rate limiter stopped: the scan is over
				}
			}
		}
		if refusedAll && len(addrs) > 0 {
			unreached = append(unreached, h)
		}
	}
	return urls, unreached, nil
}

func urlPort(raw string) (int, bool) {
	u, err := url.Parse(raw)
	if err != nil {
		return 0, false
	}
	if p := u.Port(); p != "" {
		n, err := strconv.Atoi(p)
		return n, err == nil && n > 0 && n < 65536
	}
	switch u.Scheme {
	case "https":
		return 443, true
	case "http":
		return 80, true
	}
	return 0, false
}

// pass is one Nuclei invocation.
type pass struct {
	name string
	args []string
}

// genericDirs are the template folders of the generic pass.
var genericDirs = []string{"http/exposures", "http/misconfiguration", "http/takeovers"}

func (m *Module) passes() []pass {
	out := []pass{{name: "detect", args: []string{
		// -automatic-scan reads the templates from the "install"
		// directory, hence -update-template-dir (no update is made:
		// -disable-update-check).
		"-automatic-scan", "-update-template-dir", m.cfg.Templates, "-templates", m.cfg.Templates,
	}}}
	var dirs []string
	for _, d := range genericDirs {
		if st, err := os.Stat(filepath.Join(m.cfg.Templates, d)); err == nil && st.IsDir() {
			dirs = append(dirs, filepath.Join(m.cfg.Templates, d))
		}
	}
	if len(dirs) > 0 {
		out = append(out, pass{name: "generic", args: []string{
			"-templates", strings.Join(dirs, ","), "-severity", "medium,high,critical",
		}})
	}
	return out
}

// writeInputs writes the URL list and the proxy file. The proxy URL carries
// a secret, so it goes in a file readable by us only, never on the command
// line (visible to every local user in ps).
func writeInputs(dir string, urls []string, proxyURL string) error {
	files := map[string]string{"targets.txt": strings.Join(urls, "\n") + "\n", "proxy.txt": proxyURL + "\n"}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			return fmt.Errorf("write %s: %w", name, err)
		}
	}
	if err := os.Mkdir(filepath.Join(dir, "home"), 0o700); err != nil {
		return fmt.Errorf("home dir: %w", err)
	}
	return nil
}

// commonArgs are the flags of every pass.
func commonArgs(dir string) []string {
	return []string{
		"-list", filepath.Join(dir, "targets.txt"),
		"-type", "http",
		"-exclude-tags", strings.Join(excludedTags, ","),
		"-proxy", filepath.Join(dir, "proxy.txt"),
		"-no-interactsh",
		"-disable-update-check",
		"-no-httpx", // targets are URLs already probed
		"-header", "User-Agent: " + userAgent,
		"-jsonl", "-omit-raw", "-omit-template", "-silent", "-no-color",
		// The gate sets the real pace; these keep Nuclei from queuing far
		// more requests than the gate lets through.
		"-concurrency", "5", "-bulk-size", "5", "-rate-limit", "50",
		"-timeout", "20", "-retries", "1",
		"-max-redirects", "3",
		"-response-size-read", strconv.Itoa(2 << 20),
	}
}
