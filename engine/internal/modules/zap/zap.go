// Package zap is the deep web application scan of the deep profile
// ("Approfondi"): OWASP ZAP crawls each site of the target, then runs its
// active scan rules (injections, cross-site scripting, path traversal,
// request forgery...).
//
// It is an ACTIVE module, and the most intrusive one: the active scan sends
// attack payloads to the customer's applications. It therefore runs only
//
//   - on verified targets (rule 1; the worker checks it, and so does Run),
//   - when the organization chose the deep profile with an explicit consent
//     and its offer includes it: the worker then passes Config
//     {"deep": true}; otherwise Run does nothing and evaluates nothing.
//
// ZAP runs in a pinned Docker image (ORUS_ZAP_IMAGE, by digest). Its only
// route out is package gateproxy, as for Nuclei: ZAP is configured with the
// proxy as its upstream, so every request it sends is checked by the
// scan's gate (scope, per-IP ownership, exclusions with paths, rate
// limiter). Production must also deny the container any other network
// access (see CLAUDE.md, External tools).
//
// Only exploitable application flaws become findings (see report.go):
// header and cookie hygiene is the web module's, so ZAP's passive alerts
// would only duplicate it.
package zap

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/jordyorel/orus-shield/engine/internal/dialer"
	"github.com/jordyorel/orus-shield/engine/internal/finding"
	"github.com/jordyorel/orus-shield/engine/internal/gateproxy"
	"github.com/jordyorel/orus-shield/engine/internal/module"
	"github.com/jordyorel/orus-shield/engine/internal/resolver"
)

// ID is the stable module ID. Never change it: finding IDs depend on it.
const ID = "zap"

// Check IDs, one per class of flaw.
const (
	CheckInjection = "zap-injection"
	CheckXSS       = "zap-xss"
	CheckFiles     = "zap-file-access"
	CheckForgery   = "zap-request-forgery"
	CheckOther     = "zap-other-high-risk"
)

// Checks is the module's catalog.
var Checks = []module.Check{
	{ID: CheckInjection, Category: module.CategoryWeb, Severity: finding.SeverityCritical, Title: "No injection flaw (SQL, command, code, template, XML)"},
	{ID: CheckXSS, Category: module.CategoryWeb, Severity: finding.SeverityHigh, Title: "No cross-site scripting"},
	{ID: CheckFiles, Category: module.CategoryWeb, Severity: finding.SeverityHigh, Title: "No path traversal or file inclusion"},
	{ID: CheckForgery, Category: module.CategoryWeb, Severity: finding.SeverityMedium, Title: "No server-side request forgery or open redirect"},
	{ID: CheckOther, Category: module.CategoryWeb, Severity: finding.SeverityHigh, Title: "No other high-risk web application flaw"},
}

const (
	// Timeout bounds one run: crawl, then active scan of up to maxURLs
	// sites at the customer's rate.
	Timeout = 3 * time.Hour
	// maxURLs bounds the sites (name and scheme) one run scans.
	maxURLs = 4
	// probeTimeout bounds the TCP check that a site answers.
	probeTimeout  = 5 * time.Second
	maxIPsPerHost = 4
	// maxReport bounds the report we read back (rule 7).
	maxReport = 16 << 20
	// userAgent tells the customer's logs who is scanning.
	userAgent = "OrusShield/1 (+deep security check of a site you registered)"
)

// Config is how this worker runs ZAP.
type Config struct {
	// Image is the pinned image, name@sha256:digest (ORUS_ZAP_IMAGE).
	Image string
	// ProxyHost is how the container reaches the worker's loopback, where
	// gateproxy listens: "host.docker.internal" with Docker Desktop, or
	// "127.0.0.1" with Network "host" on Linux (ORUS_ZAP_PROXY_HOST).
	ProxyHost string
	// Network is passed to docker run --network ("" for the default).
	Network string
	// WorkDir holds the per-run temporary files, mounted into the
	// container (ORUS_ZAP_WORKDIR); empty: the system's. Docker must be
	// able to mount it: Colima shares only the home directory.
	WorkDir string
}

// ErrNotInstalled is returned when ZAP is not configured on this worker.
var ErrNotInstalled = errors.New("ZAP is not installed on this worker (ORUS_ZAP_IMAGE)")

// RunConfig is the module's per-scan configuration (module.Request.Config).
type RunConfig struct {
	Deep bool `json:"deep"`
}

// Module is the deep web scan.
type Module struct {
	cfg    Config
	dns    resolver.Resolver
	dial   dialer.Dialer
	runner Runner
	// urls gives the candidate URLs of a host; tests point it elsewhere.
	urls func(host string) []string
}

func defaultURLs(host string) []string { return []string{"https://" + host, "http://" + host} }

// New returns the module.
func New(dns resolver.Resolver, dial dialer.Dialer, cfg Config) *Module {
	if cfg.ProxyHost == "" {
		cfg.ProxyHost = "host.docker.internal"
	}
	return &Module{cfg: cfg, dns: dns, dial: dial, runner: Docker{}, urls: defaultURLs}
}

// Info implements module.Module.
func (m *Module) Info() module.Info {
	return module.Info{ID: ID, Name: "Deep web application scan", Kind: module.KindActive, Checks: Checks, Timeout: Timeout}
}

// Run implements module.Module. Outside the deep profile it returns an
// empty result: nothing observed, nothing evaluated, findings untouched.
func (m *Module) Run(ctx context.Context, req module.Request) (module.Result, error) {
	var rc RunConfig
	if len(req.Config) > 0 {
		if err := json.Unmarshal(req.Config, &rc); err != nil {
			return module.Result{}, fmt.Errorf("zap: invalid config: %w", err)
		}
	}
	if !rc.Deep {
		return module.Result{}, nil
	}
	if m.cfg.Image == "" {
		return module.Result{}, ErrNotInstalled
	}
	domain, err := module.NormalizeDomain(req.Target.Domain)
	if err != nil {
		return module.Result{}, fmt.Errorf("zap: %w", err)
	}
	if !req.Target.Verified { // defense in depth: the worker checks it too
		return module.Result{}, fmt.Errorf("zap on %s: %w", domain, module.ErrNotVerified)
	}

	urls, unreached, err := m.reachable(ctx, req.Gate, req.Target.ScanHosts(domain))
	if err != nil {
		return module.Result{}, fmt.Errorf("zap: %w", err)
	}
	if len(urls) == 0 {
		return module.Result{Unreached: unreached}, nil
	}

	proxy, err := gateproxy.Start(ctx, gateproxy.Config{Domain: domain, Gate: req.Gate, DNS: m.dns, Dial: m.dial})
	if err != nil {
		return module.Result{}, fmt.Errorf("zap: %w", err)
	}
	defer func() { _ = proxy.Close() }()
	up, err := upstream(proxy.URL(), m.cfg.ProxyHost)
	if err != nil {
		return module.Result{}, fmt.Errorf("zap: %w", err)
	}

	dir, err := os.MkdirTemp(m.cfg.WorkDir, "orus-zap-")
	if err != nil {
		return module.Result{}, fmt.Errorf("zap: work dir: %w", err)
	}
	defer func() { _ = os.RemoveAll(dir) }()
	if err := writeInputs(dir, domain, urls, up); err != nil {
		return module.Result{}, fmt.Errorf("zap: %w", err)
	}

	if err := m.runner.Run(ctx, m.cfg, dir); err != nil {
		if ctx.Err() != nil {
			return module.Result{}, fmt.Errorf("zap: %w", ctx.Err())
		}
		return module.Result{}, fmt.Errorf("zap: %w", err)
	}
	_ = proxy.Close() // wait for the last requests before reading the counters
	if err := proxy.Err(); err != nil {
		return module.Result{}, fmt.Errorf("zap: scan stopped: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return module.Result{}, fmt.Errorf("zap: %w", err)
	}

	rep, err := readReport(filepath.Join(dir, reportFile))
	if err != nil {
		return module.Result{}, fmt.Errorf("zap: %w", err)
	}
	res := convert(domain, rep)
	res.Unreached = append(unreached, proxy.Unreached()...)
	// Every check is evaluated once a request reached the target: "no
	// alert" is then a pass. A run where nothing answered evaluates none.
	if proxy.Stats().Answered > 0 {
		for _, c := range Checks {
			res.Evaluated = append(res.Evaluated, c.ID)
		}
	}
	return res, nil
}

// reachable keeps the URLs whose port accepts a gated TCP connection, at
// most maxURLs (the logic of the vulns module). Names the gate refused
// entirely are reported unreached.
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
