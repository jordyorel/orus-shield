// Package web checks how a domain's websites protect their visitors: the
// redirection from HTTP to HTTPS, the security headers browsers rely on, the
// Secure flag of cookies, and software versions the server reveals.
//
// It is passive: it sends ordinary "GET /" requests, like a browser opening
// the home page, and reads the response headers only, never the body. It
// checks the domain and its www. subdomain, on ports 80 and 443.
//
// What it does not do (later modules, or the "Deep" profile): crawl pages,
// submit forms, test for injections, identify CMS versions from page content.
package web

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jordyorel/orus-shield/engine/internal/asset"
	"github.com/jordyorel/orus-shield/engine/internal/dialer"
	"github.com/jordyorel/orus-shield/engine/internal/finding"
	"github.com/jordyorel/orus-shield/engine/internal/module"
	"github.com/jordyorel/orus-shield/engine/internal/resolver"
)

// ID is the stable module ID. Never change it: finding IDs depend on it.
const ID = "web"

// Check IDs. They are stable: reports use them to show localized text.
const (
	CheckHTTPNotRedirected = "web-http-not-redirected"
	CheckHSTSMissing       = "web-hsts-missing"
	CheckCSPMissing        = "web-csp-missing"
	CheckFramingAllowed    = "web-framing-allowed"
	CheckNosniffMissing    = "web-nosniff-missing"
	CheckCookieNotSecure   = "web-cookie-not-secure"
	CheckVersionDisclosed  = "web-version-disclosed"
)

// Checks is the module's catalog.
var Checks = []module.Check{
	{ID: CheckHTTPNotRedirected, Category: module.CategoryWeb, Severity: finding.SeverityMedium, Title: "HTTP visitors are sent to HTTPS"},
	{ID: CheckHSTSMissing, Category: module.CategoryWeb, Severity: finding.SeverityMedium, Title: "Browsers are told to always use HTTPS (HSTS)"},
	{ID: CheckCSPMissing, Category: module.CategoryWeb, Severity: finding.SeverityLow, Title: "A Content Security Policy is set"},
	{ID: CheckFramingAllowed, Category: module.CategoryWeb, Severity: finding.SeverityLow, Title: "Pages cannot be framed by other sites"},
	{ID: CheckNosniffMissing, Category: module.CategoryWeb, Severity: finding.SeverityLow, Title: "Browsers do not guess content types"},
	{ID: CheckCookieNotSecure, Category: module.CategoryWeb, Severity: finding.SeverityLow, Title: "Cookies are sent over HTTPS only"},
	{ID: CheckVersionDisclosed, Category: module.CategoryWeb, Severity: finding.SeverityLow, Title: "Server software versions are not revealed"},
}

const (
	httpPort  = 80
	httpsPort = 443
	// maxIPsPerHost bounds the addresses tried per name. The first one that
	// answers is used: the headers are the site's configuration, normally
	// identical behind every address (the tls module, which checks each
	// address, is where per-server differences matter most).
	maxIPsPerHost = 4
	// maxRedirects bounds the redirections followed on the same host (for
	// example "/" to "/fr/") before reading the page's headers.
	maxRedirects = 3
	// requestTimeout bounds one request, from dial to the end of headers.
	requestTimeout = 10 * time.Second
	// maxHeaderBytes bounds what we read from the target (rule 7): status
	// line and headers only, never the body.
	maxHeaderBytes = 32 << 10
	userAgent      = "OrusShield/1 (+security check of a site you registered)"
)

// Module is the web check.
type Module struct {
	dns  resolver.Resolver
	dial dialer.Dialer
}

// New returns the module. dns and dial are the underlying resolver and
// dialer; the module wraps both with the request's gate on every run.
func New(dns resolver.Resolver, dial dialer.Dialer) *Module {
	return &Module{dns: dns, dial: dial}
}

// Info implements module.Module.
func (m *Module) Info() module.Info {
	return module.Info{ID: ID, Name: "Website security", Kind: module.KindPassive, Checks: Checks}
}

// Run implements module.Module. req.Config is ignored for now.
//
// A name that does not resolve, or a port that does not answer HTTP,
// produces nothing: checks are only evaluated on responses we read. DNS
// failures other than "not found", gate refusals and cancellation stop the
// run.
//
// Assets: each name that answered over HTTP or HTTPS.
func (m *Module) Run(ctx context.Context, req module.Request) (module.Result, error) {
	domain, err := module.NormalizeDomain(req.Target.Domain)
	if err != nil {
		return module.Result{}, fmt.Errorf("web: %w", err)
	}
	c := client{
		dns:  resolver.Gated{Gate: req.Gate, Inner: m.dns},
		dial: dialer.Gated{Gate: req.Gate, Inner: m.dial},
	}

	hosts := []string{domain}
	if !strings.HasPrefix(domain, "www.") {
		hosts = append(hosts, "www."+domain)
	}
	var (
		findings  []finding.Finding
		assets    asset.Set
		evaluated []string
	)
	for _, host := range hosts {
		r, err := checkHost(ctx, c, domain, host)
		if err != nil {
			return module.Result{}, fmt.Errorf("web: %w", err)
		}
		for _, i := range r.issues {
			findings = append(findings, i.finding(domain))
		}
		evaluated = append(evaluated, r.evaluated...)
		if r.answered {
			assets.Add(asset.Hostname(host))
		}
	}
	return module.Result{Findings: findings, Assets: assets.List(), Evaluated: evaluated}, nil
}

// hostResult is what was learned about one host name.
type hostResult struct {
	issues    []issue
	evaluated []string
	answered  bool
}

func (r *hostResult) add(i issue)            { r.issues = append(r.issues, i) }
func (r *hostResult) evaluate(ids ...string) { r.evaluated = append(r.evaluated, ids...) }
func (r *hostResult) merge(o hostResult) {
	r.issues = append(r.issues, o.issues...)
	r.evaluated = append(r.evaluated, o.evaluated...)
}

// checkHost reads the HTTPS and HTTP responses of host and analyzes them.
func checkHost(ctx context.Context, c client, domain, host string) (hostResult, error) {
	var r hostResult
	ips, err := c.lookup(ctx, host)
	if err != nil || len(ips) == 0 {
		return r, err
	}

	// HTTPS first: whether it works changes what we say about plain HTTP.
	secure, err := c.fetchPage(ctx, host, ips, httpsPort)
	if err != nil {
		return r, err
	}
	if len(secure) > 0 {
		r.answered = true
		r.merge(analyzeHTTPS(host, secure))
	}

	plain, err := c.fetchPage(ctx, host, ips, httpPort)
	if err != nil {
		return r, err
	}
	if len(plain) > 0 {
		r.answered = true
		if i, evaluated := analyzeHTTP(domain, host, plain, len(secure) > 0); evaluated {
			r.evaluate(CheckHTTPNotRedirected)
			if i != nil {
				r.add(*i)
			}
		}
	}

	r.merge(analyzeVersions(host, secure, plain))
	return r, nil
}

// stopError returns the error that must stop the whole run, or nil if the
// failure only concerns this address. Exclusions are expected; any other
// gate refusal, or cancellation, stops the run.
func stopError(ctx context.Context, err error) error {
	if errors.Is(err, module.ErrExcluded) {
		return nil
	}
	if errors.Is(err, dialer.ErrGateRefused) || errors.Is(err, dialer.ErrNoGate) {
		return err
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		return fmt.Errorf("%w: %w", ctxErr, err)
	}
	return nil
}

// issue is what a check detects; see the email module for the same pattern.
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
