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
	"strings"

	"github.com/jordyorel/orus-shield/engine/internal/dialer"
	"github.com/jordyorel/orus-shield/engine/internal/dnsname"
	"github.com/jordyorel/orus-shield/engine/internal/finding"
	"github.com/jordyorel/orus-shield/engine/internal/gateproxy"
	"github.com/jordyorel/orus-shield/engine/internal/module"
	"github.com/jordyorel/orus-shield/engine/internal/resolver"
)

// APIID is the stable ID of the API security module (step H).
const APIID = "api"

// Checks of the API module.
const (
	CheckAPIInjection = "api-injection"
	CheckAPIAccess    = "api-access-control"
	CheckAPIExposure  = "api-data-exposure"
	CheckAPIConfig    = "api-misconfiguration"
	CheckAPIOther     = "api-other-high-risk"
)

// APIChecks is the API module's catalog.
var APIChecks = []module.Check{
	{ID: CheckAPIInjection, Category: module.CategoryWeb, Severity: finding.SeverityCritical, Title: "No injection flaw in the API (SQL, command, code, XML)"},
	{ID: CheckAPIAccess, Category: module.CategoryWeb, Severity: finding.SeverityHigh, Title: "API endpoints require authentication and enforce access control"},
	{ID: CheckAPIExposure, Category: module.CategoryWeb, Severity: finding.SeverityMedium, Title: "The API does not expose internal details or sensitive data"},
	{ID: CheckAPIConfig, Category: module.CategoryWeb, Severity: finding.SeverityMedium, Title: "The API is configured safely (CORS, methods)"},
	{ID: CheckAPIOther, Category: module.CategoryWeb, Severity: finding.SeverityHigh, Title: "No other high-risk API flaw"},
}

// apiClasses map CWE identifiers to the API checks.
var apiClasses = map[string]string{
	"77": CheckAPIInjection, "78": CheckAPIInjection, "89": CheckAPIInjection, "90": CheckAPIInjection,
	"94": CheckAPIInjection, "95": CheckAPIInjection, "611": CheckAPIInjection, "643": CheckAPIInjection,
	"917": CheckAPIInjection, "943": CheckAPIInjection, "1336": CheckAPIInjection,
	"284": CheckAPIAccess, "285": CheckAPIAccess, "287": CheckAPIAccess, "306": CheckAPIAccess,
	"639": CheckAPIAccess, "862": CheckAPIAccess, "863": CheckAPIAccess,
	"200": CheckAPIExposure, "209": CheckAPIExposure, "215": CheckAPIExposure, "359": CheckAPIExposure,
	"497": CheckAPIExposure, "532": CheckAPIExposure,
	"16": CheckAPIConfig, "346": CheckAPIConfig, "942": CheckAPIConfig, "749": CheckAPIConfig,
}

// classifyAPI is classify for the API checks: medium and high alerts of
// the known classes, and every other high one.
func classifyAPI(a alert) (string, finding.Severity) {
	risk, _ := strconv.Atoi(a.RiskCode)
	if risk < 2 {
		return "", ""
	}
	check := apiClasses[strings.TrimSpace(a.CWE)]
	switch {
	case check == "" && risk >= 3:
		check = CheckAPIOther
	case check == "":
		return "", ""
	}
	sev := finding.SeverityMedium
	if risk >= 3 {
		sev = finding.SeverityHigh
		if check == CheckAPIInjection {
			sev = finding.SeverityCritical
		}
	}
	return check, sev
}

// maxAPIs bounds the APIs one run scans.
const maxAPIs = 5

// APIModule scans the APIs a customer declared on a verified target, with
// ZAP behind gateproxy (same image, runner and hardening as the zap module).
// Without declared APIs it does nothing and evaluates nothing.
type APIModule struct {
	cfg    Config
	dns    resolver.Resolver
	dial   dialer.Dialer
	runner Runner
}

// NewAPI returns the API security module.
func NewAPI(dns resolver.Resolver, dial dialer.Dialer, cfg Config) *APIModule {
	if cfg.ProxyHost == "" {
		cfg.ProxyHost = "host.docker.internal"
	}
	return &APIModule{cfg: cfg, dns: dns, dial: dial, runner: Docker{}}
}

// Info implements module.Module.
func (m *APIModule) Info() module.Info {
	return module.Info{ID: APIID, Name: "API security", Kind: module.KindActive, Checks: APIChecks, Timeout: Timeout, UsesAPIs: true, UsesCredentials: true}
}

// Run implements module.Module.
func (m *APIModule) Run(ctx context.Context, req module.Request) (module.Result, error) {
	var rc module.RunConfig
	if len(req.Config) > 0 {
		if err := json.Unmarshal(req.Config, &rc); err != nil {
			return module.Result{}, fmt.Errorf("api: invalid config: %w", err)
		}
	}
	if len(rc.APIs) == 0 {
		return module.Result{}, nil
	}
	if m.cfg.Image == "" {
		return module.Result{}, ErrNotInstalled
	}
	domain, err := module.NormalizeDomain(req.Target.Domain)
	if err != nil {
		return module.Result{}, fmt.Errorf("api: %w", err)
	}
	if !req.Target.Verified { // defense in depth: the worker checks it too
		return module.Result{}, fmt.Errorf("api on %s: %w", domain, module.ErrNotVerified)
	}
	// Defense in depth: the API checked these URLs when they were declared.
	var apis []module.ScanAPI
	for _, a := range rc.APIs {
		if inScope(a.BaseURL, domain) && (a.SpecURL == "" || inScope(a.SpecURL, domain)) && len(apis) < maxAPIs {
			apis = append(apis, a)
		}
	}
	if len(apis) == 0 {
		return module.Result{}, errors.New("api: no declared API is under the target's domain")
	}

	proxy, err := gateproxy.Start(ctx, gateproxy.Config{Domain: domain, Gate: req.Gate, DNS: m.dns, Dial: m.dial})
	if err != nil {
		return module.Result{}, fmt.Errorf("api: %w", err)
	}
	defer func() { _ = proxy.Close() }()
	up, err := upstream(proxy.URL(), m.cfg.ProxyHost)
	if err != nil {
		return module.Result{}, fmt.Errorf("api: %w", err)
	}
	dir, err := os.MkdirTemp(m.cfg.WorkDir, "orus-api-")
	if err != nil {
		return module.Result{}, fmt.Errorf("api: work dir: %w", err)
	}
	defer func() { _ = os.RemoveAll(dir) }()
	auth, err := sessionAuth(ctx, proxy.URL(), domain, rc.Auth)
	if err != nil {
		return module.Result{}, fmt.Errorf("api: %w", err)
	}
	if err := writeAPIInputs(dir, domain, apis, up, auth); err != nil {
		return module.Result{}, fmt.Errorf("api: %w", err)
	}
	if err := m.runner.Run(ctx, m.cfg, dir); err != nil {
		if ctx.Err() != nil {
			return module.Result{}, fmt.Errorf("api: %w", ctx.Err())
		}
		return module.Result{}, fmt.Errorf("api: %w", err)
	}
	_ = proxy.Close()
	if err := proxy.Err(); err != nil {
		return module.Result{}, fmt.Errorf("api: scan stopped: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return module.Result{}, fmt.Errorf("api: %w", err)
	}
	rep, err := readReport(filepath.Join(dir, reportFile))
	if err != nil {
		return module.Result{}, fmt.Errorf("api: %w", err)
	}
	res := convertWith(APIID, classifyAPI, domain, rep)
	res.Unreached = proxy.Unreached()
	if proxy.Stats().Answered > 0 {
		for _, c := range APIChecks {
			res.Evaluated = append(res.Evaluated, c.ID)
		}
	}
	return res, nil
}

// inScope reports whether raw is an http(s) URL on domain or under it.
func inScope(raw, domain string) bool {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil {
		return false
	}
	host, err := dnsname.Normalize(u.Hostname())
	return err == nil && (host == domain || strings.HasSuffix(host, "."+domain))
}

// writeAPIInputs writes uploaded descriptions, the plan and the config.
func writeAPIInputs(dir, domain string, apis []module.ScanAPI, up proxyAddr, auth *module.ScanAuth) error {
	var urls []string
	var jobs []any
	for i, a := range apis {
		urls = append(urls, a.BaseURL)
		switch a.Kind {
		case "graphql":
			p := map[string]any{"endpoint": a.BaseURL}
			if a.SpecURL != "" {
				p["schemaUrl"] = a.SpecURL
			}
			if a.Spec != "" {
				name := fmt.Sprintf("schema-%d.graphql", i)
				if err := os.WriteFile(filepath.Join(dir, name), []byte(a.Spec), 0o644); err != nil { //nolint:gosec // G306: read by the container's user; the customer's own document
					return fmt.Errorf("schema: %w", err)
				}
				p["schemaFile"] = containerDir + "/" + name
			}
			jobs = append(jobs, map[string]any{"type": "graphql", "parameters": p})
		default:
			p := map[string]any{"context": "orus", "targetUrl": a.BaseURL}
			if a.Spec != "" {
				name := fmt.Sprintf("spec-%d", i)
				if err := os.WriteFile(filepath.Join(dir, name), []byte(a.Spec), 0o644); err != nil { //nolint:gosec // G306: as above
					return fmt.Errorf("spec: %w", err)
				}
				p["apiFile"] = containerDir + "/" + name
			} else {
				p["apiUrl"] = a.SpecURL
			}
			jobs = append(jobs, map[string]any{"type": "openapi", "parameters": p})
		}
	}
	plan := map[string]any{
		"env": map[string]any{
			"contexts": []any{map[string]any{
				"name": "orus", "urls": urls, "includePaths": []string{scopeRegex(domain)},
			}},
			"parameters": map[string]any{"failOnError": false, "failOnWarning": false, "progressToStdout": false},
		},
		"jobs": append(jobs,
			map[string]any{"type": "passiveScan-wait", "parameters": map[string]any{"maxDuration": 5}},
			map[string]any{
				"type":             "activeScan",
				"parameters":       map[string]any{"context": "orus", "maxRuleDurationInMins": 5, "maxScanDurationInMins": 90, "threadPerHost": 2},
				"policyDefinition": map[string]any{"defaultStrength": "low", "defaultThreshold": "medium"},
			},
			map[string]any{"type": "report", "parameters": map[string]any{
				"template": "traditional-json", "reportDir": containerDir, "reportFile": strings.TrimSuffix(reportFile, ".json"),
			}},
		),
	}
	if err := applyAuth(plan, dir, domain, auth); err != nil {
		return err
	}
	b, err := json.MarshalIndent(plan, "", "  ")
	if err != nil {
		return fmt.Errorf("plan: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, planFile), b, 0o644); err != nil { //nolint:gosec // G306: read by the container's user
		return fmt.Errorf("plan: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, configFile), []byte(zapConfig(up)), 0o644); err != nil { //nolint:gosec // G306: per-scan proxy credential, see writeInputs
		return fmt.Errorf("config: %w", err)
	}
	if err := os.Chmod(dir, 0o733); err != nil { //nolint:gosec // G302: see writeInputs
		return fmt.Errorf("work dir: %w", err)
	}
	return nil
}
