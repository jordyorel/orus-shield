package zap

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Files of a run, in its work directory (mounted at containerDir).
const (
	containerDir = "/zap/wrk"
	planFile     = "plan.yaml"
	configFile   = "zap.conf"
	reportFile   = "report.json"
)

// proxyAddr is where the container finds gateproxy, with its credential.
type proxyAddr struct {
	Host, Port, User, Pass string
}

// upstream reads gateproxy's URL (http://user:pass@127.0.0.1:port) and
// replaces its host with the one the container reaches the worker by.
func upstream(proxyURL, host string) (proxyAddr, error) {
	u, err := url.Parse(proxyURL)
	if err != nil || u.User == nil {
		return proxyAddr{}, errors.New("unexpected gateproxy URL")
	}
	pass, _ := u.User.Password()
	_, port, err := net.SplitHostPort(u.Host)
	if err != nil {
		return proxyAddr{}, fmt.Errorf("gateproxy URL: %w", err)
	}
	return proxyAddr{Host: host, Port: port, User: u.User.Username(), Pass: pass}, nil
}

// writeInputs writes the automation plan and ZAP's configuration. The plan
// is written as JSON, which is valid YAML: every value is quoted by the
// encoder, so no name from the scan can change the plan's structure.
func writeInputs(dir, domain string, urls []string, up proxyAddr) error {
	plan, err := json.MarshalIndent(automationPlan(domain, urls), "", "  ")
	if err != nil {
		return fmt.Errorf("plan: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, planFile), plan, 0o644); err != nil { //nolint:gosec // G306: read by the container's own user; holds no secret
		return fmt.Errorf("plan: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, configFile), []byte(zapConfig(up)), 0o644); err != nil { //nolint:gosec // G306: read by the container's user; the proxy credential is per scan and the proxy only reaches the scan's own target
		return fmt.Errorf("config: %w", err)
	}
	// The container runs as its own user: it must be able to write the
	// report. The directory's name is random and it lives for one run.
	if err := os.Chmod(dir, 0o733); err != nil { //nolint:gosec // G302: see above
		return fmt.Errorf("work dir: %w", err)
	}
	return nil
}

// scopeRegex matches URLs of domain and of names under it, any port.
func scopeRegex(domain string) string {
	return `^https?://([a-z0-9-]+\.)*` + regexp.QuoteMeta(domain) + `(:[0-9]+)?(/.*)?$`
}

// automationPlan is ZAP's automation framework plan: crawl, wait for the
// passive scan, active scan, JSON report. Limits keep a run bounded; the
// gate's rate limiter paces every request anyway.
func automationPlan(domain string, urls []string) map[string]any {
	return map[string]any{
		"env": map[string]any{
			"contexts": []any{map[string]any{
				"name":         "orus",
				"urls":         urls,
				"includePaths": []string{scopeRegex(domain)},
			}},
			"parameters": map[string]any{
				"failOnError":      false,
				"failOnWarning":    false,
				"progressToStdout": false,
			},
		},
		"jobs": []any{
			map[string]any{"type": "spider", "parameters": map[string]any{
				"context": "orus", "maxDuration": 10, "maxDepth": 5, "maxChildren": 50, "userAgent": userAgent,
			}},
			map[string]any{"type": "passiveScan-wait", "parameters": map[string]any{"maxDuration": 10}},
			map[string]any{
				"type": "activeScan",
				"parameters": map[string]any{
					"context": "orus", "maxRuleDurationInMins": 5, "maxScanDurationInMins": 120, "threadPerHost": 2,
				},
				// Low strength: fewer attack variants per input, so less
				// load on the customer's application.
				"policyDefinition": map[string]any{"defaultStrength": "low", "defaultThreshold": "medium"},
			},
			map[string]any{"type": "report", "parameters": map[string]any{
				"template": "traditional-json", "reportDir": containerDir, "reportFile": strings.TrimSuffix(reportFile, ".json"),
			}},
		},
	}
}

// zapConfig sets gateproxy as ZAP's upstream proxy for every request (no
// bypass list), and our user agent.
func zapConfig(up proxyAddr) string {
	lines := []string{
		"network.connection.httpProxy.enabled=true",
		"network.connection.httpProxy.host=" + up.Host,
		"network.connection.httpProxy.port=" + up.Port,
		"network.connection.httpProxy.authEnabled=true",
		"network.connection.httpProxy.username=" + up.User,
		"network.connection.httpProxy.password=" + up.Pass,
		"network.connection.defaultUserAgent=" + userAgent,
	}
	return strings.Join(lines, "\n") + "\n"
}
