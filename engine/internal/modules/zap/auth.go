package zap

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/jordyorel/orus-shield/engine/internal/module"
)

// authEnvFile holds the test account's values for the docker client
// (--env-file). It stays on the worker's side, mode 0600: the plan refers
// to the values by ${...}, so they are in no file the container reads.
const authEnvFile = "auth.env"

// logoutPaths keep an authenticated scan from logging itself out.
var logoutPaths = []string{`(?i).*(log|sign)[-_]?(out|off).*`}

// applyAuth adds the test account to a plan: its header on every request
// to the domain (ZAP_AUTH_HEADER*), logout pages excluded. A form account
// arrives here as the Cookie header of its session (sessionAuth). It
// writes auth.env; with no account it does nothing.
func applyAuth(plan map[string]any, dir, domain string, auth *module.ScanAuth) error {
	if auth == nil || auth.Secret == "" {
		return nil
	}
	ctx := plan["env"].(map[string]any)["contexts"].([]any)[0].(map[string]any)
	ctx["excludePaths"] = logoutPaths
	var env []string
	switch auth.Kind {
	case "header":
		env = []string{
			"ZAP_AUTH_HEADER=" + auth.HeaderName,
			"ZAP_AUTH_HEADER_VALUE=" + auth.Secret,
			"ZAP_AUTH_HEADER_SITE=" + domain,
		}
	default:
		return fmt.Errorf("unknown test account kind %q", auth.Kind)
	}
	for _, line := range env {
		if strings.ContainsAny(line, "\r\n") {
			return fmt.Errorf("test account: a value spans several lines")
		}
	}
	return os.WriteFile(filepath.Join(dir, authEnvFile), []byte(strings.Join(env, "\n")+"\n"), 0o600)
}
