package main

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jordyorel/orus-shield/engine/internal/mailer"
	"github.com/jordyorel/orus-shield/engine/internal/modules/vulns"
	"github.com/jordyorel/orus-shield/engine/internal/modules/zap"
	"github.com/jordyorel/orus-shield/engine/internal/resolver"
	"github.com/jordyorel/orus-shield/engine/internal/seal"
	"github.com/jordyorel/orus-shield/engine/internal/worker"
)

// config is everything the worker reads from its environment (security
// rule 5: configuration comes from environment variables, never from code).
type config struct {
	databaseURL string
	worker      worker.Config
	// smtp sends the alerts the scans queue; nil: mail not configured, the
	// alerts wait in the outbox (and expire after a day).
	smtp      *mailer.SMTP
	publicURL string
	dns       *resolver.System
	nuclei    vulns.Config
	zap       zap.Config
}

// loadConfig reads the configuration through getenv (os.Getenv in
// production, a map in tests).
//
//	ORUS_DATABASE_URL     required, e.g. postgres://user:pass@host:5432/orus
//	ORUS_WORKER_ID        optional, defaults to worker:<hostname>-<pid>
//	ORUS_WORKER_LEASE     optional duration, e.g. 5m
//	ORUS_MODULE_TIMEOUT   optional duration, e.g. 2m
//	ORUS_POLL_INTERVAL    optional duration, e.g. 2s
//	ORUS_SMTP_ADDR, ORUS_SMTP_USERNAME, ORUS_SMTP_PASSWORD, ORUS_MAIL_FROM
//	                      email alerts (see mailer.FromEnv); unset: no alert is sent
//	ORUS_PUBLIC_URL       the dashboard's address, for links in alerts
//	ORUS_DNS_SERVER       DNS server for every lookup (modules, ownership), e.g.
//	                      127.0.0.1 (Unbound) or 1.1.1.1; unset: the system's.
//	                      Production should set it: see resolver.NewWithServer
//	ORUS_NUCLEI_BIN       path to the pinned nuclei binary (vulns module)
//	ORUS_NUCLEI_TEMPLATES path to the pinned nuclei-templates directory;
//	                      both or neither. Unset: the vulns module fails its runs
//	ORUS_CREDENTIALS_KEY  the API's key (32 bytes, base64) that opens customers'
//	                      test accounts for authenticated scans; unset: scans
//	                      run without them
//	ORUS_ZAP_IMAGE        pinned ZAP image, name@sha256:digest (zap module, deep
//	                      profile; see deploy/zap/install.sh). Unset: deep web
//	                      scans fail
//	ORUS_ZAP_PROXY_HOST   how the container reaches this host's loopback, where
//	                      gateproxy listens (default host.docker.internal)
//	ORUS_ZAP_NETWORK      docker run --network (e.g. host on Linux); optional
//	ORUS_ZAP_WORKDIR      absolute directory for the runs' files, mountable by
//	                      Docker (Colima: under the home directory); optional
func loadConfig(getenv func(string) string) (config, error) {
	var c config
	c.databaseURL = getenv("ORUS_DATABASE_URL")
	if c.databaseURL == "" {
		return config{}, errors.New("ORUS_DATABASE_URL is required")
	}

	c.worker.ID = getenv("ORUS_WORKER_ID")
	if c.worker.ID == "" {
		host, err := os.Hostname()
		if err != nil {
			host = "unknown"
		}
		c.worker.ID = fmt.Sprintf("worker:%s-%d", host, os.Getpid())
	}

	durations := []struct {
		name string
		dst  *time.Duration
	}{
		{"ORUS_WORKER_LEASE", &c.worker.Lease},
		{"ORUS_MODULE_TIMEOUT", &c.worker.ModuleTimeout},
		{"ORUS_POLL_INTERVAL", &c.worker.PollInterval},
	}
	for _, d := range durations {
		v := getenv(d.name)
		if v == "" {
			continue // worker.New applies the default
		}
		parsed, err := time.ParseDuration(v)
		if err != nil || parsed <= 0 {
			return config{}, fmt.Errorf("%s=%q: want a positive duration such as 30s or 5m", d.name, v)
		}
		*d.dst = parsed
	}
	if c.worker.Lease > 0 && c.worker.ModuleTimeout > 0 && c.worker.ModuleTimeout >= c.worker.Lease {
		// Not fatal thanks to the heartbeat, but a sign of a mistake.
		return config{}, errors.New("ORUS_MODULE_TIMEOUT must be shorter than ORUS_WORKER_LEASE")
	}
	var err error
	if c.smtp, err = mailer.FromEnv(getenv); err != nil {
		return config{}, err
	}
	if c.publicURL, err = mailer.PublicURLFromEnv(getenv); err != nil {
		return config{}, err
	}
	if c.dns, err = resolver.FromEnv(getenv); err != nil {
		return config{}, fmt.Errorf("ORUS_DNS_SERVER: %w", err)
	}
	if c.nuclei, err = nucleiFromEnv(getenv); err != nil {
		return config{}, err
	}
	if c.zap, err = zapFromEnv(getenv); err != nil {
		return config{}, err
	}
	if raw := strings.TrimSpace(getenv("ORUS_CREDENTIALS_KEY")); raw != "" {
		key, err := base64.StdEncoding.DecodeString(raw)
		if err != nil || len(key) != seal.KeyLen {
			return config{}, fmt.Errorf("ORUS_CREDENTIALS_KEY must be %d random bytes in base64", seal.KeyLen)
		}
		if c.worker.Credentials, err = seal.NewKey(key); err != nil {
			return config{}, err
		}
	}
	return c, nil
}

// nucleiFromEnv reads where Nuclei is installed. Both paths must exist and
// be absolute: a relative path would depend on the worker's directory.
func nucleiFromEnv(getenv func(string) string) (vulns.Config, error) {
	bin, templates := getenv("ORUS_NUCLEI_BIN"), getenv("ORUS_NUCLEI_TEMPLATES")
	if bin == "" && templates == "" {
		return vulns.Config{}, nil
	}
	for name, path := range map[string]string{"ORUS_NUCLEI_BIN": bin, "ORUS_NUCLEI_TEMPLATES": templates} {
		if path == "" || !filepath.IsAbs(path) {
			return vulns.Config{}, fmt.Errorf("%s=%q: want an absolute path (set both ORUS_NUCLEI_BIN and ORUS_NUCLEI_TEMPLATES, or neither)", name, path)
		}
		if _, err := os.Stat(path); err != nil {
			return vulns.Config{}, fmt.Errorf("%s: %w", name, err)
		}
	}
	return vulns.Config{Binary: bin, Templates: templates}, nil
}

// zapFromEnv reads how ZAP runs. The image must be pinned by digest: a tag
// can be moved to other content.
func zapFromEnv(getenv func(string) string) (zap.Config, error) {
	image := getenv("ORUS_ZAP_IMAGE")
	if image == "" {
		return zap.Config{}, nil
	}
	if !strings.Contains(image, "@sha256:") {
		return zap.Config{}, fmt.Errorf("ORUS_ZAP_IMAGE=%q: pin the image by digest (name@sha256:...), see deploy/zap/install.sh", image)
	}
	cfg := zap.Config{Image: image, ProxyHost: getenv("ORUS_ZAP_PROXY_HOST"), Network: getenv("ORUS_ZAP_NETWORK"), WorkDir: getenv("ORUS_ZAP_WORKDIR")}
	if cfg.WorkDir != "" && !filepath.IsAbs(cfg.WorkDir) {
		return zap.Config{}, fmt.Errorf("ORUS_ZAP_WORKDIR=%q: want an absolute path", cfg.WorkDir)
	}
	return cfg, nil
}
