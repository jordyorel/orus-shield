package main

import (
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/jordyorel/orus-shield/engine/internal/mailer"
	"github.com/jordyorel/orus-shield/engine/internal/resolver"
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
	return c, nil
}
