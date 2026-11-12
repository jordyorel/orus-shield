package main

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/jordyorel/orus-shield/engine/internal/mailer"
	"github.com/jordyorel/orus-shield/engine/internal/resolver"
	"github.com/jordyorel/orus-shield/engine/internal/seal"
)

type config struct {
	databaseURL    string
	addr           string
	trustedOrigins []string
	mfaKey         []byte
	credentialsKey []byte
	publicURL      string
	smtp           *mailer.SMTP // nil: mail not configured
	signupClosed   bool
	dns            *resolver.System
}

// loadConfig reads:
//
//	ORUS_DATABASE_URL         required
//	ORUS_API_ADDR             listen address, default 127.0.0.1:8080
//	ORUS_API_TRUSTED_ORIGINS  comma-separated origins allowed to send
//	                          state-changing requests besides the API's own
//	                          (e.g. http://localhost:5173 in development)
//	ORUS_MFA_KEY              required: 32 random bytes in base64, the key
//	                          that encrypts TOTP secrets in the database
//	                          (generate with: openssl rand -base64 32).
//	                          Losing it disables every user's MFA codes;
//	                          keep it out of the database backups.
//	ORUS_CREDENTIALS_KEY      optional: 32 random bytes in base64, the key that
//	                          seals customers' test accounts (authenticated
//	                          scans); the worker needs the same. Unset: no
//	                          test account can be stored
//	ORUS_PUBLIC_URL           the dashboard's address, for links in emails;
//	                          default http://localhost:5173 (development)
//	ORUS_SMTP_ADDR            SMTP server host:port; unset: no email is sent
//	                          (development: Mailpit, 127.0.0.1:1025)
//	ORUS_SMTP_USERNAME        SMTP login, if the server needs one
//	ORUS_SMTP_PASSWORD        SMTP password
//	ORUS_MAIL_FROM            sender, e.g. "Orus Shield <no-reply@example.com>";
//	                          required with ORUS_SMTP_ADDR
//	ORUS_DNS_SERVER           DNS server for ownership checks, e.g. 1.1.1.1;
//	                          unset: the system's (see resolver.NewWithServer)
//	ORUS_SIGNUP               "open" (default) or "closed": self-service signup;
//	                          closed means accounts by invitation only
func loadConfig(getenv func(string) string) (config, error) {
	cfg := config{
		databaseURL: getenv("ORUS_DATABASE_URL"),
		addr:        getenv("ORUS_API_ADDR"),
	}
	if cfg.databaseURL == "" {
		return config{}, errors.New("ORUS_DATABASE_URL is not set")
	}
	if cfg.addr == "" {
		cfg.addr = "127.0.0.1:8080"
	}
	if _, _, err := net.SplitHostPort(cfg.addr); err != nil {
		return config{}, errors.New("ORUS_API_ADDR must be host:port")
	}
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(getenv("ORUS_MFA_KEY")))
	if err != nil || len(key) != seal.KeyLen {
		return config{}, fmt.Errorf("ORUS_MFA_KEY must be %d random bytes in base64 (openssl rand -base64 32)", seal.KeyLen)
	}
	cfg.mfaKey = key
	if raw := strings.TrimSpace(getenv("ORUS_CREDENTIALS_KEY")); raw != "" {
		ck, err := base64.StdEncoding.DecodeString(raw)
		if err != nil || len(ck) != seal.KeyLen {
			return config{}, fmt.Errorf("ORUS_CREDENTIALS_KEY must be %d random bytes in base64 (openssl rand -base64 32)", seal.KeyLen)
		}
		cfg.credentialsKey = ck
	}
	for _, o := range strings.Split(getenv("ORUS_API_TRUSTED_ORIGINS"), ",") {
		if o = strings.TrimSpace(o); o != "" {
			cfg.trustedOrigins = append(cfg.trustedOrigins, o)
		}
	}
	if cfg.publicURL, err = mailer.PublicURLFromEnv(getenv); err != nil {
		return config{}, err
	}
	if cfg.smtp, err = mailer.FromEnv(getenv); err != nil {
		return config{}, err
	}
	if cfg.dns, err = resolver.FromEnv(getenv); err != nil {
		return config{}, fmt.Errorf("ORUS_DNS_SERVER: %w", err)
	}
	switch strings.TrimSpace(getenv("ORUS_SIGNUP")) {
	case "", "open":
	case "closed":
		cfg.signupClosed = true
	default:
		return config{}, errors.New(`ORUS_SIGNUP must be "open" or "closed"`)
	}
	return cfg, nil
}
