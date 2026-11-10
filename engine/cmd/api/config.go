package main

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/jordyorel/orus-shield/engine/internal/seal"
)

type config struct {
	databaseURL    string
	addr           string
	trustedOrigins []string
	mfaKey         []byte
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
	for _, o := range strings.Split(getenv("ORUS_API_TRUSTED_ORIGINS"), ",") {
		if o = strings.TrimSpace(o); o != "" {
			cfg.trustedOrigins = append(cfg.trustedOrigins, o)
		}
	}
	return cfg, nil
}
