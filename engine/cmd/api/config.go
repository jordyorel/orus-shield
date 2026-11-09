package main

import (
	"errors"
	"net"
	"strings"
)

type config struct {
	databaseURL    string
	addr           string
	trustedOrigins []string
}

// loadConfig reads:
//
//	ORUS_DATABASE_URL         required
//	ORUS_API_ADDR             listen address, default 127.0.0.1:8080
//	ORUS_API_TRUSTED_ORIGINS  comma-separated origins allowed to send
//	                          state-changing requests besides the API's own
//	                          (e.g. http://localhost:5173 in development)
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
	for _, o := range strings.Split(getenv("ORUS_API_TRUSTED_ORIGINS"), ",") {
		if o = strings.TrimSpace(o); o != "" {
			cfg.trustedOrigins = append(cfg.trustedOrigins, o)
		}
	}
	return cfg, nil
}
