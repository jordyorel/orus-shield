package main

import (
	"slices"
	"testing"
)

func TestLoadConfig(t *testing.T) {
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

	cfg, err := loadConfig(env(map[string]string{"ORUS_DATABASE_URL": "postgres://x"}))
	if err != nil || cfg.addr != "127.0.0.1:8080" || len(cfg.trustedOrigins) != 0 {
		t.Errorf("defaults = %+v, %v", cfg, err)
	}
	cfg, err = loadConfig(env(map[string]string{
		"ORUS_DATABASE_URL": "postgres://x", "ORUS_API_ADDR": ":9000",
		"ORUS_API_TRUSTED_ORIGINS": " http://localhost:5173 , ,https://app.example",
	}))
	if err != nil || cfg.addr != ":9000" || !slices.Equal(cfg.trustedOrigins, []string{"http://localhost:5173", "https://app.example"}) {
		t.Errorf("config = %+v, %v", cfg, err)
	}
	for name, m := range map[string]map[string]string{
		"no database": {},
		"bad address": {"ORUS_DATABASE_URL": "postgres://x", "ORUS_API_ADDR": "8080"},
	} {
		if _, err := loadConfig(env(m)); err == nil {
			t.Errorf("%s: loadConfig = nil, want error", name)
		}
	}
}
