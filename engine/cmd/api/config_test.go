package main

import (
	"slices"
	"testing"
)

func TestLoadConfig(t *testing.T) {
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

	const key = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=" // 32 bytes
	cfg, err := loadConfig(env(map[string]string{"ORUS_DATABASE_URL": "postgres://x", "ORUS_MFA_KEY": key}))
	if err != nil || cfg.addr != "127.0.0.1:8080" || len(cfg.trustedOrigins) != 0 || len(cfg.mfaKey) != 32 || cfg.mfaKey[31] != 31 {
		t.Errorf("defaults = %+v, %v", cfg, err)
	}
	cfg, err = loadConfig(env(map[string]string{
		"ORUS_DATABASE_URL": "postgres://x", "ORUS_API_ADDR": ":9000", "ORUS_MFA_KEY": key,
		"ORUS_API_TRUSTED_ORIGINS": " http://localhost:5173 , ,https://app.example",
	}))
	if err != nil || cfg.addr != ":9000" || !slices.Equal(cfg.trustedOrigins, []string{"http://localhost:5173", "https://app.example"}) {
		t.Errorf("config = %+v, %v", cfg, err)
	}
	if cfg.publicURL != "http://localhost:5173" || cfg.smtp != nil {
		t.Errorf("mail defaults: public URL %q, smtp %+v", cfg.publicURL, cfg.smtp)
	}
	cfg, err = loadConfig(env(map[string]string{
		"ORUS_DATABASE_URL": "postgres://x", "ORUS_MFA_KEY": key, "ORUS_PUBLIC_URL": "https://app.example/",
		"ORUS_SMTP_ADDR": "127.0.0.1:1025", "ORUS_MAIL_FROM": "Orus Shield <no-reply@app.example>",
	}))
	if err != nil || cfg.publicURL != "https://app.example" || cfg.smtp == nil || cfg.smtp.Addr != "127.0.0.1:1025" {
		t.Errorf("mail config = %+v, %v", cfg, err)
	}
	if cfg.signupClosed {
		t.Error("signup closed by default, want open")
	}
	if cfg, err = loadConfig(env(map[string]string{"ORUS_DATABASE_URL": "postgres://x", "ORUS_MFA_KEY": key, "ORUS_SIGNUP": "closed"})); err != nil || !cfg.signupClosed {
		t.Errorf("ORUS_SIGNUP=closed: %+v, %v", cfg.signupClosed, err)
	}
	for name, m := range map[string]map[string]string{
		"signup typo":         {"ORUS_DATABASE_URL": "postgres://x", "ORUS_MFA_KEY": key, "ORUS_SIGNUP": "yes"},
		"smtp without sender": {"ORUS_DATABASE_URL": "postgres://x", "ORUS_MFA_KEY": key, "ORUS_SMTP_ADDR": "127.0.0.1:1025"},
		"smtp without port":   {"ORUS_DATABASE_URL": "postgres://x", "ORUS_MFA_KEY": key, "ORUS_SMTP_ADDR": "smtp.example", "ORUS_MAIL_FROM": "a@example.com"},
		"bad public url":      {"ORUS_DATABASE_URL": "postgres://x", "ORUS_MFA_KEY": key, "ORUS_PUBLIC_URL": "app.example"},
		"no database":         {"ORUS_MFA_KEY": key},
		"bad address":         {"ORUS_DATABASE_URL": "postgres://x", "ORUS_API_ADDR": "8080", "ORUS_MFA_KEY": key},
		"no MFA key":          {"ORUS_DATABASE_URL": "postgres://x"},
		"short MFA key":       {"ORUS_DATABASE_URL": "postgres://x", "ORUS_MFA_KEY": "AAECAwQFBgcICQoLDA0ODw=="},
		"not base64":          {"ORUS_DATABASE_URL": "postgres://x", "ORUS_MFA_KEY": "not base64!"},
	} {
		if _, err := loadConfig(env(m)); err == nil {
			t.Errorf("%s: loadConfig = nil, want error", name)
		}
	}
}
