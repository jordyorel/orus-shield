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

func TestLoadConfigPaddle(t *testing.T) {
	base := map[string]string{"ORUS_DATABASE_URL": "postgres://x", "ORUS_MFA_KEY": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="}
	with := func(kv ...string) func(string) string {
		m := map[string]string{}
		for k, v := range base {
			m[k] = v
		}
		for i := 0; i+1 < len(kv); i += 2 {
			m[kv[i]] = kv[i+1]
		}
		return func(k string) string { return m[k] }
	}
	full := []string{"ORUS_PADDLE_API_KEY", "k", "ORUS_PADDLE_CLIENT_TOKEN", "t", "ORUS_PADDLE_WEBHOOK_SECRET", "s",
		"ORUS_PADDLE_PRICE_SME_MONTHLY", "p1", "ORUS_PADDLE_PRICE_SME_YEARLY", "p2", "ORUS_PADDLE_PRICE_PRO_MONTHLY", "p3", "ORUS_PADDLE_PRICE_PRO_YEARLY", "p4"}
	c, err := loadConfig(with(full...))
	if err != nil || !c.paddle.Enabled() || c.paddle.Environment != "sandbox" || c.paddle.Prices["pro/yearly"] != "p4" {
		t.Errorf("full = %+v, %v", c.paddle, err)
	}
	if c, err := loadConfig(with()); err != nil || c.paddle.Enabled() {
		t.Errorf("none = %+v, %v", c.paddle, err)
	}
	if _, err := loadConfig(with("ORUS_PADDLE_API_KEY", "k")); err == nil {
		t.Error("partial configuration accepted")
	}
	if _, err := loadConfig(with(append(full, "ORUS_PADDLE_ENVIRONMENT", "staging")...)); err == nil {
		t.Error("unknown environment accepted")
	}
}
