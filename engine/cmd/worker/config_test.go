package main

import (
	"strings"
	"testing"
	"time"
)

func env(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestLoadConfig(t *testing.T) {
	c, err := loadConfig(env(map[string]string{
		"ORUS_DATABASE_URL":   "postgres://localhost/orus",
		"ORUS_WORKER_ID":      "worker:a",
		"ORUS_WORKER_LEASE":   "10m",
		"ORUS_MODULE_TIMEOUT": "90s",
		"ORUS_POLL_INTERVAL":  "500ms",
	}))
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if c.databaseURL != "postgres://localhost/orus" || c.worker.ID != "worker:a" ||
		c.worker.Lease != 10*time.Minute || c.worker.ModuleTimeout != 90*time.Second ||
		c.worker.PollInterval != 500*time.Millisecond {
		t.Errorf("config = %+v", c)
	}
}

func TestLoadConfigDefaults(t *testing.T) {
	c, err := loadConfig(env(map[string]string{"ORUS_DATABASE_URL": "postgres://localhost/orus"}))
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if !strings.HasPrefix(c.worker.ID, "worker:") {
		t.Errorf("default ID = %q, want worker:<host>-<pid>", c.worker.ID)
	}
	if c.worker.Lease != 0 || c.worker.ModuleTimeout != 0 {
		t.Errorf("unset durations should stay zero for worker.New defaults: %+v", c.worker)
	}
}

func TestLoadConfigRejects(t *testing.T) {
	tests := []struct {
		name string
		env  map[string]string
		want string
	}{
		{"missing database URL", map[string]string{}, "ORUS_DATABASE_URL"},
		{"bad duration", map[string]string{"ORUS_DATABASE_URL": "x", "ORUS_WORKER_LEASE": "five"}, "ORUS_WORKER_LEASE"},
		{"negative duration", map[string]string{"ORUS_DATABASE_URL": "x", "ORUS_POLL_INTERVAL": "-1s"}, "ORUS_POLL_INTERVAL"},
		{"timeout longer than lease", map[string]string{
			"ORUS_DATABASE_URL": "x", "ORUS_WORKER_LEASE": "1m", "ORUS_MODULE_TIMEOUT": "2m",
		}, "shorter"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := loadConfig(env(tt.env))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("loadConfig = %v, want error mentioning %s", err, tt.want)
			}
		})
	}
}

func TestLoadConfigMail(t *testing.T) {
	base := map[string]string{"ORUS_DATABASE_URL": "postgres://x"}
	get := func(extra map[string]string) func(string) string {
		return func(k string) string {
			if v, ok := extra[k]; ok {
				return v
			}
			return base[k]
		}
	}
	c, err := loadConfig(get(nil))
	if err != nil || c.smtp != nil || c.publicURL != "http://localhost:5173" {
		t.Errorf("no mail: %+v, %v", c, err)
	}
	c, err = loadConfig(get(map[string]string{"ORUS_SMTP_ADDR": "127.0.0.1:1025", "ORUS_MAIL_FROM": "Orus <a@example.com>", "ORUS_PUBLIC_URL": "https://app.example"}))
	if err != nil || c.smtp == nil || c.publicURL != "https://app.example" {
		t.Errorf("mail: %+v, %v", c, err)
	}
	if _, err := loadConfig(get(map[string]string{"ORUS_SMTP_ADDR": "127.0.0.1:1025"})); err == nil {
		t.Error("SMTP without a sender: nil error")
	}
}
