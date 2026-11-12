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

func TestLoadConfigDNS(t *testing.T) {
	get := func(v string) func(string) string {
		return func(k string) string {
			switch k {
			case "ORUS_DATABASE_URL":
				return "postgres://x"
			case "ORUS_DNS_SERVER":
				return v
			}
			return ""
		}
	}
	if c, err := loadConfig(get("")); err != nil || c.dns == nil {
		t.Errorf("default resolver: %+v, %v", c.dns, err)
	}
	if c, err := loadConfig(get("127.0.0.1:53")); err != nil || c.dns == nil {
		t.Errorf("ORUS_DNS_SERVER=127.0.0.1:53: %v", err)
	}
	if _, err := loadConfig(get("unbound.local")); err == nil {
		t.Error("ORUS_DNS_SERVER with a name: nil error")
	}
}

func TestLoadConfigNuclei(t *testing.T) {
	dir := t.TempDir()
	base := map[string]string{"ORUS_DATABASE_URL": "postgres://localhost/orus"}
	with := func(kv ...string) map[string]string {
		m := map[string]string{}
		for k, v := range base {
			m[k] = v
		}
		for i := 0; i < len(kv); i += 2 {
			m[kv[i]] = kv[i+1]
		}
		return m
	}
	c, err := loadConfig(env(with("ORUS_NUCLEI_BIN", dir, "ORUS_NUCLEI_TEMPLATES", dir)))
	if err != nil || c.nuclei.Binary != dir || c.nuclei.Templates != dir {
		t.Errorf("both set: %+v, %v", c.nuclei, err)
	}
	if c, err := loadConfig(env(base)); err != nil || c.nuclei.Binary != "" {
		t.Errorf("neither set: %+v, %v", c.nuclei, err)
	}
	for name, m := range map[string]map[string]string{
		"only the binary": with("ORUS_NUCLEI_BIN", dir),
		"relative path":   with("ORUS_NUCLEI_BIN", "bin/nuclei", "ORUS_NUCLEI_TEMPLATES", dir),
		"missing path":    with("ORUS_NUCLEI_BIN", dir+"/nope", "ORUS_NUCLEI_TEMPLATES", dir),
	} {
		if _, err := loadConfig(env(m)); err == nil {
			t.Errorf("%s: nil error", name)
		}
	}
}
