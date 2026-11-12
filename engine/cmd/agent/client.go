package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// Config is the agent's configuration file.
type Config struct {
	API     string   `json:"api"`
	AgentID string   `json:"agent_id"`
	Token   string   `json:"token"`
	Ranges  []string `json:"ranges"`
}

// defaultConfigPath is where the agent keeps its configuration: a
// system-wide place, readable by the service's account only.
// ORUS_AGENT_CONFIG overrides it (the systemd unit passes the file as a
// credential).
func defaultConfigPath() string {
	if p := os.Getenv("ORUS_AGENT_CONFIG"); p != "" {
		return p
	}
	if runtime.GOOS == "windows" {
		base := os.Getenv("ProgramData")
		if base == "" {
			base = `C:\ProgramData`
		}
		return filepath.Join(base, "OrusAgent", "config.json")
	}
	return "/etc/orus-agent/config.json"
}

func saveConfig(path string, c Config) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("save configuration: %w", err)
	}
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	// The token lets anyone act as this agent: owner only.
	if err := os.WriteFile(path, b, 0o600); err != nil {
		return fmt.Errorf("save configuration: %w", err)
	}
	return nil
}

func loadConfig(path string) (Config, error) {
	b, err := os.ReadFile(path) //nolint:gosec // G304: the operator's configuration path
	if err != nil {
		return Config{}, fmt.Errorf("read configuration (run enroll first): %w", err)
	}
	var c Config
	if err := json.Unmarshal(b, &c); err != nil || c.API == "" || c.Token == "" {
		return Config{}, fmt.Errorf("configuration %s is incomplete: enroll again", path)
	}
	return c, nil
}

// client calls the API's agent endpoints.
type client struct {
	base  string
	token string
	http  *http.Client
}

func newClient(base, token string) *client {
	return &client{base: strings.TrimRight(base, "/"), token: token, http: &http.Client{Timeout: 60 * time.Second}}
}

// errStatus is a non-2xx answer.
type errStatus struct {
	code int
	msg  string
}

func (e *errStatus) Error() string { return fmt.Sprintf("API answered %d: %s", e.code, e.msg) }

// maxAnswer bounds what we read from the API.
const maxAnswer = 1 << 20

// do sends body as JSON and decodes the answer into out (if any). It
// returns the status code.
func (c *client) do(ctx context.Context, path string, body, out any) (int, error) {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return 0, err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+path, rd)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "orus-agent/"+version)
	req.Header.Set("X-Orus-Agent-Version", version)
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxAnswer))
	if err != nil {
		return resp.StatusCode, err
	}
	if resp.StatusCode >= 300 {
		var e struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(data, &e)
		return resp.StatusCode, &errStatus{code: resp.StatusCode, msg: e.Error}
	}
	if out != nil && resp.StatusCode != http.StatusNoContent {
		if err := json.Unmarshal(data, out); err != nil {
			return resp.StatusCode, fmt.Errorf("unreadable answer: %w", err)
		}
	}
	return resp.StatusCode, nil
}

// enrol exchanges the one-time code for the agent's token.
func enrol(ctx context.Context, c *client, code string) (Config, error) {
	host, _ := os.Hostname()
	var out struct {
		AgentID string   `json:"agent_id"`
		Token   string   `json:"token"`
		Ranges  []string `json:"ranges"`
	}
	_, err := c.do(ctx, "/api/v1/agent/enroll", map[string]string{
		"code": strings.TrimSpace(code), "hostname": host, "os": runtime.GOOS + "/" + runtime.GOARCH, "version": version,
	}, &out)
	var es *errStatus
	if errors.As(err, &es) && es.code == http.StatusUnauthorized {
		return Config{}, errors.New("this code is invalid, expired or already used: create a new one in the dashboard")
	}
	if err != nil {
		return Config{}, fmt.Errorf("enrol: %w", err)
	}
	return Config{AgentID: out.AgentID, Token: out.Token, Ranges: out.Ranges}, nil
}
