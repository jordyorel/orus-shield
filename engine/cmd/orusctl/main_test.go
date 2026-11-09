package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jordyorel/orus-shield/engine/internal/finding"
	"github.com/jordyorel/orus-shield/engine/internal/ownership"
	"github.com/jordyorel/orus-shield/engine/internal/store"
)

type fakeStore struct {
	targets  map[string]store.Target // by domain
	created  []store.NewTarget
	enqueued []string // "targetID modules requester"
	findings []finding.Finding
	audit    []store.AuditEntry
}

func (f *fakeStore) CreateTarget(ctx context.Context, nt store.NewTarget) (store.Target, error) {
	f.created = append(f.created, nt)
	t := store.Target{ID: "t-1", Domain: nt.Domain, RatePerSec: nt.RatePerSec, Exclusions: nt.Exclusions}
	return t, nil
}

func (f *fakeStore) TargetByDomain(ctx context.Context, domain string) (store.Target, error) {
	t, ok := f.targets[domain]
	if !ok {
		return store.Target{}, store.ErrNotFound
	}
	return t, nil
}

func (f *fakeStore) EnqueueScan(ctx context.Context, targetID string, modules []string, requestedBy string) (store.Scan, error) {
	f.enqueued = append(f.enqueued, targetID+" "+strings.Join(modules, ",")+" "+requestedBy)
	return store.Scan{ID: "s-1", Modules: modules}, nil
}

func (f *fakeStore) GetScan(ctx context.Context, id string) (store.Scan, error) {
	if id != "s-1" {
		return store.Scan{}, store.ErrNotFound
	}
	return store.Scan{ID: "s-1", Domain: "example.com", Status: store.StatusDone,
		Modules: []string{"email", "tls"}, RequestedBy: "cli:jordy", Attempt: 1, Error: "tls: timeout"}, nil
}

func (f *fakeStore) ListFindings(ctx context.Context, targetID string) ([]finding.Finding, error) {
	return f.findings, nil
}

func (f *fakeStore) AuditLog(ctx context.Context, target string) ([]store.AuditEntry, error) {
	return f.audit, nil
}

// fakeVerifier records calls and returns fixed answers.
type fakeVerifier struct {
	in        ownership.Instructions
	verifyErr error
	calls     []string
}

func (f *fakeVerifier) Instructions(ctx context.Context, targetID, actor string) (ownership.Instructions, error) {
	f.calls = append(f.calls, "instructions "+targetID+" "+actor)
	return f.in, nil
}

func (f *fakeVerifier) Verify(ctx context.Context, targetID, actor string) error {
	f.calls = append(f.calls, "verify "+targetID+" "+actor)
	return f.verifyErr
}

func newCLI() (cli, *fakeStore, *bytes.Buffer) {
	st := &fakeStore{targets: map[string]store.Target{
		"example.com": {ID: "t-1", Domain: "example.com", RatePerSec: 5, Exclusions: json.RawMessage("{}")},
	}}
	out := &bytes.Buffer{}
	expires := time.Date(2026, 11, 16, 10, 0, 0, 0, time.UTC)
	v := &fakeVerifier{in: ownership.Instructions{
		Domain: "example.com", RecordName: "_orus-verify.example.com",
		RecordValue: "orus-verify=abc123", ExpiresAt: &expires,
	}}
	return cli{st: st, verifier: v, out: out, modules: []string{"email", "tls"}, defaultActor: "cli:jordy"}, st, out
}

func TestUsageErrors(t *testing.T) {
	for _, args := range [][]string{
		nil,
		{"bogus"},
		{"target"},
		{"target", "remove", "example.com"},
		{"target", "add"},
		{"scan"},
		{"findings", "-x", "example.com"},
		{"status"},
	} {
		c, _, _ := newCLI()
		if err := c.run(context.Background(), args); !errors.Is(err, errUsage) {
			t.Errorf("run(%q) = %v, want a usage error", args, err)
		}
	}
}

func TestTargetAdd(t *testing.T) {
	c, st, out := newCLI()
	err := c.run(context.Background(), []string{"target", "add", "-rate", "2", "-exclusions", `{"ips": ["192.0.2.10"]}`, "new.example"})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(st.created) != 1 || st.created[0].RatePerSec != 2 || string(st.created[0].Exclusions) != `{"ips": ["192.0.2.10"]}` {
		t.Errorf("created = %+v", st.created)
	}
	if !strings.Contains(out.String(), "not verified") {
		t.Errorf("output = %q", out.String())
	}
}

// Exclusions are checked with the worker's parser before anything is stored.
func TestTargetAddRejectsBadExclusions(t *testing.T) {
	c, st, _ := newCLI()
	err := c.run(context.Background(), []string{"target", "add", "-exclusions", `{"ip": ["192.0.2.10"]}`, "new.example"})
	if err == nil {
		t.Fatal("run = nil, want error for unknown field \"ip\"")
	}
	if len(st.created) != 0 {
		t.Error("target was stored despite invalid exclusions")
	}
}

func TestScan(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{"every module by default", []string{"scan", "example.com"}, "t-1 email,tls cli:jordy"},
		{"chosen module", []string{"scan", "example.com", "tls"}, "t-1 tls cli:jordy"},
		{"custom requester", []string{"scan", "-as", "alice", "example.com", "email"}, "t-1 email alice"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, st, out := newCLI()
			if err := c.run(context.Background(), tt.args); err != nil {
				t.Fatalf("run: %v", err)
			}
			if len(st.enqueued) != 1 || st.enqueued[0] != tt.want {
				t.Errorf("enqueued = %v, want %q", st.enqueued, tt.want)
			}
			if !strings.Contains(out.String(), "not verified") {
				t.Errorf("output %q should warn that the target is not verified", out.String())
			}
		})
	}
}

func TestScanRejects(t *testing.T) {
	c, st, _ := newCLI()
	if err := c.run(context.Background(), []string{"scan", "example.com", "nmap"}); err == nil || !strings.Contains(err.Error(), "unknown module") {
		t.Errorf("unknown module: %v", err)
	}
	if err := c.run(context.Background(), []string{"scan", "missing.example"}); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("unknown target: %v, want ErrNotFound", err)
	}
	if len(st.enqueued) != 0 {
		t.Errorf("enqueued = %v, want nothing", st.enqueued)
	}
}

func TestStatus(t *testing.T) {
	c, _, out := newCLI()
	if err := c.run(context.Background(), []string{"status", "s-1"}); err != nil {
		t.Fatalf("run: %v", err)
	}
	for _, want := range []string{"done", "cli:jordy", "tls: timeout"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output does not contain %q:\n%s", want, out.String())
		}
	}
}

func TestFindings(t *testing.T) {
	c, st, out := newCLI()
	if err := c.run(context.Background(), []string{"findings", "example.com"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "no findings") {
		t.Errorf("empty output = %q", out.String())
	}

	st.findings = []finding.Finding{{
		Severity: finding.SeverityHigh, Status: finding.StatusOpen, ModuleID: "email",
		CheckID: "dmarc-missing", Asset: "_dmarc.example.com", Title: "No DMARC record",
		Description: "The domain publishes no DMARC policy.", Evidence: "NXDOMAIN",
		Remediation: []string{"Publish a DMARC record."},
	}}
	out.Reset()
	if err := c.run(context.Background(), []string{"findings", "example.com"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "dmarc-missing") || strings.Contains(out.String(), "NXDOMAIN") {
		t.Errorf("table output = %q", out.String())
	}

	out.Reset()
	if err := c.run(context.Background(), []string{"findings", "-v", "example.com"}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"NXDOMAIN", "fix 1: Publish a DMARC record."} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("verbose output does not contain %q:\n%s", want, out.String())
		}
	}
}

func TestAudit(t *testing.T) {
	c, st, out := newCLI()
	st.audit = []store.AuditEntry{{
		At: time.Date(2026, 11, 9, 10, 0, 0, 0, time.UTC), Actor: "cli:jordy",
		Action: store.ActionScanRequested, Target: "example.com",
		Details: json.RawMessage(`{"modules":["email"]}`),
	}}
	if err := c.run(context.Background(), []string{"audit", "example.com"}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"cli:jordy", "scan.requested", `{"modules":["email"]}`} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output does not contain %q:\n%s", want, out.String())
		}
	}
}

func TestDefaultActor(t *testing.T) {
	if got := defaultActor(func(string) string { return "jordy" }); got != "cli:jordy" {
		t.Errorf("defaultActor = %q", got)
	}
	if got := defaultActor(func(string) string { return "" }); got != "cli:unknown" {
		t.Errorf("defaultActor without USER = %q", got)
	}
}

func TestVerifyToken(t *testing.T) {
	c, _, out := newCLI()
	if err := c.run(context.Background(), []string{"target", "verify-token", "example.com"}); err != nil {
		t.Fatalf("run: %v", err)
	}
	for _, want := range []string{"_orus-verify.example.com", "TXT", "orus-verify=abc123", "orusctl target verify example.com"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output does not contain %q:\n%s", want, out.String())
		}
	}
	if calls := c.verifier.(*fakeVerifier).calls; len(calls) != 1 || calls[0] != "instructions t-1 cli:jordy" {
		t.Errorf("verifier calls = %v", calls)
	}
}

func TestVerify(t *testing.T) {
	c, _, out := newCLI()
	if err := c.run(context.Background(), []string{"target", "verify", "-as", "alice", "example.com"}); err != nil {
		t.Fatalf("run: %v", err)
	}
	if !strings.Contains(out.String(), "is verified") {
		t.Errorf("output = %q", out.String())
	}
	if calls := c.verifier.(*fakeVerifier).calls; len(calls) != 1 || calls[0] != "verify t-1 alice" {
		t.Errorf("verifier calls = %v", calls)
	}

	c, _, out = newCLI()
	c.verifier.(*fakeVerifier).verifyErr = ownership.ErrRecordMissing
	if err := c.run(context.Background(), []string{"target", "verify", "example.com"}); !errors.Is(err, ownership.ErrRecordMissing) {
		t.Errorf("run = %v, want ErrRecordMissing", err)
	}
	if strings.Contains(out.String(), "is verified") {
		t.Error("printed success on failure")
	}
}

func TestTargetShowVerification(t *testing.T) {
	c, st, out := newCLI()
	expires := time.Date(2026, 11, 16, 10, 0, 0, 0, time.UTC)
	tg := st.targets["example.com"]
	tg.VerifyToken, tg.VerifyTokenExpiresAt = "abc", &expires
	st.targets["example.com"] = tg
	if err := c.run(context.Background(), []string{"target", "show", "example.com"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "token pending until 2026-11-16") {
		t.Errorf("output = %q", out.String())
	}
}
