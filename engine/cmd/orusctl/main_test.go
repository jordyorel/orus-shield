package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jordyorel/orus-shield/engine/internal/asset"
	"github.com/jordyorel/orus-shield/engine/internal/finding"
	"github.com/jordyorel/orus-shield/engine/internal/module"
	"github.com/jordyorel/orus-shield/engine/internal/ownership"
	"github.com/jordyorel/orus-shield/engine/internal/plan"
	"github.com/jordyorel/orus-shield/engine/internal/posture"
	"github.com/jordyorel/orus-shield/engine/internal/store"
)

type fakeStore struct {
	targets   map[string]store.Target // by domain
	created   []store.NewTarget
	enqueued  []string // "targetID modules requester"
	findings  []finding.Finding
	audit     []store.AuditEntry
	verifier  *fakeVerifier                   // the verifier opened with this organization
	history   map[string][]store.FindingEvent // by finding ID
	assets    []store.Asset
	assetsAll bool // includeGone of the last ListAssets call
	checks    []store.CheckState
	snapshots []store.PostureSnapshot // newest first
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

func (f *fakeStore) FindingHistory(ctx context.Context, targetID, findingID string) ([]store.FindingEvent, error) {
	return f.history[findingID], nil
}

func (f *fakeStore) ListAssets(ctx context.Context, targetID string, includeGone bool) ([]store.Asset, error) {
	f.assetsAll = includeGone
	return f.assets, nil
}

func (f *fakeStore) CheckStatuses(ctx context.Context, targetID string) ([]store.CheckState, error) {
	return f.checks, nil
}

func (f *fakeStore) PostureHistory(ctx context.Context, targetID string, limit int) ([]store.PostureSnapshot, error) {
	return f.snapshots, nil
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

// fakeAdmin manages organizations in memory.
type fakeAdmin struct {
	created []string // "name actor"
	subs    map[string]plan.Subscription
}

func (f *fakeAdmin) SubscriptionOf(ctx context.Context, orgID string) (*plan.Subscription, error) {
	if sub, ok := f.subs[orgID]; ok {
		return &sub, nil
	}
	return nil, nil
}

func (f *fakeAdmin) SetSubscription(ctx context.Context, orgID string, sub plan.Subscription, provider, actor string) error {
	if f.subs == nil {
		f.subs = map[string]plan.Subscription{}
	}
	f.subs[orgID] = sub
	f.created = append(f.created, "plan "+orgID+" "+string(sub.Plan)+" "+string(sub.Status)+" "+provider+" "+actor)
	return nil
}

func (f *fakeAdmin) CreateOrganization(ctx context.Context, name, actor string) (store.Organization, error) {
	f.created = append(f.created, name+" "+actor)
	return store.Organization{ID: "o-2", Name: name}, nil
}

func (f *fakeAdmin) CreateUser(ctx context.Context, email string) (store.User, error) {
	f.created = append(f.created, "user "+email)
	return store.User{ID: "u-1", Email: email}, nil
}

func (f *fakeAdmin) UserByEmail(ctx context.Context, email string) (store.User, error) {
	if email != "alice@example.com" {
		return store.User{}, store.ErrNotFound
	}
	return store.User{ID: "u-1", Email: email}, nil
}

func (f *fakeAdmin) SetMembership(ctx context.Context, userID, orgID, role, actor string) error {
	f.created = append(f.created, "member "+userID+" "+orgID+" "+role+" "+actor)
	return nil
}

func (f *fakeAdmin) IssueSetupToken(ctx context.Context, userID string, ttl time.Duration, actor string) (string, error) {
	f.created = append(f.created, "token "+userID)
	return "secret-setup-token", nil
}

func (f *fakeAdmin) ResetMFA(ctx context.Context, userID, actor string) error {
	f.created = append(f.created, "reset-mfa "+userID+" "+actor)
	return nil
}

func (f *fakeAdmin) ListOrganizations(ctx context.Context) ([]store.Organization, error) {
	return []store.Organization{{ID: "o-1", Name: "Default", CreatedAt: time.Date(2026, 11, 9, 0, 0, 0, 0, time.UTC)}}, nil
}

// opened records which organizations commands asked for.
type opened struct{ refs []string }

func newCLI() (cli, *fakeStore, *bytes.Buffer) {
	c, st, _, out := newCLIWithOrgs()
	return c, st, out
}

// newCLIWithOrgs knows two organizations: "Default" (o-1) and "Acme" (o-2).
// Only Default has the example.com target.
func newCLIWithOrgs() (cli, *fakeStore, *opened, *bytes.Buffer) {
	st := &fakeStore{targets: map[string]store.Target{
		"example.com": {ID: "t-1", Domain: "example.com", RatePerSec: 5, Exclusions: json.RawMessage("{}")},
	}}
	out := &bytes.Buffer{}
	expires := time.Date(2026, 11, 16, 10, 0, 0, 0, time.UTC)
	v := &fakeVerifier{in: ownership.Instructions{
		Domain: "example.com", RecordName: "_orus-verify.example.com",
		RecordValue: "orus-verify=abc123", ExpiresAt: &expires,
	}}
	st.verifier = v
	op := &opened{}
	open := func(ctx context.Context, ref string) (store.Organization, OrgStore, Verifier, error) {
		op.refs = append(op.refs, ref)
		switch ref {
		case "Default", "o-1":
			return store.Organization{ID: "o-1", Name: "Default"}, st, v, nil
		case "Acme", "o-2":
			return store.Organization{ID: "o-2", Name: "Acme"}, &fakeStore{}, v, nil
		}
		return store.Organization{}, nil, nil, store.ErrNotFound
	}
	c := cli{
		admin: &fakeAdmin{}, openOrg: open, out: out, modules: []string{"email", "tls"},
		defaultActor: "cli:jordy", defaultOrg: "Default",
	}
	return c, st, op, out
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
	c, st, out := newCLI()
	if err := c.run(context.Background(), []string{"target", "verify-token", "example.com"}); err != nil {
		t.Fatalf("run: %v", err)
	}
	for _, want := range []string{"_orus-verify.example.com", "TXT", "orus-verify=abc123", "orusctl target verify example.com"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output does not contain %q:\n%s", want, out.String())
		}
	}
	if calls := st.verifier.calls; len(calls) != 1 || calls[0] != "instructions t-1 cli:jordy" {
		t.Errorf("verifier calls = %v", calls)
	}
}

func TestVerify(t *testing.T) {
	c, st, out := newCLI()
	if err := c.run(context.Background(), []string{"target", "verify", "-as", "alice", "example.com"}); err != nil {
		t.Fatalf("run: %v", err)
	}
	if !strings.Contains(out.String(), "is verified") {
		t.Errorf("output = %q", out.String())
	}
	if calls := st.verifier.calls; len(calls) != 1 || calls[0] != "verify t-1 alice" {
		t.Errorf("verifier calls = %v", calls)
	}

	c, st, out = newCLI()
	st.verifier.verifyErr = ownership.ErrRecordMissing
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

func TestOrgAdd(t *testing.T) {
	c, _, _, out := newCLIWithOrgs()
	if err := c.run(context.Background(), []string{"org", "add", "-as", "alice", "Acme", "SARL"}); err != nil {
		t.Fatal(err)
	}
	if got := c.admin.(*fakeAdmin).created; len(got) != 1 || got[0] != "Acme SARL alice" {
		t.Errorf("created = %v", got)
	}
	if !strings.Contains(out.String(), `"Acme SARL" created (id o-2)`) {
		t.Errorf("output = %q", out.String())
	}
	for _, args := range [][]string{{"org"}, {"org", "add"}, {"org", "remove", "x"}} {
		if err := c.run(context.Background(), args); !errors.Is(err, errUsage) {
			t.Errorf("run(%v) = %v, want errUsage", args, err)
		}
	}
}

func TestOrgList(t *testing.T) {
	c, _, _, out := newCLIWithOrgs()
	if err := c.run(context.Background(), []string{"org", "list"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "o-1") || !strings.Contains(out.String(), "Default") {
		t.Errorf("output = %q", out.String())
	}
}

// Every target command works in the organization given by -org, else the
// default one, and never sees another organization's targets.
func TestOrgFlag(t *testing.T) {
	ctx := context.Background()
	commands := [][]string{
		{"target", "show"}, {"target", "verify-token"}, {"target", "verify"},
		{"scan"}, {"findings"}, {"assets"}, {"posture"},
	}
	for _, cmd := range commands {
		name := strings.Join(cmd, " ")
		t.Run(name, func(t *testing.T) {
			c, _, op, _ := newCLIWithOrgs()
			args := append(append([]string{}, cmd...), "example.com")
			if err := c.run(ctx, args); err != nil {
				t.Fatalf("in the default organization: %v", err)
			}
			args = append(append(append([]string{}, cmd...), "-org", "Acme"), "example.com")
			if err := c.run(ctx, args); !errors.Is(err, store.ErrNotFound) {
				t.Errorf("in Acme, which has no such target: %v, want ErrNotFound", err)
			}
			args = append(append(append([]string{}, cmd...), "-org", "Nobody"), "example.com")
			if err := c.run(ctx, args); !errors.Is(err, store.ErrNotFound) {
				t.Errorf("in an unknown organization: %v, want ErrNotFound", err)
			}
			if want := []string{"Default", "Acme", "Nobody"}; strings.Join(op.refs, ",") != strings.Join(want, ",") {
				t.Errorf("organizations opened = %v, want %v", op.refs, want)
			}
		})
	}
}

func TestVerifyTokenHintNamesNonDefaultOrg(t *testing.T) {
	c, _, _, out := newCLIWithOrgs()
	c.defaultOrg = "Acme" // as if ORUS_ORG=Acme; example.com is in Default
	if err := c.run(context.Background(), []string{"target", "verify-token", "-org", "Default", "example.com"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "orusctl target verify -org Default example.com") {
		t.Errorf("output = %q", out.String())
	}
}

func TestFindingsShowFixDateAndHistory(t *testing.T) {
	c, st, out := newCLI()
	fixed := time.Date(2026, 11, 3, 10, 0, 0, 0, time.UTC)
	st.findings = []finding.Finding{{
		ID: "f1", Severity: finding.SeverityHigh, Status: finding.StatusFixed, FixedAt: &fixed,
		ModuleID: "email", CheckID: "spf-missing", Asset: "example.com", Title: "No SPF record",
		Description: "No SPF.",
	}}
	st.history = map[string][]store.FindingEvent{"f1": {
		{At: time.Date(2026, 11, 1, 10, 0, 0, 0, time.UTC), To: finding.StatusOpen},
		{At: fixed, From: finding.StatusOpen, To: finding.StatusFixed},
	}}
	if err := c.run(context.Background(), []string{"findings", "example.com"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "fixed 2026-11-03") {
		t.Errorf("table output does not show the fix date:\n%s", out.String())
	}
	out.Reset()
	if err := c.run(context.Background(), []string{"findings", "-v", "example.com"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "history: opened 2026-11-01, fixed 2026-11-03") {
		t.Errorf("verbose output does not show the history:\n%s", out.String())
	}
}

func TestAssets(t *testing.T) {
	c, st, out := newCLI()
	if err := c.run(context.Background(), []string{"assets", "example.com"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "no assets") {
		t.Errorf("empty output = %q", out.String())
	}
	day := time.Date(2026, 11, 1, 10, 0, 0, 0, time.UTC)
	gone := day.Add(48 * time.Hour)
	st.assets = []store.Asset{
		{Kind: asset.KindIP, Value: "192.0.2.10", Sources: []string{"tls", "ports"}, FirstSeen: day, LastSeen: day},
		{Kind: asset.KindService, Value: "192.0.2.10:22/tcp", Details: map[string]string{"expected": "SSH"},
			FirstSeen: day, LastSeen: day, GoneAt: &gone},
	}
	out.Reset()
	if err := c.run(context.Background(), []string{"assets", "-all", "example.com"}); err != nil {
		t.Fatal(err)
	}
	if !st.assetsAll {
		t.Error("-all did not ask for gone assets")
	}
	for _, want := range []string{"tls,ports", "gone 2026-11-03", "expected=SSH", "192.0.2.10:22/tcp"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output does not contain %q:\n%s", want, out.String())
		}
	}
}

func TestPosture(t *testing.T) {
	c, st, out := newCLI()
	if err := c.run(context.Background(), []string{"posture", "example.com"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "no posture yet") {
		t.Errorf("empty output = %q", out.String())
	}

	day := time.Date(2026, 11, 2, 10, 0, 0, 0, time.UTC)
	latest := posture.Compute([]posture.Check{
		{ID: "spf-missing", Category: module.CategoryEmail, Severity: finding.SeverityHigh, Status: module.CheckPassed},
		{ID: "tls-cert-expired", Category: module.CategoryTLS, Severity: finding.SeverityCritical, Status: module.CheckFailed},
	})
	st.snapshots = []store.PostureSnapshot{
		{At: day, Score: latest.Score, Details: latest},
		{At: day.Add(-24 * time.Hour), Score: nil},
	}
	st.checks = []store.CheckState{{CheckID: "tls-cert-expired", ModuleID: "tls", Severity: finding.SeverityCritical,
		Status: module.CheckFailed, EvaluatedAt: day}}
	out.Reset()
	if err := c.run(context.Background(), []string{"posture", "-v", "example.com"}); err != nil {
		t.Fatal(err)
	}
	// 6 / 16 = 38
	for _, want := range []string{"score: 38/100", "1 passed, 1 failed", "failed: tls-cert-expired",
		"history: 2026-11-01 none, 2026-11-02 38/100", "tls-cert-expired  tls"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output does not contain %q:\n%s", want, out.String())
		}
	}
}

func TestUserAdd(t *testing.T) {
	c, _, _, out := newCLIWithOrgs()
	if err := c.run(context.Background(), []string{"user", "add", "-org", "Acme", "-role", "admin", "alice@example.com"}); err != nil {
		t.Fatal(err)
	}
	got := strings.Join(c.admin.(*fakeAdmin).created, "; ")
	if got != "user alice@example.com; member u-1 o-2 admin cli:jordy; token u-1" {
		t.Errorf("calls = %s", got)
	}
	if !strings.Contains(out.String(), "secret-setup-token") || !strings.Contains(out.String(), "admin of Acme") {
		t.Errorf("output = %q", out.String())
	}
	if err := c.run(context.Background(), []string{"user", "add", "-role", "owner", "bob@example.com"}); !errors.Is(err, errUsage) {
		t.Errorf("unknown role = %v, want errUsage", err)
	}
}

func TestUserResetAndMember(t *testing.T) {
	c, _, _, out := newCLIWithOrgs()
	if err := c.run(context.Background(), []string{"user", "reset", "alice@example.com"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "secret-setup-token") {
		t.Errorf("output = %q", out.String())
	}
	if err := c.run(context.Background(), []string{"user", "member", "-role", "viewer", "alice@example.com"}); err != nil {
		t.Fatal(err)
	}
	if got := c.admin.(*fakeAdmin).created; got[len(got)-1] != "member u-1 o-1 viewer cli:jordy" {
		t.Errorf("calls = %v", got)
	}
	if err := c.run(context.Background(), []string{"user", "reset", "nobody@example.com"}); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("unknown user = %v, want ErrNotFound", err)
	}
}

func TestUserResetMFA(t *testing.T) {
	c, _, _, out := newCLIWithOrgs()
	if err := c.run(context.Background(), []string{"user", "reset-mfa", "-as", "support:ticket-42", "alice@example.com"}); err != nil {
		t.Fatal(err)
	}
	if got := c.admin.(*fakeAdmin).created; len(got) != 1 || got[0] != "reset-mfa u-1 support:ticket-42" {
		t.Errorf("calls = %v", got)
	}
	if !strings.Contains(out.String(), "alice@example.com") {
		t.Errorf("output = %q", out.String())
	}
	if err := c.run(context.Background(), []string{"user", "reset-mfa", "nobody@example.com"}); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("unknown user = %v, want ErrNotFound", err)
	}
}

func TestOrgPlan(t *testing.T) {
	ctx := context.Background()
	c, _, _, out := newCLIWithOrgs()
	admin := c.admin.(*fakeAdmin)

	if err := c.run(ctx, []string{"org", "plan"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "Default: offer Gratuit (discovery), subscription none") {
		t.Errorf("show = %q", out.String())
	}

	out.Reset()
	if err := c.run(ctx, []string{"org", "plan", "-org", "Acme", "Pro"}); err != nil {
		t.Fatal(err)
	}
	if sub := admin.subs["o-2"]; sub.Plan != plan.Pro || sub.Status != plan.Active || sub.PeriodEnd != nil {
		t.Errorf("pro = %+v", sub)
	}
	if !strings.Contains(out.String(), "Acme: offer Pro set, without end") || !slices.Contains(admin.created, "plan o-2 pro active manual cli:jordy") {
		t.Errorf("output %q, calls %v", out.String(), admin.created)
	}

	out.Reset()
	until := time.Now().AddDate(0, 1, 0).Format(time.DateOnly)
	if err := c.run(ctx, []string{"org", "plan", "-until", until, "essentiel"}); err != nil {
		t.Fatal(err)
	}
	if sub := admin.subs["o-1"]; sub.Plan != plan.SME || sub.PeriodEnd == nil || sub.PeriodEnd.Format(time.DateOnly) <= until {
		t.Errorf("paid period = %+v", sub)
	}

	if err := c.run(ctx, []string{"org", "plan", "-trial", "14", "sur-devis"}); err != nil {
		t.Fatal(err)
	}
	if sub := admin.subs["o-1"]; sub.Plan != plan.Enterprise || sub.Status != plan.Trialing || sub.TrialEndsAt == nil {
		t.Errorf("trial = %+v", sub)
	}

	for _, args := range [][]string{
		{"org", "plan", "gold"},
		{"org", "plan", "-trial", "7", "-until", until, "pro"},
		{"org", "plan", "-until", "2020-01-01", "pro"},
		{"org", "plan", "-until", "tomorrow", "pro"},
		{"org", "plan", "-trial", "365", "pro"},
	} {
		if err := c.run(ctx, args); !errors.Is(err, errUsage) {
			t.Errorf("run(%v) = %v, want errUsage", args, err)
		}
	}
}
