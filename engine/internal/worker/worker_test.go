package worker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jordyorel/orus-shield/engine/internal/asset"
	"github.com/jordyorel/orus-shield/engine/internal/finding"
	"github.com/jordyorel/orus-shield/engine/internal/module"
	"github.com/jordyorel/orus-shield/engine/internal/ownership"
	"github.com/jordyorel/orus-shield/engine/internal/store"
)

// ---- Fakes ----------------------------------------------------------------

type fakeStore struct {
	mu        sync.Mutex
	queue     []store.Scan
	targets   map[string]store.Target
	finished  []store.ScanResult
	failed    []string // reasons
	audit     []store.AuditEntry
	leaseLost bool // ExtendLease reports the lease as lost
	extended  int

	hostnames     []string // the inventory's current hostnames
	scheduleCalls []time.Time
	scheduleErr   error
}

func (f *fakeStore) ClaimScan(ctx context.Context, workerID string, lease time.Duration, maxAttempts int) (store.Scan, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.queue) == 0 {
		return store.Scan{}, false, nil
	}
	sc := f.queue[0]
	f.queue = f.queue[1:]
	sc.Attempt++
	return sc, true, nil
}

func (f *fakeStore) GetTarget(ctx context.Context, id string) (store.Target, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	t, ok := f.targets[id]
	if !ok {
		return store.Target{}, store.ErrNotFound
	}
	return t, nil
}

func (f *fakeStore) ExtendLease(ctx context.Context, scanID string, attempt int, lease time.Duration) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.extended++
	if f.leaseLost {
		return store.ErrLeaseLost
	}
	return nil
}

func (f *fakeStore) EnqueueDueScans(ctx context.Context, now time.Time, limit int) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.scheduleCalls = append(f.scheduleCalls, now)
	return 0, f.scheduleErr
}

func (f *fakeStore) CurrentHostnames(ctx context.Context, targetID string) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.hostnames, nil
}

func (f *fakeStore) FinishScan(ctx context.Context, r store.ScanResult) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.finished = append(f.finished, r)
	return nil
}

func (f *fakeStore) FailScan(ctx context.Context, scanID string, attempt int, workerID, reason string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failed = append(f.failed, reason)
	return nil
}

func (f *fakeStore) AppendAudit(ctx context.Context, e store.AuditEntry) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.audit = append(f.audit, e)
	return nil
}

// fakeModule returns the findings run returns, plus assets, and counts its
// runs.
type fakeModule struct {
	info      module.Info
	runs      atomic.Int32
	run       func(ctx context.Context, req module.Request) ([]finding.Finding, error)
	assets    []asset.Asset
	evaluated []string
	unreached []string
}

func (m *fakeModule) Info() module.Info { return m.info }

func (m *fakeModule) Run(ctx context.Context, req module.Request) (module.Result, error) {
	m.runs.Add(1)
	if m.run == nil {
		return module.Result{Assets: m.assets, Evaluated: m.evaluated, Unreached: m.unreached}, nil
	}
	findings, err := m.run(ctx, req)
	return module.Result{Findings: findings, Assets: m.assets, Evaluated: m.evaluated, Unreached: m.unreached}, err
}

func newModule(id string, kind module.Kind, run func(context.Context, module.Request) ([]finding.Finding, error)) *fakeModule {
	checks := []module.Check{{ID: id + "-check", Category: module.CategoryTLS, Severity: finding.SeverityMedium, Title: "A check"}}
	return &fakeModule{info: module.Info{ID: id, Name: id, Kind: kind, Checks: checks}, run: run}
}

func validFinding(moduleID, domain string) finding.Finding {
	return finding.Finding{
		SchemaVersion: finding.SchemaVersion,
		ID:            finding.NewID(moduleID, moduleID+"-check", domain, domain),
		ModuleID:      moduleID,
		CheckID:       moduleID + "-check",
		Target:        domain,
		Asset:         domain,
		Severity:      finding.SeverityMedium,
		Title:         "A title",
		Description:   "A description",
	}
}

func returns(findings ...finding.Finding) func(context.Context, module.Request) ([]finding.Finding, error) {
	return func(context.Context, module.Request) ([]finding.Finding, error) { return findings, nil }
}

// setup returns a worker with the given modules and one queued scan of
// example.com running them all.
func setup(t *testing.T, verified bool, exclusions string, mods ...*fakeModule) (*Worker, *fakeStore) {
	t.Helper()
	reg := module.NewRegistry()
	var ids []string
	for _, m := range mods {
		if err := reg.Register(m); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, m.info.ID)
	}
	return setupWithModules(t, verified, exclusions, reg, ids)
}

func setupWithModules(t *testing.T, verified bool, exclusions string, reg *module.Registry, ids []string) (*Worker, *fakeStore) {
	t.Helper()
	target := store.Target{ID: "t1", OrgID: "o1", Domain: "example.com", RatePerSec: 100, Exclusions: json.RawMessage(exclusions)}
	if verified {
		at := time.Now()
		target.VerifiedAt = &at
	}
	st := &fakeStore{
		targets: map[string]store.Target{"t1": target},
		queue:   []store.Scan{{ID: "s1", OrgID: "o1", TargetID: "t1", Domain: "example.com", Modules: ids}},
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	w := New(st, reg, trustingRechecker{}, Config{ID: "worker:test", ModuleTimeout: time.Second, Lease: time.Minute}, log)
	return w, st
}

func runOnce(t *testing.T, w *Worker) error {
	t.Helper()
	worked, err := w.RunOnce(context.Background())
	if !worked {
		t.Fatal("RunOnce did not pick the scan")
	}
	return err
}

// trustingRechecker confirms whatever the stored status says and lets
// active modules reach every IP.
type trustingRechecker struct{}

func (trustingRechecker) Recheck(ctx context.Context, t store.Target, g module.Gate, actor string) (bool, error) {
	return t.Verified(), nil
}

func (trustingRechecker) IPGate(inner module.Gate, domain string, onRefuse ownership.RefuseFunc) module.Gate {
	return inner
}

// fixedRechecker returns a fixed answer and counts calls.
type fixedRechecker struct {
	trustingRechecker
	ok    bool
	err   error
	calls int
}

func (f *fixedRechecker) Recheck(ctx context.Context, t store.Target, g module.Gate, actor string) (bool, error) {
	f.calls++
	return f.ok, f.err
}

// ipOwnership refuses one IP for active modules, like ownership.IPGate.
type ipOwnership struct {
	trustingRechecker
	refused netip.Addr
}

func (o ipOwnership) IPGate(inner module.Gate, domain string, onRefuse ownership.RefuseFunc) module.Gate {
	return gateFunc(func(ctx context.Context, d module.Destination) error {
		if d.IP == o.refused {
			onRefuse(d.IP, "no PTR")
			return fmt.Errorf("not owned: %w", module.ErrExcluded)
		}
		return inner.Allow(ctx, d)
	})
}

type gateFunc func(context.Context, module.Destination) error

func (f gateFunc) Allow(ctx context.Context, d module.Destination) error { return f(ctx, d) }

// ---- Tests ----------------------------------------------------------------

func TestPassiveModuleRuns(t *testing.T) {
	email := newModule("email", module.KindPassive, returns(validFinding("email", "example.com")))
	w, st := setup(t, false, "{}", email)

	if err := runOnce(t, w); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if len(st.finished) != 1 {
		t.Fatalf("FinishScan called %d times, want 1", len(st.finished))
	}
	r := st.finished[0]
	if r.ScanID != "s1" || r.Attempt != 1 || r.WorkerID != "worker:test" || r.At.IsZero() {
		t.Errorf("result header = %+v", r)
	}
	if len(r.Succeeded) != 1 || len(r.Findings) != 1 || len(r.Failed) != 0 {
		t.Errorf("result = succeeded %v, %d findings, failed %v", r.Succeeded, len(r.Findings), r.Failed)
	}
}

// Security rule 1: an active module never runs on an unverified target.
func TestActiveModuleRefusedOnUnverifiedTarget(t *testing.T) {
	ports := newModule("ports", module.KindActive, nil)
	email := newModule("email", module.KindPassive, nil)
	w, st := setup(t, false, "{}", ports, email)

	if err := runOnce(t, w); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if n := ports.runs.Load(); n != 0 {
		t.Fatalf("active module ran %d times on an unverified target", n)
	}
	if email.runs.Load() != 1 {
		t.Error("the passive module should still run")
	}
	r := st.finished[0]
	if !strings.Contains(r.Failed["ports"], "verified") {
		t.Errorf("failed = %v, want ports refused for verification", r.Failed)
	}
	if len(st.audit) != 1 || st.audit[0].Action != store.ActionModuleRefused || st.audit[0].OrgID != "o1" {
		t.Errorf("audit = %+v, want one module.refused entry for the target's organization", st.audit)
	}
}

func TestActiveModuleRunsOnVerifiedTarget(t *testing.T) {
	ports := newModule("ports", module.KindActive, nil)
	w, st := setup(t, true, "{}", ports)
	if err := runOnce(t, w); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if ports.runs.Load() != 1 || len(st.finished[0].Succeeded) != 1 {
		t.Errorf("active module on a verified target: runs %d, result %+v", ports.runs.Load(), st.finished[0])
	}
}

func TestBadModuleOutputFailsThatModule(t *testing.T) {
	invalid := validFinding("email", "example.com")
	invalid.Severity = "severe"
	wrongModule := validFinding("tls", "example.com")
	wrongTarget := validFinding("email", "other.example")
	many := make([]finding.Finding, maxFindingsPerModule+1)
	for i := range many {
		many[i] = validFinding("email", "example.com")
	}

	tests := []struct {
		name string
		run  func(context.Context, module.Request) ([]finding.Finding, error)
		want string
	}{
		{"error", func(context.Context, module.Request) ([]finding.Finding, error) {
			return nil, errors.New("dns timeout")
		}, "dns timeout"},
		{"invalid finding", returns(validFinding("email", "example.com"), invalid), "invalid finding"},
		{"finding of another module", returns(wrongModule), "for module"},
		{"finding for another target", returns(wrongTarget), "target"},
		{"too many findings", returns(many...), "limit"},
		{"panic", func(context.Context, module.Request) ([]finding.Finding, error) {
			panic("index out of range")
		}, "panicked"},
		{"timeout", func(ctx context.Context, _ module.Request) ([]finding.Finding, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		}, "deadline"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			email := newModule("email", module.KindPassive, tt.run)
			w, st := setup(t, false, "{}", email)
			w.cfg.ModuleTimeout = 50 * time.Millisecond
			if err := runOnce(t, w); err != nil {
				t.Fatalf("RunOnce: %v", err)
			}
			r := st.finished[0]
			if len(r.Succeeded) != 0 || len(r.Findings) != 0 {
				t.Errorf("result = succeeded %v, %d findings; want nothing", r.Succeeded, len(r.Findings))
			}
			if !strings.Contains(r.Failed["email"], tt.want) {
				t.Errorf("failure = %q, want it to mention %q", r.Failed["email"], tt.want)
			}
		})
	}
}

func TestUnknownModuleIsRefused(t *testing.T) {
	w, st := setupWithModules(t, true, "{}", module.NewRegistry(), []string{"nmap"})
	if err := runOnce(t, w); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if !strings.Contains(st.finished[0].Failed["nmap"], "unknown module") {
		t.Errorf("failed = %v", st.finished[0].Failed)
	}
}

// Unreadable exclusions: the scan fails and no module runs.
func TestInvalidExclusionsFailClosed(t *testing.T) {
	email := newModule("email", module.KindPassive, nil)
	w, st := setup(t, false, `{"ip": ["192.0.2.10"]}`, email)
	if err := runOnce(t, w); err == nil {
		t.Fatal("RunOnce = nil, want error")
	}
	if email.runs.Load() != 0 {
		t.Error("a module ran despite unreadable exclusions")
	}
	if len(st.failed) != 1 || !strings.Contains(st.failed[0], "exclusions") || len(st.finished) != 0 {
		t.Errorf("failed = %v, finished = %d", st.failed, len(st.finished))
	}
}

// The gate a module receives applies the target's exclusions.
func TestModuleGateAppliesExclusions(t *testing.T) {
	var gateErr error
	probe := newModule("probe", module.KindPassive, func(ctx context.Context, req module.Request) ([]finding.Finding, error) {
		gateErr = req.Gate.Allow(ctx, module.Destination{Host: "example.com", IP: netip.MustParseAddr("192.0.2.10"), Port: 443})
		return nil, nil
	})
	w, _ := setup(t, false, `{"ips": ["192.0.2.0/24"]}`, probe)
	if err := runOnce(t, w); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if !errors.Is(gateErr, module.ErrExcluded) {
		t.Errorf("gate answer = %v, want ErrExcluded", gateErr)
	}
}

// If another worker took the scan over, this one stops and records nothing.
func TestLostLeaseDropsResults(t *testing.T) {
	slow := newModule("email", module.KindPassive, func(ctx context.Context, _ module.Request) ([]finding.Finding, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	})
	w, st := setup(t, false, "{}", slow)
	w.cfg.Lease = 30 * time.Millisecond // heartbeat every 10ms
	w.cfg.ModuleTimeout = 5 * time.Second
	st.leaseLost = true

	start := time.Now()
	err := runOnce(t, w)
	if !errors.Is(err, store.ErrLeaseLost) {
		t.Fatalf("RunOnce = %v, want ErrLeaseLost", err)
	}
	if time.Since(start) > 2*time.Second {
		t.Error("the module was not stopped when the lease was lost")
	}
	if len(st.finished) != 0 || len(st.failed) != 0 {
		t.Errorf("results recorded after losing the lease: finished %d, failed %d", len(st.finished), len(st.failed))
	}
}

func TestHeartbeatExtendsLease(t *testing.T) {
	slow := newModule("email", module.KindPassive, func(ctx context.Context, _ module.Request) ([]finding.Finding, error) {
		time.Sleep(100 * time.Millisecond)
		return nil, nil
	})
	w, st := setup(t, false, "{}", slow)
	w.cfg.Lease = 30 * time.Millisecond
	if err := runOnce(t, w); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if st.extended < 3 {
		t.Errorf("lease extended %d times during a 100ms scan with a 30ms lease, want >= 3", st.extended)
	}
}

func TestShutdownDropsPartialResults(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	first := newModule("a", module.KindPassive, func(context.Context, module.Request) ([]finding.Finding, error) {
		cancel() // shutdown signal arrives during the scan
		return nil, nil
	})
	second := newModule("b", module.KindPassive, nil)
	w, st := setup(t, false, "{}", first, second)

	if _, err := w.RunOnce(ctx); !errors.Is(err, context.Canceled) {
		t.Errorf("RunOnce = %v, want context.Canceled", err)
	}
	if second.runs.Load() != 0 {
		t.Error("a module started after shutdown")
	}
	if len(st.finished) != 0 {
		t.Error("a partial result was recorded at shutdown")
	}
}

func TestEmptyQueue(t *testing.T) {
	w, st := setup(t, false, "{}")
	st.queue = nil
	worked, err := w.RunOnce(context.Background())
	if worked || err != nil {
		t.Errorf("RunOnce on empty queue = %v, %v", worked, err)
	}
}

func TestRunStopsOnCancel(t *testing.T) {
	email := newModule("email", module.KindPassive, nil)
	w, st := setup(t, false, "{}", email)
	w.cfg.PollInterval = 10 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error)
	go func() { done <- w.Run(ctx) }()

	deadline := time.Now().Add(2 * time.Second)
	for {
		st.mu.Lock()
		n := len(st.finished)
		st.mu.Unlock()
		if n == 1 || time.Now().After(deadline) {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Run = %v, want nil on shutdown", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not stop after cancel")
	}
	if len(st.finished) != 1 {
		t.Errorf("finished %d scans, want 1", len(st.finished))
	}
}

func TestOwnershipIsRecheckedBeforeActiveModules(t *testing.T) {
	tests := []struct {
		name      string
		recheck   *fixedRechecker
		wantRuns  int32
		wantCalls int
	}{
		{"still verified", &fixedRechecker{ok: true}, 1, 1},
		{"record removed", &fixedRechecker{ok: false}, 0, 1},
		{"dns failure", &fixedRechecker{err: errors.New("timeout")}, 0, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ports := newModule("ports", module.KindActive, nil)
			w, st := setup(t, true, "{}", ports)
			w.owner = tt.recheck
			if err := runOnce(t, w); err != nil {
				t.Fatalf("RunOnce: %v", err)
			}
			if got := ports.runs.Load(); got != tt.wantRuns {
				t.Errorf("active module ran %d times, want %d", got, tt.wantRuns)
			}
			if tt.recheck.calls != tt.wantCalls {
				t.Errorf("Recheck called %d times, want %d", tt.recheck.calls, tt.wantCalls)
			}
			if tt.wantRuns == 0 && !strings.Contains(st.finished[0].Failed["ports"], "verified") {
				t.Errorf("failed = %v, want ports refused", st.finished[0].Failed)
			}
		})
	}
}

// Passive-only scans do not trigger a DNS re-check.
func TestNoRecheckForPassiveScans(t *testing.T) {
	email := newModule("email", module.KindPassive, nil)
	w, _ := setup(t, true, "{}", email)
	r := &fixedRechecker{ok: true}
	w.owner = r
	if err := runOnce(t, w); err != nil {
		t.Fatal(err)
	}
	if r.calls != 0 {
		t.Errorf("Recheck called %d times for a passive scan", r.calls)
	}
}

func TestNilRecheckerRefusesActiveModules(t *testing.T) {
	ports := newModule("ports", module.KindActive, nil)
	w, _ := setup(t, true, "{}", ports)
	w.owner = nil
	if err := runOnce(t, w); err != nil {
		t.Fatal(err)
	}
	if ports.runs.Load() != 0 {
		t.Error("active module ran without a rechecker")
	}
}

// Active modules get the IP-restricted gate; passive modules do not.
func TestActiveModulesGetIPGate(t *testing.T) {
	shared := netip.MustParseAddr("198.51.100.20")
	dest := module.Destination{Host: "example.com", IP: shared, Port: 443}
	var activeErr, passiveErr error
	ports := newModule("ports", module.KindActive, func(ctx context.Context, req module.Request) ([]finding.Finding, error) {
		activeErr = req.Gate.Allow(ctx, dest)
		return nil, nil
	})
	tls := newModule("tls", module.KindPassive, func(ctx context.Context, req module.Request) ([]finding.Finding, error) {
		passiveErr = req.Gate.Allow(ctx, dest)
		return nil, nil
	})
	w, st := setup(t, true, "{}", ports, tls)
	w.owner = ipOwnership{refused: shared}

	if err := runOnce(t, w); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if !errors.Is(activeErr, module.ErrExcluded) {
		t.Errorf("active module reached an unverified IP: %v", activeErr)
	}
	if passiveErr != nil {
		t.Errorf("passive module was IP-restricted: %v", passiveErr)
	}
	var audited bool
	for _, e := range st.audit {
		audited = audited || (e.Action == store.ActionIPNotVerified && e.OrgID == "o1")
	}
	if !audited {
		t.Errorf("audit = %+v, want an ip.not_verified entry", st.audit)
	}
}

func TestAssetsAreForwarded(t *testing.T) {
	ip := netip.MustParseAddr("192.0.2.10")
	m := newModule("tls", module.KindPassive, nil)
	m.assets = []asset.Asset{
		asset.Hostname("example.com"), asset.IP(ip),
		asset.Service(ip, 443, map[string]string{"expected": "https"}),
		asset.Service(ip, 443, map[string]string{"tls_version": "TLS 1.3"}), // duplicate: merged
	}
	w, st := setup(t, false, "", m)
	if err := runOnce(t, w); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	got := st.finished[0].Assets["tls"]
	if len(got) != 3 {
		t.Fatalf("assets = %+v, want 3 (duplicate merged)", got)
	}
	if d := got[2].Details; d["expected"] != "https" || d["tls_version"] != "TLS 1.3" {
		t.Errorf("merged details = %v", d)
	}
}

func TestBadAssetsFailThatModule(t *testing.T) {
	many := make([]asset.Asset, maxAssetsPerModule+1)
	for i := range many {
		many[i] = asset.IP(netip.AddrFrom4([4]byte{192, 0, 2, byte(i)}))
	}
	tests := []struct {
		name   string
		assets []asset.Asset
		want   string
	}{
		{"name outside the target", []asset.Asset{asset.Hostname("mx.provider.net")}, "invalid asset"},
		{"unknown kind", []asset.Asset{{Kind: "printer", Value: "x"}}, "invalid asset"},
		{"too many", many, "limit"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := newModule("tls", module.KindPassive, nil)
			m.assets = tt.assets
			w, st := setup(t, false, "", m)
			if err := runOnce(t, w); err != nil {
				t.Fatalf("RunOnce: %v", err)
			}
			r := st.finished[0]
			if !strings.Contains(r.Failed["tls"], tt.want) || len(r.Assets) != 0 || len(r.Succeeded) != 0 {
				t.Errorf("result = %+v, want tls failed with %q and no assets", r, tt.want)
			}
		})
	}
}

func TestCheckOutcomesAreForwarded(t *testing.T) {
	email := newModule("email", module.KindPassive, returns(validFinding("email", "example.com")))
	tls := newModule("tls", module.KindPassive, nil)
	tls.evaluated = []string{"tls-check"}
	silent := newModule("silent", module.KindPassive, nil) // evaluates nothing
	w, st := setup(t, false, "", email, tls, silent)
	if err := runOnce(t, w); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	got := st.finished[0].Checks
	want := map[string]module.CheckStatus{"email": module.CheckFailed, "tls": module.CheckPassed, "silent": module.CheckNotApplicable}
	for id, status := range want {
		if len(got[id]) != 1 || got[id][0].Status != status {
			t.Errorf("%s outcomes = %+v, want one %s", id, got[id], status)
		}
	}
}

func TestUndeclaredCheckFailsTheModule(t *testing.T) {
	typo := validFinding("email", "example.com")
	typo.CheckID = "emial-check"
	typo.ID = finding.NewID("email", typo.CheckID, "example.com", "example.com")
	for name, m := range map[string]*fakeModule{
		"finding": newModule("email", module.KindPassive, returns(typo)),
		"evaluated": func() *fakeModule {
			m := newModule("email", module.KindPassive, nil)
			m.evaluated = []string{"emial-check"}
			return m
		}(),
	} {
		t.Run(name, func(t *testing.T) {
			w, st := setup(t, false, "", m)
			if err := runOnce(t, w); err != nil {
				t.Fatalf("RunOnce: %v", err)
			}
			r := st.finished[0]
			if !strings.Contains(r.Failed["email"], "undeclared check") || len(r.Checks["email"]) != 0 {
				t.Errorf("result = %+v, want email failed for an undeclared check", r)
			}
		})
	}
}

// The worker tells the store what was out of reach: excluded destinations
// and IPs refused to active modules. Their findings must not become "fixed".
func TestUnobservedCoversExclusionsAndRefusedIPs(t *testing.T) {
	refusedIP := netip.MustParseAddr("198.51.100.20")
	ports := newModule("ports", module.KindActive, func(ctx context.Context, req module.Request) ([]finding.Finding, error) {
		_ = req.Gate.Allow(ctx, module.Destination{Host: "example.com", IP: refusedIP, Port: 22})
		return nil, nil
	})
	w, st := setup(t, true, `{"ports": [8080], "hosts": ["staging.example.com"]}`, ports)
	w.owner = ipOwnership{refused: refusedIP}
	if err := runOnce(t, w); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if len(st.finished) != 1 || st.finished[0].Unobserved == nil {
		t.Fatalf("finished = %+v, want one result with Unobserved", st.finished)
	}
	unobserved := st.finished[0].Unobserved
	tests := []struct {
		kind  asset.Kind
		value string
		want  bool
	}{
		{"", "192.0.2.10:8080", true},                    // excluded port, finding asset
		{asset.KindService, "192.0.2.10:8080/tcp", true}, // excluded port, service asset
		{"", "192.0.2.10:22", false},                     // probed: absence means closed
		{"", "staging.example.com:443", true},            // excluded host
		{"", "198.51.100.20:22", true},                   // IP refused to the active module
		{asset.KindIP, "198.51.100.20", true},
		{"", "www.example.com:443", false},
		{asset.KindCertificate, "staging.example.com", false}, // certificates are hashes, never destinations
	}
	for _, tt := range tests {
		if got := unobserved(tt.kind, tt.value); got != tt.want {
			t.Errorf("Unobserved(%q, %q) = %v, want %v", tt.kind, tt.value, got, tt.want)
		}
	}
}

// Names a module could not reach (the gate refused them) keep their
// findings, whatever the form of the finding's asset.
func TestUnobservedCoversUnreachedNames(t *testing.T) {
	vulns := newModule("vulns", module.KindActive, returns())
	vulns.unreached = []string{"app.example.com"}
	w, st := setup(t, true, "{}", vulns)
	if err := runOnce(t, w); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	unobserved := st.finished[0].Unobserved
	for value, want := range map[string]bool{
		"https://app.example.com/.git/config#git-config": true,
		"app.example.com":            true,
		"app.example.com:443":        true,
		"https://www.example.com/#x": false,
		"www.example.com":            false,
	} {
		if got := unobserved("", value); got != want {
			t.Errorf("Unobserved(%q) = %v, want %v", value, got, want)
		}
	}
}

// A module's own Timeout replaces the worker's default.
func TestModuleTimeout(t *testing.T) {
	var left time.Duration
	long := newModule("long", module.KindPassive, func(ctx context.Context, req module.Request) ([]finding.Finding, error) {
		dl, _ := ctx.Deadline()
		left = time.Until(dl)
		return nil, nil
	})
	long.info.Timeout = 30 * time.Second // the worker's default here is 1s
	w, _ := setup(t, false, "{}", long)
	if err := runOnce(t, w); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if left < 20*time.Second {
		t.Errorf("module deadline in %v, want its own 30s", left)
	}
}

// Run queues the due scheduled scans when it starts, then every
// ScheduleInterval; an error there does not stop the worker.
func TestRunQueuesScheduledScans(t *testing.T) {
	w, st := setup(t, false, "{}")
	st.queue = nil
	st.scheduleErr = errors.New("database unavailable")
	w.cfg.PollInterval = 5 * time.Millisecond
	w.cfg.ScheduleInterval = 20 * time.Millisecond

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	if err := w.Run(ctx); err != nil {
		t.Fatalf("Run: %v", err)
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	if n := len(st.scheduleCalls); n < 2 || n > 10 {
		t.Errorf("EnqueueDueScans called %d times in 150ms with a 20ms interval, want a few", n)
	}
}

// A discovery module runs first even when listed last, and the modules
// after it get the inventory's hostnames plus what it found.
func TestDiscoveryRunsFirstAndFeedsHosts(t *testing.T) {
	var order []string
	var tlsHosts []string
	tls := newModule("tls", module.KindPassive, func(ctx context.Context, req module.Request) ([]finding.Finding, error) {
		order = append(order, "tls")
		tlsHosts = req.Target.Hosts
		return nil, nil
	})
	disc := &fakeModule{
		info:   module.Info{ID: "discovery", Name: "Discovery", Kind: module.KindPassive, ProvidesHosts: true},
		assets: []asset.Asset{asset.Hostname("vpn.example.com"), asset.Hostname("old.example.com")},
		run: func(ctx context.Context, req module.Request) ([]finding.Finding, error) {
			order = append(order, "discovery")
			return nil, nil
		},
	}
	w, st := setup(t, false, "{}", tls, disc) // queued as [tls discovery]
	st.hostnames = []string{"old.example.com", "shop.example.com"}
	if err := runOnce(t, w); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if !slices.Equal(order, []string{"discovery", "tls"}) {
		t.Errorf("run order = %v, want discovery first", order)
	}
	if want := []string{"old.example.com", "shop.example.com", "vpn.example.com"}; !slices.Equal(tlsHosts, want) {
		t.Errorf("tls got hosts %v, want %v", tlsHosts, want)
	}
}
