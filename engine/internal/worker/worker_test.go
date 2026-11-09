package worker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

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

// fakeModule returns what run returns and counts its runs.
type fakeModule struct {
	info module.Info
	runs atomic.Int32
	run  func(ctx context.Context, req module.Request) ([]finding.Finding, error)
}

func (m *fakeModule) Info() module.Info { return m.info }

func (m *fakeModule) Run(ctx context.Context, req module.Request) ([]finding.Finding, error) {
	m.runs.Add(1)
	if m.run == nil {
		return nil, nil
	}
	return m.run(ctx, req)
}

func newModule(id string, kind module.Kind, run func(context.Context, module.Request) ([]finding.Finding, error)) *fakeModule {
	return &fakeModule{info: module.Info{ID: id, Name: id, Kind: kind}, run: run}
}

func validFinding(moduleID, domain string) finding.Finding {
	return finding.Finding{
		SchemaVersion: finding.SchemaVersion,
		ID:            finding.NewID(moduleID, "some-check", domain, domain),
		ModuleID:      moduleID,
		CheckID:       "some-check",
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
	target := store.Target{ID: "t1", Domain: "example.com", RatePerSec: 100, Exclusions: json.RawMessage(exclusions)}
	if verified {
		at := time.Now()
		target.VerifiedAt = &at
	}
	st := &fakeStore{
		targets: map[string]store.Target{"t1": target},
		queue:   []store.Scan{{ID: "s1", TargetID: "t1", Domain: "example.com", Modules: ids}},
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
	if len(st.audit) != 1 || st.audit[0].Action != store.ActionModuleRefused {
		t.Errorf("audit = %+v, want one module.refused entry", st.audit)
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
		audited = audited || e.Action == store.ActionIPNotVerified
	}
	if !audited {
		t.Errorf("audit = %+v, want an ip.not_verified entry", st.audit)
	}
}
