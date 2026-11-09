// Package worker runs scans: it claims a job from the queue, runs the
// requested modules against the target, and records the results.
//
// Workers are stateless: everything they need comes from the job and the
// database, and nothing is kept between jobs. Scaling means starting more
// workers.
package worker

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	"github.com/jordyorel/orus-shield/engine/internal/asset"
	"github.com/jordyorel/orus-shield/engine/internal/finding"
	"github.com/jordyorel/orus-shield/engine/internal/gate"
	"github.com/jordyorel/orus-shield/engine/internal/module"
	"github.com/jordyorel/orus-shield/engine/internal/ownership"
	"github.com/jordyorel/orus-shield/engine/internal/store"
)

// Store is the part of store.Store the worker uses. Tests replace it with an
// in-memory fake.
type Store interface {
	ClaimScan(ctx context.Context, workerID string, lease time.Duration, maxAttempts int) (store.Scan, bool, error)
	GetTarget(ctx context.Context, id string) (store.Target, error)
	ExtendLease(ctx context.Context, scanID string, attempt int, lease time.Duration) error
	FinishScan(ctx context.Context, r store.ScanResult) error
	FailScan(ctx context.Context, scanID string, attempt int, workerID, reason string) error
	AppendAudit(ctx context.Context, e store.AuditEntry) error
}

// Ownership enforces security rule 1 for active modules (see package
// ownership): Recheck confirms the domain is still verified, IPGate wraps
// the scan's gate so active modules can only reach IPs proven to belong to
// the customer.
type Ownership interface {
	Recheck(ctx context.Context, t store.Target, g module.Gate, actor string) (bool, error)
	IPGate(inner module.Gate, domain string, onRefuse ownership.RefuseFunc) module.Gate
}

// Config tunes a worker. Zero values get the defaults below.
type Config struct {
	ID            string        // identity in the audit log, e.g. "worker:host-1234"
	Lease         time.Duration // how long a claim is valid without heartbeat
	ModuleTimeout time.Duration // maximum duration of one module run
	PollInterval  time.Duration // wait between polls when the queue is empty
	MaxAttempts   int           // claims before a crashing scan is abandoned
}

const (
	defaultLease         = 5 * time.Minute
	defaultModuleTimeout = 2 * time.Minute
	defaultPollInterval  = 2 * time.Second
	defaultMaxAttempts   = 3

	// maxFindingsPerModule bounds one module's output (rule 7): a bug or a
	// hostile target must not flood the database.
	maxFindingsPerModule = 1000
	// maxAssetsPerModule does the same for the asset inventory.
	maxAssetsPerModule = 1000

	// finishTimeout bounds the final database writes. They run even if the
	// worker is shutting down, so a completed scan is not lost.
	finishTimeout = 30 * time.Second
)

// Worker processes scans one at a time. Run several workers to scan in
// parallel.
type Worker struct {
	store   Store
	modules *module.Registry
	owner   Ownership
	cfg     Config
	log     *slog.Logger
	now     func() time.Time
}

// New returns a worker. modules is the set of checks it can run; owner
// enforces ownership for active modules (nil: active modules are always
// refused).
func New(st Store, modules *module.Registry, owner Ownership, cfg Config, log *slog.Logger) *Worker {
	if cfg.ID == "" {
		cfg.ID = "worker"
	}
	if cfg.Lease <= 0 {
		cfg.Lease = defaultLease
	}
	if cfg.ModuleTimeout <= 0 {
		cfg.ModuleTimeout = defaultModuleTimeout
	}
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = defaultPollInterval
	}
	if cfg.MaxAttempts <= 0 {
		cfg.MaxAttempts = defaultMaxAttempts
	}
	return &Worker{store: st, modules: modules, owner: owner, cfg: cfg, log: log.With("worker", cfg.ID), now: time.Now}
}

// Run processes scans until ctx is cancelled, then returns nil. A scan in
// progress at shutdown is abandoned; its lease expires and another worker
// picks it up.
func (w *Worker) Run(ctx context.Context) error {
	w.log.Info("worker started")
	for {
		worked, err := w.RunOnce(ctx)
		if ctx.Err() != nil {
			w.log.Info("worker stopped")
			return nil
		}
		if err != nil {
			w.log.Error("scan failed", "err", err)
		}
		if worked && err == nil {
			continue // there may be more work: poll again right away
		}
		select {
		case <-ctx.Done():
			w.log.Info("worker stopped")
			return nil
		case <-time.After(w.cfg.PollInterval):
		}
	}
}

// RunOnce claims and processes at most one scan. worked is false when the
// queue was empty.
func (w *Worker) RunOnce(ctx context.Context) (worked bool, err error) {
	sc, ok, err := w.store.ClaimScan(ctx, w.cfg.ID, w.cfg.Lease, w.cfg.MaxAttempts)
	if err != nil {
		return false, fmt.Errorf("claim scan: %w", err)
	}
	if !ok {
		return false, nil
	}
	log := w.log.With("scan_id", sc.ID, "domain", sc.Domain, "attempt", sc.Attempt)
	start := time.Now()
	log.Info("scan started", "modules", sc.Modules)
	if err := w.process(ctx, sc, log); err != nil {
		return true, fmt.Errorf("scan %s: %w", sc.ID, err)
	}
	log.Info("scan finished", "duration_ms", time.Since(start).Milliseconds())
	return true, nil
}

func (w *Worker) process(ctx context.Context, sc store.Scan, log *slog.Logger) error {
	// scanCtx is cancelled if the lease is lost: another worker owns the
	// scan, so this one must stop sending requests at once.
	scanCtx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	stopHeartbeat := w.heartbeat(scanCtx, cancel, sc, log)
	defer stopHeartbeat()

	target, err := w.store.GetTarget(scanCtx, sc.TargetID)
	if err != nil {
		return w.fail(ctx, sc, fmt.Sprintf("load target: %v", err))
	}
	// Fail closed: never scan with exclusions or a rate we cannot read.
	g, err := gate.FromTarget(target.Exclusions, target.RatePerSec)
	if err != nil {
		return w.fail(ctx, sc, fmt.Sprintf("invalid target settings: %v", err))
	}
	mt := module.Target{Domain: target.Domain, Verified: w.stillVerified(scanCtx, sc, target, g, log)}

	// Active modules get a stricter gate, built on first use: it only lets
	// them reach IPs whose ownership is proven (rule 1, per IP).
	var activeGate module.Gate
	gateFor := func(id string) module.Gate {
		m, ok := w.modules.Get(id)
		if !ok || m.Info().Kind != module.KindActive {
			return g
		}
		if activeGate == nil {
			activeGate = w.activeGate(scanCtx, sc, target, g, log)
		}
		return activeGate
	}

	result := store.ScanResult{
		ScanID: sc.ID, Attempt: sc.Attempt, WorkerID: w.cfg.ID,
		Failed: make(map[string]string),
		Assets: make(map[string][]asset.Asset),
		Checks: make(map[string][]module.CheckOutcome),
	}
	for _, id := range sc.Modules {
		if scanCtx.Err() != nil {
			break
		}
		start := time.Now()
		res, checks, err := w.runModule(scanCtx, id, mt, gateFor(id))
		var refused *refusedError
		switch {
		case errors.As(err, &refused):
			log.Warn("module refused", "module", id, "reason", refused.err)
			result.Failed[id] = "refused: " + refused.err.Error()
			if err := w.store.AppendAudit(scanCtx, store.AuditEntry{
				OrgID: target.OrgID, Actor: w.cfg.ID, Action: store.ActionModuleRefused, Target: target.Domain,
				Details: map[string]any{"scan_id": sc.ID, "module": id, "reason": refused.err.Error()},
			}); err != nil {
				return fmt.Errorf("audit refusal: %w", err)
			}
		case err != nil:
			log.Warn("module failed", "module", id, "err", err, "duration_ms", time.Since(start).Milliseconds())
			result.Failed[id] = err.Error()
		default:
			// Log counts only: findings and assets are customer data and
			// never logged.
			log.Info("module done", "module", id, "findings", len(res.Findings), "assets", len(res.Assets),
				"duration_ms", time.Since(start).Milliseconds())
			result.Succeeded = append(result.Succeeded, id)
			result.Findings = append(result.Findings, res.Findings...)
			if len(res.Assets) > 0 {
				result.Assets[id] = res.Assets
			}
			result.Checks[id] = checks
		}
	}
	// Lease lost or shutdown: drop the partial result. Recording it could
	// mark findings fixed only because their module was interrupted.
	if cause := context.Cause(scanCtx); cause != nil {
		return fmt.Errorf("scan interrupted: %w", cause)
	}

	result.At = w.now()
	finishCtx, cancelFinish := context.WithTimeout(context.WithoutCancel(ctx), finishTimeout)
	defer cancelFinish()
	if err := w.store.FinishScan(finishCtx, result); err != nil {
		return fmt.Errorf("record results: %w", err)
	}
	return nil
}

// stillVerified decides whether active modules may run in this scan. The
// stored status is confirmed against DNS when an active module is requested
// (rule 1 is checked at scan time, not only once). If the confirmation
// fails, the answer is no for this scan.
func (w *Worker) stillVerified(ctx context.Context, sc store.Scan, t store.Target, g module.Gate, log *slog.Logger) bool {
	if !t.Verified() || !w.wantsActive(sc.Modules) {
		return t.Verified()
	}
	if w.owner == nil {
		return false
	}
	ok, err := w.owner.Recheck(ctx, t, g, w.cfg.ID)
	if err != nil {
		log.Warn("ownership re-check failed, active modules refused for this scan", "err", err)
		return false
	}
	if !ok {
		log.Warn("ownership no longer verified, active modules refused")
	}
	return ok
}

// activeGate returns the gate for active modules: g restricted to verified
// IPs. Each refused IP is logged and written to the audit log once.
func (w *Worker) activeGate(ctx context.Context, sc store.Scan, t store.Target, g module.Gate, log *slog.Logger) module.Gate {
	if w.owner == nil {
		return refuseAll{}
	}
	return w.owner.IPGate(g, t.Domain, func(ip netip.Addr, reason string) {
		log.Warn("IP refused for active scan", "ip", ip, "reason", reason)
		if err := w.store.AppendAudit(ctx, store.AuditEntry{
			OrgID: t.OrgID, Actor: w.cfg.ID, Action: store.ActionIPNotVerified, Target: t.Domain,
			Details: map[string]any{"scan_id": sc.ID, "ip": ip.String(), "reason": reason},
		}); err != nil {
			log.Error("audit IP refusal", "err", err)
		}
	})
}

// refuseAll is the active gate when no ownership checker is configured.
type refuseAll struct{}

func (refuseAll) Allow(context.Context, module.Destination) error {
	return fmt.Errorf("no ownership checker: %w", module.ErrExcluded)
}

// wantsActive reports whether one of the requested modules is active.
func (w *Worker) wantsActive(ids []string) bool {
	for _, id := range ids {
		if m, ok := w.modules.Get(id); ok && m.Info().Kind == module.KindActive {
			return true
		}
	}
	return false
}

// refusedError means a module was not allowed to run (rule 1 or unknown ID).
type refusedError struct{ err error }

func (e *refusedError) Error() string { return "refused: " + e.err.Error() }

// runModule runs one module with its own timeout, checks its output, and
// evaluates its check catalog (module.Evaluate).
func (w *Worker) runModule(ctx context.Context, id string, t module.Target, g module.Gate) (res module.Result, checks []module.CheckOutcome, err error) {
	m, ok := w.modules.Get(id)
	if !ok {
		return module.Result{}, nil, &refusedError{fmt.Errorf("unknown module %q", id)}
	}
	// Security rule 1, checked right before every run.
	if err := module.CheckAllowed(m.Info(), t); err != nil {
		return module.Result{}, nil, &refusedError{err}
	}

	// Modules parse untrusted data. A panic in one must fail that module,
	// not crash the worker and every scan after it.
	defer func() {
		if r := recover(); r != nil {
			res, checks, err = module.Result{}, nil, fmt.Errorf("module %s panicked: %v", id, r)
		}
	}()

	mctx, cancel := context.WithTimeout(ctx, w.cfg.ModuleTimeout)
	defer cancel()
	res, err = m.Run(mctx, module.Request{Target: t, Gate: g})
	if err != nil {
		return module.Result{}, nil, err
	}
	findings := res.Findings
	if len(findings) > maxFindingsPerModule {
		return module.Result{}, nil, fmt.Errorf("module %s returned %d findings, limit is %d", id, len(findings), maxFindingsPerModule)
	}
	if len(res.Assets) > maxAssetsPerModule {
		return module.Result{}, nil, fmt.Errorf("module %s returned %d assets, limit is %d", id, len(res.Assets), maxAssetsPerModule)
	}

	// Reject the whole output if one finding is wrong: storing part of it
	// would mark the missing findings fixed.
	now := w.now()
	for _, f := range findings {
		if f.ModuleID != id || f.Target != t.Domain {
			return module.Result{}, nil, fmt.Errorf("module %s returned a finding for module %q, target %q", id, f.ModuleID, f.Target)
		}
		stamped := f
		stamped.FirstSeen, stamped.LastSeen, stamped.Status = now, now, finding.StatusOpen
		if err := stamped.Validate(); err != nil {
			return module.Result{}, nil, fmt.Errorf("module %s returned an invalid finding %s: %w", id, f.CheckID, err)
		}
	}
	// Same for assets: a missing asset would be marked gone. Duplicates
	// are merged so each asset is stored once.
	var assets asset.Set
	for _, a := range res.Assets {
		if err := a.Validate(t.Domain); err != nil {
			return module.Result{}, nil, fmt.Errorf("module %s returned an invalid asset: %w", id, err)
		}
		assets.Add(a)
	}
	res = module.Result{Findings: findings, Assets: assets.List(), Evaluated: res.Evaluated}
	// Rejects findings or evaluated checks the catalog does not declare.
	checks, err = module.Evaluate(m.Info(), res)
	if err != nil {
		return module.Result{}, nil, err
	}
	return res, checks, nil
}

// heartbeat extends the lease every Lease/3 until stopped. If the lease is
// lost, it cancels the scan.
func (w *Worker) heartbeat(ctx context.Context, cancel context.CancelCauseFunc, sc store.Scan, log *slog.Logger) (stop func()) {
	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Go(func() {
		ticker := time.NewTicker(w.cfg.Lease / 3)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ctx.Done():
				return
			case <-ticker.C:
				err := w.store.ExtendLease(ctx, sc.ID, sc.Attempt, w.cfg.Lease)
				if errors.Is(err, store.ErrLeaseLost) {
					log.Warn("lease lost, stopping scan")
					cancel(err)
					return
				}
				if err != nil {
					// Transient database error: try again at the next tick.
					// The lease is three ticks long.
					log.Warn("extend lease", "err", err)
				}
			}
		}
	})
	return func() {
		close(done)
		wg.Wait()
	}
}

// fail records a scan failure and returns it as an error.
func (w *Worker) fail(ctx context.Context, sc store.Scan, reason string) error {
	failCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), finishTimeout)
	defer cancel()
	if err := w.store.FailScan(failCtx, sc.ID, sc.Attempt, w.cfg.ID, reason); err != nil {
		return fmt.Errorf("%s (and recording the failure failed: %w)", reason, err)
	}
	return errors.New(reason)
}
