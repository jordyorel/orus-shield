package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"time"

	"github.com/jordyorel/orus-shield/engine/internal/dialer"
	"github.com/jordyorel/orus-shield/engine/internal/gate"
	"github.com/jordyorel/orus-shield/engine/internal/module"
	"github.com/jordyorel/orus-shield/engine/internal/modules/ports"
	"github.com/jordyorel/orus-shield/engine/internal/resolver"
)

const (
	pollInterval = 30 * time.Second
	errorBackoff = 2 * time.Minute
)

// job is a scan the API gave the agent (api.agentJobJSON).
type job struct {
	ScanID     string          `json:"scan_id"`
	Attempt    int             `json:"attempt"`
	Modules    []string        `json:"modules"`
	Domain     string          `json:"domain"`
	Ranges     []string        `json:"ranges"`
	Exclusions json.RawMessage `json:"exclusions"`
	RatePerSec float64         `json:"rate_per_sec"`
	LeaseSecs  int             `json:"lease_seconds"`
}

// agent runs the scans of its internal network.
type agent struct {
	api *client
	log *slog.Logger
	// modules the agent can run; the others are reported as failed.
	modules map[string]module.Module
	// allowAddr says whether an address may be scanned at all (private
	// only); tests widen it to the loopback.
	allowAddr func(netip.Addr) bool
	now       func() time.Time
}

func newAgent(api *client, log *slog.Logger) *agent {
	return &agent{
		api: api, log: log,
		modules:   map[string]module.Module{ports.ID: ports.New(resolver.NewSystem(), dialer.NewSystem())},
		allowAddr: func(a netip.Addr) bool { return a.IsPrivate() },
		now:       time.Now,
	}
}

// loop claims and runs scans until ctx ends.
func (a *agent) loop(ctx context.Context) error {
	a.log.Info("agent started", "version", version)
	for {
		worked, err := a.once(ctx)
		if ctx.Err() != nil {
			return nil
		}
		wait := pollInterval
		switch {
		case err != nil:
			var es *errStatus
			if errors.As(err, &es) && es.code == http.StatusUnauthorized {
				return errors.New("this agent was revoked or its token is unknown: enroll it again")
			}
			a.log.Warn("agent error", "err", err)
			wait = errorBackoff
		case worked:
			wait = 0
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(wait):
		}
	}
}

// once claims one scan and runs it; worked is false when there was none.
func (a *agent) once(ctx context.Context) (worked bool, err error) {
	var j job
	code, err := a.api.do(ctx, "/api/v1/agent/claim", nil, &j)
	if err != nil {
		return false, err
	}
	if code == http.StatusNoContent {
		return false, nil
	}
	a.log.Info("scan started", "scan_id", j.ScanID, "modules", j.Modules)
	results, failed := a.runJob(ctx, j)
	if ctx.Err() != nil {
		return true, ctx.Err()
	}
	_, err = a.api.do(ctx, "/api/v1/agent/scans/"+j.ScanID+"/result", map[string]any{
		"attempt": j.Attempt, "results": results, "failed": failed,
	}, nil)
	if err != nil {
		return true, fmt.Errorf("send results of %s: %w", j.ScanID, err)
	}
	a.log.Info("scan sent", "scan_id", j.ScanID, "failed", failed)
	return true, nil
}

// runJob runs the job's modules and keeps the lease while it does.
func (a *agent) runJob(ctx context.Context, j job) (map[string]module.Result, map[string]string) {
	results := map[string]module.Result{}
	failed := map[string]string{}
	ranges, addrs, err := a.addresses(j.Ranges)
	if err != nil {
		for _, id := range j.Modules {
			failed[id] = err.Error()
		}
		return results, failed
	}
	rules, err := gate.ParseExclusions(j.Exclusions)
	if err == nil && j.RatePerSec <= 0 {
		err = errors.New("no rate")
	}
	var g module.Gate
	if err == nil {
		var base *gate.Gate
		if base, err = gate.New(rules, j.RatePerSec); err == nil {
			g = rangeGate{inner: base, ranges: ranges, allow: a.allowAddr}
		}
	}
	if err != nil {
		for _, id := range j.Modules {
			failed[id] = "exclusions or rate: " + err.Error()
		}
		return results, failed
	}

	jobCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go a.keepLease(jobCtx, cancel, j)

	target := module.Target{Domain: j.Domain, Verified: true, Addresses: addrs}
	for _, id := range j.Modules {
		m, ok := a.modules[id]
		if !ok {
			failed[id] = "not supported by the agent yet"
			continue
		}
		res, err := m.Run(jobCtx, module.Request{Target: target, Gate: g, Config: json.RawMessage(`{}`)})
		if err != nil {
			failed[id] = err.Error()
			continue
		}
		results[id] = res
	}
	return results, failed
}

// keepLease extends the scan's lease every third of it; a lost lease
// cancels the job (another run of the agent owns it now).
func (a *agent) keepLease(ctx context.Context, cancel context.CancelFunc, j job) {
	every := time.Duration(j.LeaseSecs) * time.Second / 3
	if every <= 0 {
		every = time.Minute
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			_, err := a.api.do(ctx, "/api/v1/agent/scans/"+j.ScanID+"/lease", map[string]int{"attempt": j.Attempt}, nil)
			var es *errStatus
			if errors.As(err, &es) && es.code == http.StatusConflict {
				a.log.Warn("lease lost", "scan_id", j.ScanID)
				cancel()
				return
			}
		}
	}
}

// addresses parses the ranges (private only) and lists their addresses,
// at most module.MaxAddresses, network and broadcast addresses excluded.
func (a *agent) addresses(raw []string) ([]netip.Prefix, []netip.Addr, error) {
	var ranges []netip.Prefix
	var addrs []netip.Addr
	for _, s := range raw {
		p, err := netip.ParsePrefix(s)
		if err != nil || !a.allowAddr(p.Addr()) {
			return nil, nil, fmt.Errorf("range %q is not a private network: refused", s)
		}
		p = p.Masked()
		ranges = append(ranges, p)
		first, last := p.Addr(), lastAddr(p)
		for ip := first; p.Contains(ip) && len(addrs) < module.MaxAddresses; ip = ip.Next() {
			if p.Addr().Is4() && p.Bits() <= 30 && (ip == first || ip == last) {
				continue // network and broadcast
			}
			addrs = append(addrs, ip)
			if ip == last {
				break
			}
		}
	}
	return ranges, addrs, nil
}

func lastAddr(p netip.Prefix) netip.Addr {
	b := p.Addr().AsSlice()
	bits := p.Bits()
	for i := range b {
		for k := 0; k < 8; k++ {
			if i*8+k >= bits {
				b[i] |= 1 << (7 - k)
			}
		}
	}
	a, _ := netip.AddrFromSlice(b)
	return a
}

// rangeGate refuses every destination outside the agent's private ranges,
// then applies the network's exclusions and rate (gate.Gate).
type rangeGate struct {
	inner  module.Gate
	ranges []netip.Prefix
	allow  func(netip.Addr) bool
}

func (g rangeGate) Allow(ctx context.Context, d module.Destination) error {
	if d.IP.IsValid() {
		ip := d.IP.Unmap()
		in := false
		for _, p := range g.ranges {
			if p.Contains(ip) {
				in = true
				break
			}
		}
		if !in || !g.allow(ip) {
			return fmt.Errorf("%s is outside the agent's ranges: %w", ip, module.ErrExcluded)
		}
	}
	return g.inner.Allow(ctx, d)
}
