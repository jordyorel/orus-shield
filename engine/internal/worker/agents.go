package worker

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"

	"github.com/jordyorel/orus-shield/engine/internal/asset"
	"github.com/jordyorel/orus-shield/engine/internal/module"
	"github.com/jordyorel/orus-shield/engine/internal/plan"
	"github.com/jordyorel/orus-shield/engine/internal/store"
)

// agentPayload is what an agent sent for a scan (api.agentResultRequest).
type agentPayload struct {
	Attempt int                        `json:"attempt"`
	Results map[string]json.RawMessage `json:"results"`
	Failed  map[string]string          `json:"failed"`
}

// maxAgentError bounds a failure message an agent sends.
const maxAgentError = 500

// ingestAgentResult records one agent submission, if any: each module's
// output is validated like the worker's own (checkResult), and every
// address it reports must be in the agent's declared private ranges. A
// module that fails validation is recorded as failed, so its findings keep
// their state.
func (w *Worker) ingestAgentResult(ctx context.Context) (bool, error) {
	r, ok, err := w.store.ClaimAgentResult(ctx)
	if err != nil {
		return false, fmt.Errorf("claim agent result: %w", err)
	}
	if !ok {
		return false, nil
	}
	sc := r.Scan
	log := w.log.With("scan_id", sc.ID, "domain", sc.Domain, "agent_id", r.AgentID)
	var p agentPayload
	if err := json.Unmarshal(r.Payload, &p); err != nil {
		log.Warn("agent result unreadable", "err", err)
		return true, w.store.FailScan(ctx, sc.ID, sc.Attempt, w.cfg.ID, "agent result unreadable")
	}
	var ranges []netip.Prefix
	for _, s := range r.Ranges {
		if pr, err := netip.ParsePrefix(s); err == nil {
			ranges = append(ranges, pr)
		}
	}
	sub, err := w.store.SubscriptionOf(ctx, sc.OrgID)
	if err != nil {
		log.Warn("read subscription", "err", err)
		sub = nil
	}
	offer := plan.Resolve(sub, w.now()).Plan

	result := store.ScanResult{
		ScanID: sc.ID, Attempt: p.Attempt, WorkerID: w.cfg.ID, At: w.now(), NoAlerts: !offer.Alerts,
		Failed: map[string]string{}, Assets: map[string][]asset.Asset{}, Checks: map[string][]module.CheckOutcome{},
	}
	for _, id := range sc.Modules {
		m, known := w.modules.Get(id)
		raw, sent := p.Results[id]
		switch {
		case !known:
			result.Failed[id] = "unknown module"
			continue
		case !sent:
			msg := p.Failed[id]
			if msg == "" {
				msg = "no result from the agent"
			}
			result.Failed[id] = "agent: " + truncate(msg, maxAgentError)
			continue
		}
		var res module.Result
		if err := json.Unmarshal(raw, &res); err != nil {
			result.Failed[id] = "agent: unreadable result"
			continue
		}
		res, checks, err := w.checkResult(id, m.Info(), sc.Domain, res)
		if err == nil {
			err = inRanges(res, ranges)
		}
		if err != nil {
			log.Warn("agent result rejected", "module", id, "err", err)
			result.Failed[id] = "agent result rejected: " + truncate(err.Error(), maxAgentError)
			continue
		}
		result.Succeeded = append(result.Succeeded, id)
		result.Findings = append(result.Findings, res.Findings...)
		result.Assets[id] = res.Assets
		result.Checks[id] = checks
	}
	if err := w.store.FinishScan(ctx, result); err != nil {
		return true, fmt.Errorf("record agent scan %s: %w", sc.ID, err)
	}
	log.Info("agent scan recorded", "succeeded", result.Succeeded, "findings", len(result.Findings))
	return true, nil
}

// inRanges checks that every address a module reported is in the agent's
// ranges: an agent can only speak for the networks it was given.
func inRanges(res module.Result, ranges []netip.Prefix) error {
	in := func(s string) bool {
		a, err := netip.ParseAddr(s)
		if err != nil {
			return false
		}
		a = a.Unmap()
		for _, p := range ranges {
			if p.Contains(a) {
				return true
			}
		}
		return false
	}
	host := func(v string) string { // "ip", "ip:port", "ip:port/tcp", "[v6]:port"
		v = strings.TrimSuffix(v, "/tcp")
		if ap, err := netip.ParseAddrPort(v); err == nil {
			return ap.Addr().String()
		}
		return v
	}
	for _, a := range res.Assets {
		if (a.Kind == asset.KindIP || a.Kind == asset.KindService) && !in(host(a.Value)) {
			return fmt.Errorf("address %s is outside the agent's ranges", a.Value)
		}
	}
	for _, f := range res.Findings {
		if h := host(f.Asset); isAddr(h) && !in(h) {
			return fmt.Errorf("finding %s on %s, outside the agent's ranges", f.CheckID, f.Asset)
		}
	}
	return nil
}

func isAddr(s string) bool {
	_, err := netip.ParseAddr(s)
	return err == nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
