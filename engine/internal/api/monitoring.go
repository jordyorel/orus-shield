package api

import (
	"context"

	"github.com/jordyorel/orus-shield/engine/internal/plan"
	"github.com/jordyorel/orus-shield/engine/internal/store"
)

// startMonitoring runs when an organization's offer gains monitoring (a
// trial or a subscription after Gratuit): what the customer just bought
// starts at once. Each verified domain gets a full scan with the offer's
// modules (ports and known vulnerabilities, which the free audit did not
// check), and a weekly schedule is set when none was chosen (Saturday
// night, 2:00 in the organization's time zone), changeable in Réglages.
//
// before is the offer in force before the change. Best effort: the
// subscription is recorded either way, failures are logged.
func (s *Server) startMonitoring(ctx context.Context, org *store.Org, before plan.Plan, actor string) {
	if before.Monitoring {
		return
	}
	eff, err := org.Plan(ctx, s.cfg.Now())
	if err != nil {
		s.log.Warn("start monitoring: read offer", "err", err)
		return
	}
	p := eff.Plan
	if !p.Monitoring {
		return
	}
	st, err := org.Settings(ctx)
	if err != nil {
		s.log.Warn("start monitoring: read settings", "err", err)
		return
	}
	if st.Frequency == "" && p.Allows(plan.Weekly) {
		st.Frequency, st.Weekday, st.Hour = "weekly", 6, 2
		if err := org.SaveSettings(ctx, st, false, actor); err != nil {
			s.log.Warn("start monitoring: save schedule", "err", err)
			return
		}
	}
	ts, err := s.targetSettingsFrom(st, p, s.cfg.Now())
	if err != nil {
		s.log.Warn("start monitoring: schedule", "err", err)
		return
	}
	targets, err := org.ListTargets(ctx)
	if err != nil {
		s.log.Warn("start monitoring: list targets", "err", err)
		return
	}
	modules := s.scheduledModules(st, p)
	for _, t := range targets {
		if ts.Schedule != nil || ts.RatePerSec != nil {
			if _, err := org.UpdateTargetSettings(ctx, t.ID, ts); err != nil {
				s.log.Warn("start monitoring: target schedule", "err", err)
			}
		}
		if t.Internal || !t.Verified() || len(modules) == 0 {
			continue
		}
		if _, err := org.EnqueueScan(ctx, t.ID, modules, actor); err != nil {
			s.log.Warn("start monitoring: queue scan", "err", err)
		}
	}
}
