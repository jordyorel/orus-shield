package api

import (
	"net/http"
	"time"

	"github.com/jordyorel/orus-shield/engine/internal/plan"
	"github.com/jordyorel/orus-shield/engine/internal/store"
)

// planJSON is one offer and what it allows. Limits: 0 means unlimited.
type planJSON struct {
	ID            plan.ID `json:"id"`
	Name          string  `json:"name"`
	Domains       int     `json:"domains"`
	HostsPerScan  int     `json:"hosts_per_scan"`
	Members       int     `json:"members"`
	ActiveModules bool    `json:"active_modules"`
	MaxFrequency  string  `json:"max_frequency"` // monthly, weekly, daily
	Alerts        bool    `json:"alerts"`
	Reports       bool    `json:"reports"`
	Threats       bool    `json:"threats"`
	DeepScans     bool    `json:"deep_scans"`
	DeepPerMonth  int     `json:"deep_scans_per_month"` // 0: unlimited
	APIScans      bool    `json:"api_scans"`
	AuthScans     bool    `json:"auth_scans"`
	Agents        bool    `json:"agents"`
	USDMonthly    int     `json:"usd_monthly"`
	USDYearly     int     `json:"usd_yearly"` // per month, billed yearly
	OnQuote       bool    `json:"on_quote"`
}

func toPlanJSON(p plan.Plan) planJSON {
	freq := map[plan.Frequency]string{plan.Monthly: "monthly", plan.Weekly: "weekly", plan.Daily: "daily"}[p.MaxFrequency]
	return planJSON{ID: p.ID, Name: p.Name, Domains: p.Domains, HostsPerScan: p.HostsPerScan, Members: p.Members,
		ActiveModules: p.ActiveModules, MaxFrequency: freq, Alerts: p.Alerts, Reports: p.Reports, Threats: p.Threats, DeepScans: p.DeepScans, DeepPerMonth: p.DeepScansPerMonth, APIScans: p.APIScans, AuthScans: p.AuthScans, Agents: p.Agents,
		USDMonthly: p.USDMonthly, USDYearly: p.USDYearly, OnQuote: p.OnQuote}
}

type usageJSON struct {
	Domains int `json:"domains"`
	Members int `json:"members"`
	// DeepScans run this calendar month (UTC).
	DeepScans int `json:"deep_scans"`
}

type subscriptionJSON struct {
	Plan planJSON `json:"plan"` // the offer in force now
	// Status is the stored subscription's: trialing, active, canceled, or
	// "none" (no subscription, the free offer).
	Status  string     `json:"status"`
	Until   *time.Time `json:"until"`    // when the offer in force stops; null: it does not
	InGrace bool       `json:"in_grace"` // period over, grace days running
	Lapsed  bool       `json:"lapsed"`   // a paid offer or trial ended: back on Gratuit
	Usage   usageJSON  `json:"usage"`
	Plans   []planJSON `json:"plans"` // every offer, for comparison
}

// subscription answers GET /orgs/{org}/subscription.
func (s *Server) subscription(w http.ResponseWriter, r *http.Request, req orgRequest) {
	ctx := r.Context()
	sub, err := req.org.Subscription(ctx)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	eff := plan.Resolve(sub, s.cfg.Now())
	domains, err := req.org.CountTargets(ctx)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	members, err := s.acct.Members(ctx, req.org.ID())
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	deep, err := req.org.DeepScansSince(ctx, store.MonthStart(s.cfg.Now()))
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	out := subscriptionJSON{
		Plan: toPlanJSON(eff.Plan), Status: "none", Until: eff.Until, InGrace: eff.InGrace, Lapsed: eff.Lapsed,
		Usage: usageJSON{Domains: domains, Members: len(members), DeepScans: deep},
	}
	if sub != nil {
		out.Status = string(sub.Status)
	}
	out.Plans = allPlans()
	writeJSON(w, http.StatusOK, out)
}

func allPlans() []planJSON {
	out := make([]planJSON, 0, len(plan.Plans))
	for _, p := range plan.Plans {
		out = append(out, toPlanJSON(p))
	}
	return out
}

// listPlans answers GET /plans: public, the same for everyone.
func (s *Server) listPlans(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, list[planJSON]{Items: allPlans()})
}
