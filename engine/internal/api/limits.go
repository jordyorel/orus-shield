package api

import (
	"fmt"
	"net/http"
	"slices"

	"github.com/jordyorel/orus-shield/engine/internal/module"
	"github.com/jordyorel/orus-shield/engine/internal/plan"
	"github.com/jordyorel/orus-shield/engine/internal/schedule"
)

// codePlanLimit marks a request the organization's offer does not allow.
// The dashboard shows the message and points to Paramètres > Abonnement.
const codePlanLimit = "plan_limit"

// codeAuditUsed marks a scan, or a fix to verify, refused because the
// organization's offer is a single audit and it was used. The dashboard
// answers with the trial offer.
const codeAuditUsed = "audit_used"

// checkMonitoring refuses what needs a scan after the single audit of an
// offer without monitoring (Gratuit): it answers 403 audit_used itself.
func (s *Server) checkMonitoring(w http.ResponseWriter, r *http.Request, req orgRequest, p plan.Plan, what string) bool {
	if p.Monitoring {
		return true
	}
	used, err := req.org.AuditUsed(r.Context())
	if err != nil {
		s.internalError(w, r, err)
		return false
	}
	if used {
		writeErrorCode(w, http.StatusForbidden, codeAuditUsed,
			fmt.Sprintf("the %s offer includes a single audit, already done: choose an offer to %s", p.Name, what))
		return false
	}
	return true
}

// planOf returns the plan in force; it answers 500 itself on failure.
func (s *Server) planOf(w http.ResponseWriter, r *http.Request, req orgRequest) (plan.Plan, bool) {
	eff, err := req.org.Plan(r.Context(), s.cfg.Now())
	if err != nil {
		s.internalError(w, r, err)
		return plan.Plan{}, false
	}
	return eff.Plan, true
}

func planLimit(w http.ResponseWriter, msg string) {
	writeErrorCode(w, http.StatusForbidden, codePlanLimit, msg)
}

// activeModules returns the active modules among ids.
func (s *Server) activeModules(ids []string) []string {
	var out []string
	for _, id := range ids {
		for _, m := range s.cfg.Catalog {
			if m.ID == id && m.Kind == module.KindActive {
				out = append(out, id)
			}
		}
	}
	return out
}

// allowedModules lists the modules a scan without an explicit list runs:
// all of them, minus the active ones on an offer without active modules.
func (s *Server) allowedModules(p plan.Plan) []string {
	if p.ActiveModules {
		return s.cfg.Modules
	}
	active := s.activeModules(s.cfg.Modules)
	var out []string
	for _, id := range s.cfg.Modules {
		if !slices.Contains(active, id) {
			out = append(out, id)
		}
	}
	return out
}

// checkModules refuses active modules on an offer without them.
func (s *Server) checkModules(w http.ResponseWriter, p plan.Plan, ids []string) bool {
	if active := s.activeModules(ids); len(active) > 0 && !p.ActiveModules {
		planLimit(w, fmt.Sprintf("the %s offer runs passive checks only (not %v)", p.Name, active))
		return false
	}
	return true
}

// frequencyOf maps a schedule frequency to the plan's scale.
func frequencyOf(f schedule.Frequency) plan.Frequency {
	switch f {
	case schedule.Daily:
		return plan.Daily
	case schedule.Weekly:
		return plan.Weekly
	}
	return plan.Monthly
}
