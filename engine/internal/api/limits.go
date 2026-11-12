package api

import (
	"fmt"
	"net/http"

	"github.com/jordyorel/orus-shield/engine/internal/module"
	"github.com/jordyorel/orus-shield/engine/internal/plan"
	"github.com/jordyorel/orus-shield/engine/internal/schedule"
)

// codePlanLimit marks a request the organization's offer does not allow.
// The dashboard shows the message and points to Paramètres > Abonnement.
const codePlanLimit = "plan_limit"

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
