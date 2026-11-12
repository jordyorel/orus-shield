package api

import (
	"context"
	"math"
	"strconv"
	"strings"

	"github.com/jordyorel/orus-shield/engine/internal/finding"
	"github.com/jordyorel/orus-shield/engine/internal/module"
	"github.com/jordyorel/orus-shield/engine/internal/posture"
	"github.com/jordyorel/orus-shield/engine/internal/store"
)

// fixMinutes estimates how long fixing a finding takes, by module: the
// "environ 15 min" of the dashboard. A product estimate written here, not
// a scan result; refine per check when customers report real times.
var fixMinutes = map[string]int{
	"email": 15, // a DNS record to publish or tighten
	"tls":   10, // renew a certificate, change the server's protocols
	"web":   15, // a header or a cookie flag in the server configuration
	"ports": 20, // a firewall rule, a service to stop or update
	"vulns": 30, // a software update
	"zap":   60, // a change in the application's code
	"api":   45, // a change in the API's code or its gateway
	"cdn":   15,
}

// cveJSON is what a known-vulnerability finding says about its CVE,
// read back from the vulns module's evidence and references.
type cveJSON struct {
	ID   string   `json:"id,omitempty"`
	Name string   `json:"name,omitempty"` // the template's name, emerging threats only
	CVSS *float64 `json:"cvss,omitempty"`
	EPSS *float64 `json:"epss,omitempty"` // probability of exploitation within 30 days
	KEV  bool     `json:"kev"`            // in CISA's catalog of exploited vulnerabilities
}

// findingExtras are computed for the dashboard; the finding itself is
// unchanged (schema of package finding).
type findingExtras struct {
	Category module.Category `json:"category,omitempty"`
	// Minutes: estimated time to fix (fixMinutes).
	Minutes int `json:"minutes"`
	// Gain: points the target's posture score would win if the finding's
	// check passed, shared among the check's open findings. 0 for findings
	// that are not open.
	Gain int `json:"gain"`
	// Emerging: the finding comes from a recent CVE template matched to a
	// technology of the target (package threats).
	Emerging bool     `json:"emerging"`
	CVE      *cveJSON `json:"cve,omitempty"`
}

// targetEnricher computes the extras of one target's findings.
type targetEnricher struct {
	checks   []store.CheckState
	score    int
	hasScore bool
	open     map[string]int    // open findings by check
	threats  map[string]string // template ID -> name, matched on this target
}

func (s *Server) enricher(ctx context.Context, org *store.Org, targetID string, fs []finding.Finding, threats []store.ThreatView) (*targetEnricher, error) {
	checks, err := org.CheckStatuses(ctx, targetID)
	if err != nil {
		return nil, err
	}
	e := &targetEnricher{checks: checks, open: map[string]int{}, threats: map[string]string{}}
	if sc := posture.Compute(postureChecks(checks, "")).Score; sc != nil {
		e.score, e.hasScore = *sc, true
	}
	for _, f := range fs {
		if f.Status == finding.StatusOpen {
			e.open[f.CheckID]++
		}
	}
	for _, t := range threats {
		if t.TargetID == targetID {
			e.threats[t.TemplateID] = t.Name
		}
	}
	return e, nil
}

// postureChecks converts check states, passing the check pass (if any).
func postureChecks(states []store.CheckState, pass string) []posture.Check {
	out := make([]posture.Check, 0, len(states))
	for _, c := range states {
		st := c.Status
		if c.CheckID == pass && st == module.CheckFailed {
			st = module.CheckPassed
		}
		out = append(out, posture.Check{ID: c.CheckID, Category: c.Category, Severity: c.Severity, Status: st})
	}
	return out
}

func (e *targetEnricher) extras(f finding.Finding) findingExtras {
	x := findingExtras{Minutes: fixMinutes[f.ModuleID]}
	if x.Minutes == 0 {
		x.Minutes = 15
	}
	for _, c := range e.checks {
		if c.CheckID == f.CheckID {
			x.Category = c.Category
		}
	}
	if f.Status == finding.StatusOpen && e.hasScore && e.open[f.CheckID] > 0 {
		if sc := posture.Compute(postureChecks(e.checks, f.CheckID)).Score; sc != nil && *sc > e.score {
			x.Gain = int(math.Round(float64(*sc-e.score) / float64(e.open[f.CheckID])))
		}
	}
	if f.ModuleID == "vulns" {
		x.CVE = parseCVE(f)
		if i := strings.LastIndexByte(f.Asset, '#'); i >= 0 {
			if name, ok := e.threats[f.Asset[i+1:]]; ok {
				x.Emerging = true
				if x.CVE != nil {
					x.CVE.Name = name
				}
			}
		}
	}
	return x
}

// parseCVE reads the CVE facts the vulns module wrote in a finding's
// evidence ("cvss: 8.1", "epss: 0.9123", "known exploited: yes") and
// references. nil when there is none of them.
func parseCVE(f finding.Finding) *cveJSON {
	c := &cveJSON{}
	for _, ref := range f.References {
		if strings.HasPrefix(ref, "CVE-") {
			c.ID = ref
			break
		}
	}
	for line := range strings.SplitSeq(f.Evidence, "\n") {
		k, v, ok := strings.Cut(line, ": ")
		if !ok {
			continue
		}
		switch k {
		case "cvss":
			if n, err := strconv.ParseFloat(v, 64); err == nil && n >= 0 && n <= 10 {
				c.CVSS = &n
			}
		case "epss":
			if n, err := strconv.ParseFloat(v, 64); err == nil && n >= 0 && n <= 1 {
				c.EPSS = &n
			}
		case "known exploited":
			c.KEV = strings.HasPrefix(v, "yes")
		}
	}
	if c.ID == "" && c.CVSS == nil && c.EPSS == nil && !c.KEV {
		return nil
	}
	return c
}
