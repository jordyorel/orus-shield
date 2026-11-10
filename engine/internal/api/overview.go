package api

import (
	"net/http"
	"slices"
	"time"

	"github.com/jordyorel/orus-shield/engine/internal/finding"
	"github.com/jordyorel/orus-shield/engine/internal/posture"
	"github.com/jordyorel/orus-shield/engine/internal/store"
)

// The overview feeds the dashboard's first screen. Every figure is computed
// from stored scans (docs/ui-adaptation.md, rule 1); the dashboard only
// formats them. Nothing here comes from the AI layer.

// staleAfter is when a target without a finished scan becomes a priority
// action ("no scan for N days").
const staleAfter = 7 * 24 * time.Hour

// maxPriorities bounds the priority list: a short list gets read.
const maxPriorities = 5

type overviewTarget struct {
	ID            string         `json:"id"`
	Domain        string         `json:"domain"`
	Verified      bool           `json:"verified"`
	LastScanAt    *time.Time     `json:"last_scan_at"`
	Stale         bool           `json:"stale"` // no finished scan within staleAfter
	OpenFindings  map[string]int `json:"open_findings"`
	PostureScore  *int           `json:"posture_score"`
	CurrentAssets int            `json:"current_assets"`
}

type trendPoint struct {
	At    time.Time `json:"at"`
	Score *int      `json:"score"` // null: no score yet on that day
}

// remediationJSON compares the period with the one before, of the same
// length. Means are in seconds, null without fixes.
type remediationJSON struct {
	Fixed               int      `json:"fixed"`
	MeanSeconds         *float64 `json:"mean_seconds"`
	PreviousFixed       int      `json:"previous_fixed"`
	PreviousMeanSeconds *float64 `json:"previous_mean_seconds"`
}

// priorityJSON is one entry of the priority list. Kind says which rule
// produced it: "finding" (open critical or high finding), "verify_target"
// (ownership not verified) or "scan_target" (never scanned, or not within
// staleAfter). The dashboard writes the sentence; the API gives the facts.
type priorityJSON struct {
	Kind       string           `json:"kind"`
	TargetID   string           `json:"target_id"`
	Domain     string           `json:"domain"`
	FindingID  string           `json:"finding_id,omitempty"`
	Severity   finding.Severity `json:"severity,omitempty"`
	Title      string           `json:"title,omitempty"`
	Asset      string           `json:"asset,omitempty"`
	FirstSeen  *time.Time       `json:"first_seen,omitempty"`
	LastScanAt *time.Time       `json:"last_scan_at,omitempty"`
}

type overviewJSON struct {
	Days            int            `json:"days"`
	Targets         int            `json:"targets"`
	VerifiedTargets int            `json:"verified_targets"`
	OpenFindings    map[string]int `json:"open_findings"` // by severity, all targets
	Assets          int            `json:"assets"`
	NewAssets       int            `json:"new_assets"` // first seen within the period
	// Score pools every target's checks (posture.Series): not an average
	// of the targets' scores. Null when nothing was evaluated.
	Score *int `json:"score"`
	// ScoreChange is the last score of the trend minus the first one;
	// null with fewer than two days measured.
	ScoreChange *int             `json:"score_change"`
	Trend       []trendPoint     `json:"trend"` // one point per day, the last one now
	Remediation remediationJSON  `json:"remediation"`
	Priorities  []priorityJSON   `json:"priorities"`
	PerTarget   []overviewTarget `json:"per_target"`
}

// overview answers GET /orgs/{org}/overview?days=N (1 to 365, default 30).
func (s *Server) overview(w http.ResponseWriter, r *http.Request, req orgRequest) {
	days, ok := intParam(w, r, "days", 30, 1, 365)
	if !ok {
		return
	}
	ctx := r.Context()
	now := s.cfg.Now()
	period := time.Duration(days) * 24 * time.Hour
	since := now.Add(-period)

	sums, err := req.org.Overview(ctx)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	points, err := req.org.PosturePoints(ctx, since)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	// until is just after now: a fix recorded this very second counts.
	rem, err := req.org.Remediation(ctx, since, now.Add(time.Second))
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	prev, err := req.org.Remediation(ctx, since.Add(-period), since)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	newAssets, err := req.org.NewAssets(ctx, since)
	if err != nil {
		s.internalError(w, r, err)
		return
	}

	out := overviewJSON{
		Days: days, OpenFindings: map[string]int{}, NewAssets: newAssets,
		Trend: []trendPoint{}, Priorities: []priorityJSON{}, PerTarget: []overviewTarget{},
		Remediation: remediationJSON{
			Fixed: rem.Fixed, MeanSeconds: meanSeconds(rem),
			PreviousFixed: prev.Fixed, PreviousMeanSeconds: meanSeconds(prev),
		},
	}

	times := make([]time.Time, days+1)
	for i := range times {
		times[i] = now.Add(-time.Duration(days-i) * 24 * time.Hour)
	}
	series := posture.Series(points, times)
	for i, sc := range series {
		out.Trend = append(out.Trend, trendPoint{At: times[i], Score: sc})
	}
	out.Score = series[len(series)-1]
	if delta, ok := posture.Change(series); ok {
		out.ScoreChange = &delta
	}

	var urgent []priorityJSON
	for _, t := range sums {
		out.Targets++
		if t.Verified {
			out.VerifiedTargets++
		}
		out.Assets += t.CurrentAssets
		for sev, n := range t.OpenFindings {
			out.OpenFindings[sev] += n
		}
		out.PerTarget = append(out.PerTarget, overviewTarget{
			ID: t.ID, Domain: t.Domain, Verified: t.Verified, LastScanAt: t.LastScanAt,
			Stale:        t.LastScanAt == nil || now.Sub(*t.LastScanAt) > staleAfter,
			OpenFindings: t.OpenFindings, PostureScore: t.PostureScore, CurrentAssets: t.CurrentAssets,
		})
		if t.OpenFindings[string(finding.SeverityCritical)]+t.OpenFindings[string(finding.SeverityHigh)] == 0 {
			continue
		}
		fs, err := req.org.ListFindings(ctx, t.ID)
		if err != nil {
			s.internalError(w, r, err)
			return
		}
		for _, f := range fs {
			if f.Status == finding.StatusOpen && (f.Severity == finding.SeverityCritical || f.Severity == finding.SeverityHigh) {
				urgent = append(urgent, priorityJSON{
					Kind: "finding", TargetID: t.ID, Domain: t.Domain, FindingID: f.ID,
					Severity: f.Severity, Title: f.Title, Asset: f.Asset, FirstSeen: &f.FirstSeen,
				})
			}
		}
	}
	out.Priorities = priorities(urgent, sums, now)
	writeJSON(w, http.StatusOK, out)
}

func meanSeconds(r store.Remediation) *float64 {
	if r.Fixed == 0 {
		return nil
	}
	s := r.Mean.Seconds()
	return &s
}

// priorities orders the priority list by fixed rules, most urgent first:
// open critical then high findings (oldest first), then targets to verify,
// then targets without a recent scan. The AI layer may later explain it for
// the customer's context; it never adds entries (rule 8).
func priorities(urgent []priorityJSON, sums []store.TargetSummary, now time.Time) []priorityJSON {
	slices.SortStableFunc(urgent, func(a, b priorityJSON) int {
		if c := b.Severity.Rank() - a.Severity.Rank(); c != 0 {
			return c
		}
		return a.FirstSeen.Compare(*b.FirstSeen)
	})
	out := urgent
	for _, t := range sums {
		if !t.Verified {
			out = append(out, priorityJSON{Kind: "verify_target", TargetID: t.ID, Domain: t.Domain})
		}
	}
	for _, t := range sums {
		if t.LastScanAt == nil || now.Sub(*t.LastScanAt) > staleAfter {
			out = append(out, priorityJSON{Kind: "scan_target", TargetID: t.ID, Domain: t.Domain, LastScanAt: t.LastScanAt})
		}
	}
	if out == nil {
		return []priorityJSON{}
	}
	return out[:min(len(out), maxPriorities)]
}
