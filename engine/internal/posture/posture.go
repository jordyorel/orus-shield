// Package posture computes a target's security posture score from the
// status of its checks.
//
// The score is computed by the engine, deterministically, from stored check
// results: the AI layer may explain it, never produce it (security rule 8).
// Every snapshot keeps the counts that led to the score, so the dashboard
// can show why.
package posture

import (
	"maps"
	"math"
	"slices"
	"strings"

	"github.com/jordyorel/orus-shield/engine/internal/finding"
	"github.com/jordyorel/orus-shield/engine/internal/module"
)

// Weight is how much a check counts in the score, by its catalog severity.
// Info checks are shown but do not move the score: they describe, they do
// not warn.
func Weight(s finding.Severity) int {
	switch s {
	case finding.SeverityCritical:
		return 10
	case finding.SeverityHigh:
		return 6
	case finding.SeverityMedium:
		return 3
	case finding.SeverityLow:
		return 1
	}
	return 0
}

// Check is the latest status of one catalog check on a target.
type Check struct {
	ID       string
	Category module.Category
	Severity finding.Severity
	Status   module.CheckStatus
}

// Tally counts checks by status, with their weights.
type Tally struct {
	Passed          int `json:"passed"`
	Failed          int `json:"failed"`
	NotApplicable   int `json:"not_applicable"`
	PassedWeight    int `json:"passed_weight"`
	EvaluatedWeight int `json:"evaluated_weight"` // passed + failed
}

// Score returns 0 to 100, or nil when nothing with a weight was evaluated:
// no data is never shown as a score (no invented numbers).
func (t Tally) Score() *int {
	if t.EvaluatedWeight == 0 {
		return nil
	}
	s := int(math.Round(100 * float64(t.PassedWeight) / float64(t.EvaluatedWeight)))
	return &s
}

func (t *Tally) add(c Check) {
	w := Weight(c.Severity)
	switch c.Status {
	case module.CheckPassed:
		t.Passed++
		t.PassedWeight += w
		t.EvaluatedWeight += w
	case module.CheckFailed:
		t.Failed++
		t.EvaluatedWeight += w
	default:
		t.NotApplicable++
	}
}

// Snapshot is the posture of a target at one point in time.
type Snapshot struct {
	Score      *int                       `json:"score"`
	Total      Tally                      `json:"total"`
	BySeverity map[finding.Severity]Tally `json:"by_severity"`
	ByCategory map[module.Category]Tally  `json:"by_category"`
	// FailedChecks lists the failed check IDs, most severe first: the
	// "why" behind a low score.
	FailedChecks []string `json:"failed_checks"`
}

// Compute builds the snapshot of a set of checks.
//
// The score is the share of evaluated weight that passed:
//
//	score = round(100 * sum(weight of passed) / sum(weight of passed and failed))
//
// Not applicable checks count neither way. A failed critical check (weight
// 10) therefore costs as much as ten failed low ones.
func Compute(checks []Check) Snapshot {
	s := Snapshot{
		BySeverity:   make(map[finding.Severity]Tally),
		ByCategory:   make(map[module.Category]Tally),
		FailedChecks: []string{},
	}
	for _, c := range checks {
		s.Total.add(c)
		bySev := s.BySeverity[c.Severity]
		bySev.add(c)
		s.BySeverity[c.Severity] = bySev
		byCat := s.ByCategory[c.Category]
		byCat.add(c)
		s.ByCategory[c.Category] = byCat
		if c.Status == module.CheckFailed {
			s.FailedChecks = append(s.FailedChecks, c.ID)
		}
	}
	sev := make(map[string]finding.Severity, len(checks))
	for _, c := range checks {
		sev[c.ID] = c.Severity
	}
	slices.SortStableFunc(s.FailedChecks, func(a, b string) int {
		if d := sev[b].Rank() - sev[a].Rank(); d != 0 {
			return d
		}
		return strings.Compare(a, b)
	})
	s.Score = s.Total.Score()
	return s
}

// CategoryScores returns the score of each category that has one, for
// display. Categories with nothing evaluated are absent.
func (s Snapshot) CategoryScores() map[module.Category]int {
	out := make(map[module.Category]int)
	for _, cat := range slices.Sorted(maps.Keys(s.ByCategory)) {
		if score := s.ByCategory[cat].Score(); score != nil {
			out[cat] = *score
		}
	}
	return out
}
