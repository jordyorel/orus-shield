package posture

import (
	"slices"
	"testing"

	"github.com/jordyorel/orus-shield/engine/internal/finding"
	"github.com/jordyorel/orus-shield/engine/internal/module"
)

func check(id string, cat module.Category, sev finding.Severity, st module.CheckStatus) Check {
	return Check{ID: id, Category: cat, Severity: sev, Status: st}
}

const (
	pass = module.CheckPassed
	fail = module.CheckFailed
	na   = module.CheckNotApplicable
)

func TestScore(t *testing.T) {
	tests := []struct {
		name   string
		checks []Check
		want   *int // nil: no score
	}{
		{"nothing", nil, nil},
		{"only not applicable", []Check{check("a", module.CategoryTLS, finding.SeverityHigh, na)}, nil},
		{"only info", []Check{check("a", module.CategoryEmail, finding.SeverityInfo, fail)}, nil},
		{"all passed", []Check{
			check("a", module.CategoryTLS, finding.SeverityHigh, pass),
			check("b", module.CategoryTLS, finding.SeverityLow, pass),
		}, ptr(100)},
		{"all failed", []Check{check("a", module.CategoryTLS, finding.SeverityHigh, fail)}, ptr(0)},
		// passed 6 + 1 = 7, failed 10: 7 / 17 = 41.2%
		{"one critical failed", []Check{
			check("a", module.CategoryTLS, finding.SeverityCritical, fail),
			check("b", module.CategoryTLS, finding.SeverityHigh, pass),
			check("c", module.CategoryTLS, finding.SeverityLow, pass),
		}, ptr(41)},
		// not applicable checks are ignored: 3 / (3 + 1) = 75%
		{"not applicable ignored", []Check{
			check("a", module.CategoryEmail, finding.SeverityMedium, pass),
			check("b", module.CategoryEmail, finding.SeverityLow, fail),
			check("c", module.CategoryEmail, finding.SeverityCritical, na),
		}, ptr(75)},
		// rounding: 1 / 3 = 33.3%
		{"rounding", []Check{
			check("a", module.CategoryNetwork, finding.SeverityLow, pass),
			check("b", module.CategoryNetwork, finding.SeverityLow, fail),
			check("c", module.CategoryNetwork, finding.SeverityLow, fail),
		}, ptr(33)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Compute(tt.checks).Score
			if (got == nil) != (tt.want == nil) || (got != nil && *got != *tt.want) {
				t.Errorf("score = %v, want %v", deref(got), deref(tt.want))
			}
		})
	}
}

func TestSnapshotBreakdown(t *testing.T) {
	s := Compute([]Check{
		check("spf-missing", module.CategoryEmail, finding.SeverityHigh, pass),
		check("dmarc-policy-none", module.CategoryEmail, finding.SeverityMedium, fail),
		check("tls-cert-expired", module.CategoryTLS, finding.SeverityCritical, fail),
		check("tls-cert-weak-key", module.CategoryTLS, finding.SeverityMedium, pass),
		check("dkim-not-found", module.CategoryEmail, finding.SeverityInfo, na),
	})
	if s.Total.Passed != 2 || s.Total.Failed != 2 || s.Total.NotApplicable != 1 {
		t.Errorf("total = %+v", s.Total)
	}
	if want := []string{"tls-cert-expired", "dmarc-policy-none"}; !slices.Equal(s.FailedChecks, want) {
		t.Errorf("failed checks = %v, want %v (most severe first)", s.FailedChecks, want)
	}
	cats := s.CategoryScores()
	// email: 6 / 9 = 67; tls: 3 / 13 = 23
	if cats[module.CategoryEmail] != 67 || cats[module.CategoryTLS] != 23 {
		t.Errorf("category scores = %v", cats)
	}
	if _, ok := cats[module.CategoryNetwork]; ok {
		t.Error("a category with nothing evaluated has a score")
	}
	if crit := s.BySeverity[finding.SeverityCritical]; crit.Failed != 1 || crit.EvaluatedWeight != 10 {
		t.Errorf("critical tally = %+v", crit)
	}
}

func TestComputeIsDeterministic(t *testing.T) {
	checks := []Check{
		check("b", module.CategoryTLS, finding.SeverityHigh, fail),
		check("a", module.CategoryTLS, finding.SeverityHigh, fail),
		check("c", module.CategoryEmail, finding.SeverityCritical, fail),
	}
	reversed := slices.Clone(checks)
	slices.Reverse(reversed)
	a, b := Compute(checks), Compute(reversed)
	if !slices.Equal(a.FailedChecks, b.FailedChecks) || *a.Score != *b.Score {
		t.Errorf("order changes the result: %v vs %v", a.FailedChecks, b.FailedChecks)
	}
	if want := []string{"c", "a", "b"}; !slices.Equal(a.FailedChecks, want) {
		t.Errorf("failed checks = %v, want %v (severity, then ID)", a.FailedChecks, want)
	}
}

func ptr(n int) *int { return &n }

func deref(p *int) any {
	if p == nil {
		return "none"
	}
	return *p
}
