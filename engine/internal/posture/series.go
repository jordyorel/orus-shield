package posture

import (
	"slices"
	"time"
)

// Plus returns the sum of two tallies.
//
// Summing the tallies of several targets gives the organization's score
// with the same rule as one target's: the share of evaluated weight that
// passed, over every domain together. A domain with more checks evaluated
// weighs more; a domain with nothing evaluated does not count. This is not
// the average of the domains' scores, which would let a domain with a
// single passed check weigh as much as a fully audited one.
func (t Tally) Plus(o Tally) Tally {
	return Tally{
		Passed:          t.Passed + o.Passed,
		Failed:          t.Failed + o.Failed,
		NotApplicable:   t.NotApplicable + o.NotApplicable,
		PassedWeight:    t.PassedWeight + o.PassedWeight,
		EvaluatedWeight: t.EvaluatedWeight + o.EvaluatedWeight,
	}
}

// Point is a target's total tally at one snapshot.
type Point struct {
	TargetID string
	At       time.Time
	Total    Tally
}

// Series returns the organization's score at each time of at, which must
// be in ascending order. At each time, every target counts with its latest
// point at or before that time, and the tallies are pooled with Plus. A
// time before any point, or where nothing with a weight was evaluated,
// gets nil: no data is never drawn as a score.
func Series(points []Point, at []time.Time) []*int {
	sorted := slices.SortedStableFunc(slices.Values(points), func(a, b Point) int {
		return a.At.Compare(b.At)
	})
	latest := make(map[string]Tally)
	out := make([]*int, len(at))
	next := 0
	for i, t := range at {
		for next < len(sorted) && !sorted[next].At.After(t) {
			latest[sorted[next].TargetID] = sorted[next].Total
			next++
		}
		var sum Tally
		for _, tally := range latest {
			sum = sum.Plus(tally)
		}
		out[i] = sum.Score()
	}
	return out
}

// Change is the difference between the first and the last score of a
// series, skipping the times without a score. ok is false when fewer than
// two times have one: a single measure is not a trend.
func Change(series []*int) (delta int, ok bool) {
	first, last := -1, -1
	for i, s := range series {
		if s == nil {
			continue
		}
		if first < 0 {
			first = i
		}
		last = i
	}
	if first < 0 || last == first {
		return 0, false
	}
	return *series[last] - *series[first], true
}
