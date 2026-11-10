package posture

import (
	"fmt"
	"testing"
	"time"
)

func tally(passedWeight, evaluatedWeight int) Tally {
	return Tally{PassedWeight: passedWeight, EvaluatedWeight: evaluatedWeight}
}

func show(series []*int) string {
	out := ""
	for i, s := range series {
		if i > 0 {
			out += " "
		}
		if s == nil {
			out += "-"
		} else {
			out += fmt.Sprint(*s)
		}
	}
	return out
}

func TestPlusPoolsWeights(t *testing.T) {
	// A fully audited domain at 50 % and a domain with one passed low check:
	// the pooled score stays near 50, an average of scores would say 75.
	big := Tally{Passed: 5, Failed: 5, PassedWeight: 50, EvaluatedWeight: 100}
	small := Tally{Passed: 1, NotApplicable: 2, PassedWeight: 1, EvaluatedWeight: 1}
	sum := big.Plus(small)
	if sum.Passed != 6 || sum.Failed != 5 || sum.NotApplicable != 2 || sum.PassedWeight != 51 || sum.EvaluatedWeight != 101 {
		t.Fatalf("Plus = %+v", sum)
	}
	if got := *sum.Score(); got != 50 {
		t.Errorf("pooled score = %d, want 50", got)
	}
	if (Tally{}).Plus(Tally{}).Score() != nil {
		t.Error("nothing evaluated must have no score")
	}
}

func TestSeries(t *testing.T) {
	day := func(d int) time.Time { return time.Date(2026, 11, d, 12, 0, 0, 0, time.UTC) }
	at := []time.Time{day(1), day(2), day(3), day(4), day(5)}
	for _, tc := range []struct {
		name   string
		points []Point
		want   string
	}{
		{"no data", nil, "- - - - -"},
		{"one target", []Point{
			{"a", day(2), tally(5, 10)},
			{"a", day(4), tally(8, 10)},
		}, "- 50 50 80 80"},
		{"point exactly at the time counts", []Point{{"a", day(1), tally(1, 4)}}, "25 25 25 25 25"},
		{"two targets pooled, latest each", []Point{
			{"b", day(3), tally(0, 10)}, // unsorted input
			{"a", day(1), tally(10, 10)},
			{"a", day(5), tally(5, 10)},
		}, "100 100 50 50 25"},
		{"nothing weighted is no score", []Point{{"a", day(2), Tally{NotApplicable: 3}}}, "- - - - -"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := show(Series(tc.points, at)); got != tc.want {
				t.Errorf("Series = %s, want %s", got, tc.want)
			}
		})
	}
}

func TestChange(t *testing.T) {
	n := func(v int) *int { return &v }
	for _, tc := range []struct {
		series []*int
		delta  int
		ok     bool
	}{
		{nil, 0, false},
		{[]*int{nil, nil}, 0, false},
		{[]*int{nil, n(60), nil}, 0, false},
		{[]*int{nil, n(60), nil, n(74), nil}, 14, true},
		{[]*int{n(80), n(70)}, -10, true},
	} {
		delta, ok := Change(tc.series)
		if delta != tc.delta || ok != tc.ok {
			t.Errorf("Change(%s) = %d, %v; want %d, %v", show(tc.series), delta, ok, tc.delta, tc.ok)
		}
	}
}
