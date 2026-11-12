package plan

import (
	"testing"
	"time"
)

func TestResolve(t *testing.T) {
	now := time.Date(2026, 11, 12, 12, 0, 0, 0, time.UTC)
	at := func(d time.Duration) *time.Time { v := now.Add(d); return &v }
	day := 24 * time.Hour

	tests := []struct {
		name    string
		sub     *Subscription
		want    ID
		lapsed  bool
		inGrace bool
	}{
		{"no subscription", nil, Discovery, false, false},
		{"unknown plan", &Subscription{Plan: "gold", Status: Active}, Discovery, false, false},
		{"trial running", &Subscription{Plan: SME, Status: Trialing, TrialEndsAt: at(day)}, SME, false, false},
		{"trial over", &Subscription{Plan: SME, Status: Trialing, TrialEndsAt: at(-day)}, Discovery, true, false},
		{"active without end", &Subscription{Plan: Pro, Status: Active}, Pro, false, false},
		{"active in period", &Subscription{Plan: Pro, Status: Active, PeriodEnd: at(day)}, Pro, false, false},
		{"active in grace", &Subscription{Plan: Pro, Status: Active, PeriodEnd: at(-2 * day)}, Pro, false, true},
		{"active past grace", &Subscription{Plan: Pro, Status: Active, PeriodEnd: at(-(GraceDays + 1) * day)}, Discovery, true, false},
		{"canceled in period", &Subscription{Plan: SME, Status: Canceled, PeriodEnd: at(day)}, SME, false, false},
		{"canceled, no grace", &Subscription{Plan: SME, Status: Canceled, PeriodEnd: at(-day)}, Discovery, true, false},
		{"canceled without end", &Subscription{Plan: SME, Status: Canceled}, Discovery, true, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Resolve(tt.sub, now)
			if got.Plan.ID != tt.want || got.Lapsed != tt.lapsed || got.InGrace != tt.inGrace {
				t.Errorf("Resolve = %s lapsed=%v grace=%v, want %s lapsed=%v grace=%v",
					got.Plan.ID, got.Lapsed, got.InGrace, tt.want, tt.lapsed, tt.inGrace)
			}
		})
	}
}

func TestLimits(t *testing.T) {
	free, _ := Get(Discovery)
	sme, _ := Get(SME)
	if free.Allows(Weekly) || !free.Allows(Monthly) {
		t.Error("the free offer allows monthly scans only")
	}
	if !sme.Allows(Weekly) || sme.Allows(Daily) {
		t.Error("Essentiel allows weekly scans, not daily")
	}
	if !Within(3, 3) || Within(4, 3) || !Within(1000, 0) {
		t.Error("Within: n fits a limit, 0 is unlimited")
	}
	for _, p := range Plans {
		if p.Name == "" || p.MaxFrequency == 0 {
			t.Errorf("plan %s is incomplete", p.ID)
		}
	}
}
