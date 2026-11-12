package api

import (
	"fmt"
	"net/http"
	"slices"
	"time"

	"github.com/jordyorel/orus-shield/engine/internal/plan"
	"github.com/jordyorel/orus-shield/engine/internal/schedule"
	"github.com/jordyorel/orus-shield/engine/internal/store"
)

// Réglages > Ce qu'on vérifie lists these modules with a switch; the
// others (discovery, cdn, web) always run: they feed the inventory and
// cost almost nothing.
var switchableModules = []string{"email", "tls", "ports", "vulns"}

// quickSkips are the modules the quick profile leaves out: the known
// vulnerability pass takes some 20 minutes per site.
var quickSkips = []string{"vulns"}

type orgSettingsJSON struct {
	AlertLevel      string   `json:"alert_level"` // critical, high, all
	EmailAlerts     bool     `json:"email_alerts"`
	Profile         string   `json:"profile"` // quick, standard
	DisabledModules []string `json:"disabled_modules"`
	// Frequency: daily, weekly, monthly; "" while none was chosen.
	Frequency  string `json:"frequency"`
	Weekday    int    `json:"weekday"` // 0 is Sunday
	Hour       int    `json:"hour"`
	TimeZone   string `json:"timezone"`
	RatePerSec int    `json:"rate_per_sec"` // 0: the worker's default
}

func toOrgSettingsJSON(s store.OrgSettings) orgSettingsJSON {
	return orgSettingsJSON{AlertLevel: s.AlertLevel, EmailAlerts: s.EmailAlerts, Profile: s.Profile,
		DisabledModules: s.DisabledModules, Frequency: s.Frequency, Weekday: s.Weekday, Hour: s.Hour,
		TimeZone: s.TimeZone, RatePerSec: s.RatePerSec}
}

// getSettings answers GET /orgs/{org}/settings.
func (s *Server) getSettings(w http.ResponseWriter, r *http.Request, req orgRequest) {
	st, err := req.org.Settings(r.Context())
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, toOrgSettingsJSON(st))
}

// scheduledModules are the modules every scheduled scan runs under st, on
// offer p: active ones are left out of an offer without them, rather than
// refused, so a free organization keeps its passive schedule.
func (s *Server) scheduledModules(st store.OrgSettings, p plan.Plan) []string {
	var out []string
	for _, id := range s.cfg.Modules {
		if slices.Contains(st.DisabledModules, id) {
			continue
		}
		if st.Profile == store.ProfileQuick && slices.Contains(quickSkips, id) {
			continue
		}
		if !p.ActiveModules && len(s.activeModules([]string{id})) > 0 {
			continue
		}
		out = append(out, id)
	}
	return out
}

// targetSettingsFrom turns the organization's settings into one target's
// settings: its schedule (none without a frequency) and its rate.
func (s *Server) targetSettingsFrom(st store.OrgSettings, p plan.Plan, now time.Time) (store.TargetSettings, error) {
	var ts store.TargetSettings
	if st.RatePerSec > 0 {
		rate := float64(st.RatePerSec)
		ts.RatePerSec = &rate
	}
	if st.Frequency == "" {
		return ts, nil
	}
	sched := schedule.Schedule{Frequency: schedule.Frequency(st.Frequency), Weekday: time.Weekday(st.Weekday),
		Hour: st.Hour, TimeZone: st.TimeZone}
	next, err := sched.Next(now)
	if err != nil {
		return ts, err
	}
	ts.Schedule = &store.TargetSchedule{Schedule: sched, Modules: s.scheduledModules(st, p), NextScanAt: next}
	return ts, nil
}

// putSettings answers PUT /orgs/{org}/settings: it checks the settings
// against the offer, stores them, and applies the schedule and the rate
// to every target of the organization.
func (s *Server) putSettings(w http.ResponseWriter, r *http.Request, req orgRequest) {
	var body orgSettingsJSON
	if !decode(w, r, &body) {
		return
	}
	st := store.OrgSettings{AlertLevel: body.AlertLevel, EmailAlerts: body.EmailAlerts, Profile: body.Profile,
		DisabledModules: body.DisabledModules, Frequency: body.Frequency, Weekday: body.Weekday, Hour: body.Hour,
		TimeZone: body.TimeZone, RatePerSec: body.RatePerSec}
	if st.DisabledModules == nil {
		st.DisabledModules = []string{}
	}
	if msg := validSettings(st); msg != "" {
		writeError(w, http.StatusBadRequest, msg)
		return
	}
	p, ok := s.planOf(w, r, req)
	if !ok {
		return
	}
	if st.Frequency != "" && !p.Allows(frequencyOf(schedule.Frequency(st.Frequency))) {
		planLimit(w, fmt.Sprintf("the %s offer does not allow %s scans", p.Name, st.Frequency))
		return
	}
	ctx := r.Context()
	ts, err := s.targetSettingsFrom(st, p, s.cfg.Now())
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid schedule: "+err.Error())
		return
	}
	if err := req.org.SaveSettings(ctx, st, actor(req)); err != nil {
		s.internalError(w, r, err)
		return
	}
	targets, err := req.org.ListTargets(ctx)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	for _, t := range targets {
		if ts.Schedule == nil && ts.RatePerSec == nil {
			break
		}
		if _, err := req.org.UpdateTargetSettings(ctx, t.ID, ts); err != nil {
			s.internalError(w, r, err)
			return
		}
	}
	writeJSON(w, http.StatusOK, toOrgSettingsJSON(st))
}

// validSettings returns why st is invalid, "" when it is valid.
func validSettings(st store.OrgSettings) string {
	if !slices.Contains([]string{store.AlertCritical, store.AlertHigh, store.AlertAll}, st.AlertLevel) {
		return "alert_level must be critical, high or all"
	}
	if st.Profile != store.ProfileQuick && st.Profile != store.ProfileStandard {
		return "profile must be quick or standard"
	}
	for _, m := range st.DisabledModules {
		if !slices.Contains(switchableModules, m) {
			return "disabled_modules: " + m + " cannot be switched off"
		}
	}
	if st.Frequency != "" && st.Frequency != "daily" && st.Frequency != "weekly" && st.Frequency != "monthly" {
		return "frequency must be daily, weekly, monthly or empty"
	}
	if st.Weekday < 0 || st.Weekday > 6 || st.Hour < 0 || st.Hour > 23 {
		return "weekday must be 0 to 6 and hour 0 to 23"
	}
	if _, err := time.LoadLocation(st.TimeZone); err != nil || st.TimeZone == "" || st.TimeZone == "Local" {
		return "timezone must be an IANA name such as Africa/Brazzaville"
	}
	if st.RatePerSec < 0 || st.RatePerSec > maxRatePerSec {
		return "rate_per_sec must be between 0 (default) and 200"
	}
	return ""
}

// applyOrgSettings gives a new target the organization's schedule and,
// when withRate, its rate.
func (s *Server) applyOrgSettings(r *http.Request, req orgRequest, p plan.Plan, t store.Target, withRate bool) (store.Target, error) {
	st, err := req.org.Settings(r.Context())
	if err != nil {
		return t, err
	}
	ts, err := s.targetSettingsFrom(st, p, s.cfg.Now())
	if err != nil {
		return t, err
	}
	if !withRate {
		ts.RatePerSec = nil
	}
	if ts.Schedule == nil && ts.RatePerSec == nil {
		return t, nil
	}
	return req.org.UpdateTargetSettings(r.Context(), t.ID, ts)
}
