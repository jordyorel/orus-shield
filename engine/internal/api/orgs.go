package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strconv"
	"time"

	"github.com/jordyorel/orus-shield/engine/internal/finding"
	"github.com/jordyorel/orus-shield/engine/internal/store"
)

// orgRequest is what organization handlers receive: the caller, their role,
// and the handle of the organization in the URL. There is no way to reach
// another organization's data from here.
type orgRequest struct {
	sess store.Session
	role string
	org  *store.Org
}

type orgHandler func(w http.ResponseWriter, r *http.Request, req orgRequest)

// withOrg resolves {org} from the URL: the caller must be a member, with at
// least minRole for writes. A non-member gets 404, as if the organization
// did not exist; a viewer attempting a write gets 403. An admin whose
// session was not opened with a second factor gets 403 mfa_required on
// every route of the organization, reads included: MFA is mandatory for
// admins, and a stolen admin password alone must not reach their data.
func (s *Server) withOrg(minRole string, h orgHandler) http.HandlerFunc {
	return s.withSession(func(w http.ResponseWriter, r *http.Request, sess store.Session, _ string) {
		orgID := r.PathValue("org")
		role, err := s.acct.Access(r.Context(), sess, orgID, minRole)
		if err != nil {
			s.accountError(w, r, err, http.StatusUnauthorized)
			return
		}
		org, err := s.org(orgID)
		if err != nil {
			writeError(w, http.StatusNotFound, "not found")
			return
		}
		h(w, r, orgRequest{sess: sess, role: role, org: org})
	})
}

func (s *Server) orgRoutes(mux *http.ServeMux) {
	read := func(pattern string, h orgHandler) {
		mux.HandleFunc("GET /api/v1/orgs/{org}"+pattern, s.withOrg(store.RoleViewer, h))
	}
	read("/overview", s.overview)
	read("/findings", s.orgFindings)
	read("/modules", s.listModules)
	read("/assets", s.orgAssets)
	read("/checks", s.orgChecks)
	read("/trends", s.trends)
	read("/threats", s.threats)
	read("/report", s.report)
	read("/subscription", s.subscription)
	read("/settings", s.getSettings)
	read("/agents", s.listAgents)
	read("/activity", s.activity)
	read("/scans", s.recentScans)
	read("/targets", s.listTargets)
	read("/targets/{target}", s.targetOnly(s.getTarget))
	read("/targets/{target}/assets", s.targetOnly(s.listAssets))
	read("/targets/{target}/apis", s.targetOnly(s.listAPIs))
	read("/targets/{target}/scans", s.targetOnly(s.listScans))
	read("/scans/{scan}", s.getScan)
	read("/targets/{target}/findings", s.targetOnly(s.listFindings))
	read("/targets/{target}/findings/{finding}/history", s.targetOnly(s.findingHistory))
	read("/targets/{target}/posture", s.targetOnly(s.posture))
	read("/targets/{target}/checks", s.targetOnly(s.checks))
	s.writeRoutes(mux)
}

// targetHandler runs with a target of the caller's organization.
type targetHandler func(w http.ResponseWriter, r *http.Request, req orgRequest, t store.Target)

// targetOnly loads {target} through the organization's handle: a target of
// another organization is 404, so sub-resources never answer "empty" for
// an ID that exists elsewhere.
func (s *Server) targetOnly(h targetHandler) orgHandler {
	return func(w http.ResponseWriter, r *http.Request, req orgRequest) {
		t, err := req.org.GetTarget(r.Context(), r.PathValue("target"))
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "not found")
			return
		}
		if err != nil {
			s.internalError(w, r, err)
			return
		}
		h(w, r, req, t)
	}
}

// ---- JSON shapes -----------------------------------------------------------

type targetJSON struct {
	ID              string          `json:"id"`
	Domain          string          `json:"domain"`
	Verified        bool            `json:"verified"`
	VerifiedAt      *time.Time      `json:"verified_at"`
	VerifyCheckedAt *time.Time      `json:"verify_checked_at"`
	RatePerSec      float64         `json:"rate_per_sec"`
	Exclusions      json.RawMessage `json:"exclusions"`
	CreatedAt       time.Time       `json:"created_at"`
	// Schedule is null for a target scanned on demand only.
	Schedule *scheduleJSON `json:"schedule"`
	// Internal: an agent's internal network, not a domain.
	Internal bool `json:"internal"`
}

// scheduleJSON is a target's schedule. Weekday: 0 is Sunday, 6 Saturday.
type scheduleJSON struct {
	Frequency  string    `json:"frequency"`
	Weekday    int       `json:"weekday"`
	Hour       int       `json:"hour"`
	TimeZone   string    `json:"timezone"`
	Modules    []string  `json:"modules"`
	NextScanAt time.Time `json:"next_scan_at"`
}

func toTargetJSON(t store.Target) targetJSON {
	out := targetJSON{
		ID: t.ID, Domain: t.Domain, Verified: t.Verified(), VerifiedAt: t.VerifiedAt,
		VerifyCheckedAt: t.VerifyCheckedAt, RatePerSec: t.RatePerSec, Exclusions: t.Exclusions, CreatedAt: t.CreatedAt,
		Internal: t.Internal,
	}
	if sc := t.Schedule; sc != nil {
		out.Schedule = &scheduleJSON{
			Frequency: string(sc.Frequency), Weekday: int(sc.Weekday), Hour: sc.Hour, TimeZone: sc.TimeZone,
			Modules: sc.Modules, NextScanAt: sc.NextScanAt,
		}
	}
	return out
}

type scanJSON struct {
	ID          string     `json:"id"`
	TargetID    string     `json:"target_id"`
	Domain      string     `json:"domain"`
	Modules     []string   `json:"modules"`
	RequestedBy string     `json:"requested_by"`
	Status      string     `json:"status"`
	Attempts    int        `json:"attempts"`
	Error       string     `json:"error,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	StartedAt   *time.Time `json:"started_at"`
	FinishedAt  *time.Time `json:"finished_at"`
	// Findings this scan opened and marked fixed; only in scan lists, for
	// finished scans.
	NewFindings   *int `json:"new_findings,omitempty"`
	FixedFindings *int `json:"fixed_findings,omitempty"`
}

func toScanJSON(sc store.Scan) scanJSON {
	return scanJSON{
		ID: sc.ID, TargetID: sc.TargetID, Domain: sc.Domain, Modules: sc.Modules, RequestedBy: sc.RequestedBy,
		Status: sc.Status, Attempts: sc.Attempt, Error: sc.Error, CreatedAt: sc.CreatedAt,
		StartedAt: sc.StartedAt, FinishedAt: sc.FinishedAt, NewFindings: sc.NewFindings, FixedFindings: sc.FixedFindings,
	}
}

// list wraps arrays in an object, so fields (pagination) can be added
// later without breaking clients.
type list[T any] struct {
	Items []T `json:"items"`
}

func listOf[T any](items []T) list[T] {
	if items == nil {
		items = []T{}
	}
	return list[T]{Items: items}
}

// ---- Handlers --------------------------------------------------------------

func (s *Server) listTargets(w http.ResponseWriter, r *http.Request, req orgRequest) {
	targets, err := req.org.ListTargets(r.Context())
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	out := make([]targetJSON, 0, len(targets))
	for _, t := range targets {
		out = append(out, toTargetJSON(t))
	}
	writeJSON(w, http.StatusOK, listOf(out))
}

func (s *Server) getTarget(w http.ResponseWriter, r *http.Request, req orgRequest, t store.Target) {
	writeJSON(w, http.StatusOK, toTargetJSON(t))
}

type assetJSON struct {
	ID        string            `json:"id"`
	Kind      string            `json:"kind"`
	Value     string            `json:"value"`
	Details   map[string]string `json:"details"`
	Sources   []string          `json:"sources"`
	FirstSeen time.Time         `json:"first_seen"`
	LastSeen  time.Time         `json:"last_seen"`
	GoneAt    *time.Time        `json:"gone_at"`
}

func (s *Server) listAssets(w http.ResponseWriter, r *http.Request, req orgRequest, t store.Target) {
	includeGone, ok := boolParam(w, r, "include_gone")
	if !ok {
		return
	}
	assets, err := req.org.ListAssets(r.Context(), t.ID, includeGone)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	out := make([]assetJSON, 0, len(assets))
	for _, a := range assets {
		details := a.Details
		if details == nil {
			details = map[string]string{}
		}
		out = append(out, assetJSON{ID: a.ID, Kind: string(a.Kind), Value: a.Value, Details: details,
			Sources: a.Sources, FirstSeen: a.FirstSeen, LastSeen: a.LastSeen, GoneAt: a.GoneAt})
	}
	writeJSON(w, http.StatusOK, listOf(out))
}

func (s *Server) listScans(w http.ResponseWriter, r *http.Request, req orgRequest, t store.Target) {
	limit, ok := intParam(w, r, "limit", 20, 1, 100)
	if !ok {
		return
	}
	scans, err := req.org.ListScans(r.Context(), t.ID, limit)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	out := make([]scanJSON, 0, len(scans))
	for _, sc := range scans {
		out = append(out, toScanJSON(sc))
	}
	writeJSON(w, http.StatusOK, listOf(out))
}

// recentScans lists the organization's latest scans, all targets, for
// the scans screen's history.
func (s *Server) recentScans(w http.ResponseWriter, r *http.Request, req orgRequest) {
	limit, ok := intParam(w, r, "limit", 20, 1, 100)
	if !ok {
		return
	}
	scans, err := req.org.RecentScans(r.Context(), limit)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	out := make([]scanJSON, 0, len(scans))
	for _, sc := range scans {
		out = append(out, toScanJSON(sc))
	}
	writeJSON(w, http.StatusOK, listOf(out))
}

type moduleJSON struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Kind   string `json:"kind"`   // passive or active (active: verified targets only)
	Checks int    `json:"checks"` // checks in its catalog
}

// listModules lists the modules a scan may request, so the dashboard
// offers only what the engine runs.
func (s *Server) listModules(w http.ResponseWriter, r *http.Request, req orgRequest) {
	out := make([]moduleJSON, 0, len(s.cfg.Modules))
	for _, id := range s.cfg.Modules {
		m := moduleJSON{ID: id}
		for _, info := range s.cfg.Catalog {
			if info.ID == id {
				m.Name, m.Kind, m.Checks = info.Name, string(info.Kind), len(info.Checks)
			}
		}
		out = append(out, m)
	}
	writeJSON(w, http.StatusOK, listOf(out))
}

func (s *Server) getScan(w http.ResponseWriter, r *http.Request, req orgRequest) {
	sc, err := req.org.GetScan(r.Context(), r.PathValue("scan"))
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, toScanJSON(sc))
}

// listFindings returns findings in the standard schema (package finding):
// the dashboard depends on that schema only. Optional filters: status and
// severity, each a single value.
func (s *Server) listFindings(w http.ResponseWriter, r *http.Request, req orgRequest, t store.Target) {
	q := r.URL.Query()
	status, severity := finding.Status(q.Get("status")), finding.Severity(q.Get("severity"))
	if status != "" && !status.Valid() {
		writeError(w, http.StatusBadRequest, "unknown status")
		return
	}
	if severity != "" && !severity.Valid() {
		writeError(w, http.StatusBadRequest, "unknown severity")
		return
	}
	findings, err := req.org.ListFindings(r.Context(), t.ID)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	findings = slices.DeleteFunc(findings, func(f finding.Finding) bool {
		return (status != "" && f.Status != status) || (severity != "" && f.Severity != severity)
	})
	writeJSON(w, http.StatusOK, listOf(findings))
}

// orgFinding is a finding with the ID of its target, needed to act on it
// (status, re-scan). The finding fields are inlined: same schema as
// listFindings.
type orgFinding struct {
	TargetID string `json:"target_id"`
	finding.Finding
	findingExtras
}

// orgFindings lists the findings of every target of the organization, the
// vulnerabilities screen. Optional filters: status and severity, each a
// single value. Targets are read one by one: an SME has tens of them.
func (s *Server) orgFindings(w http.ResponseWriter, r *http.Request, req orgRequest) {
	q := r.URL.Query()
	status, severity := finding.Status(q.Get("status")), finding.Severity(q.Get("severity"))
	if status != "" && !status.Valid() {
		writeError(w, http.StatusBadRequest, "unknown status")
		return
	}
	if severity != "" && !severity.Valid() {
		writeError(w, http.StatusBadRequest, "unknown severity")
		return
	}
	targets, err := req.org.ListTargets(r.Context())
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	threats, err := req.org.ListThreats(r.Context(), 500)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	out := []orgFinding{}
	for _, t := range targets {
		fs, err := req.org.ListFindings(r.Context(), t.ID)
		if err != nil {
			s.internalError(w, r, err)
			return
		}
		e, err := s.enricher(r.Context(), req.org, t.ID, fs, threats)
		if err != nil {
			s.internalError(w, r, err)
			return
		}
		for _, f := range fs {
			if (status == "" || f.Status == status) && (severity == "" || f.Severity == severity) {
				out = append(out, orgFinding{TargetID: t.ID, Finding: f, findingExtras: e.extras(f)})
			}
		}
	}
	writeJSON(w, http.StatusOK, listOf(out))
}

type findingEventJSON struct {
	At     time.Time `json:"at"`
	Kind   string    `json:"kind"`
	From   string    `json:"from,omitempty"`
	To     string    `json:"to"`
	Actor  string    `json:"actor"`
	ScanID string    `json:"scan_id,omitempty"`
}

func (s *Server) findingHistory(w http.ResponseWriter, r *http.Request, req orgRequest, t store.Target) {
	events, err := req.org.FindingHistory(r.Context(), t.ID, r.PathValue("finding"))
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if len(events) == 0 {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	out := make([]findingEventJSON, 0, len(events))
	for _, e := range events {
		out = append(out, findingEventJSON{At: e.At, Kind: e.Kind(), From: string(e.From), To: string(e.To), Actor: e.Actor, ScanID: e.ScanID})
	}
	writeJSON(w, http.StatusOK, listOf(out))
}

type postureJSON struct {
	ScanID  string    `json:"scan_id"`
	At      time.Time `json:"at"`
	Score   *int      `json:"score"`
	Details any       `json:"details"`
}

func (s *Server) posture(w http.ResponseWriter, r *http.Request, req orgRequest, t store.Target) {
	limit, ok := intParam(w, r, "limit", 30, 1, 1000)
	if !ok {
		return
	}
	snaps, err := req.org.PostureHistory(r.Context(), t.ID, limit)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	out := make([]postureJSON, 0, len(snaps))
	for _, p := range snaps {
		out = append(out, postureJSON{ScanID: p.ScanID, At: p.At, Score: p.Score, Details: p.Details})
	}
	writeJSON(w, http.StatusOK, listOf(out))
}

type checkJSON struct {
	TargetID    string    `json:"target_id,omitempty"`
	ID          string    `json:"id"`
	Title       string    `json:"title"` // from the module's catalog
	Module      string    `json:"module"`
	Category    string    `json:"category"`
	Severity    string    `json:"severity"`
	Status      string    `json:"status"`
	Findings    int       `json:"findings"`
	EvaluatedAt time.Time `json:"evaluated_at"`
}

func (s *Server) checks(w http.ResponseWriter, r *http.Request, req orgRequest, t store.Target) {
	states, err := req.org.CheckStatuses(r.Context(), t.ID)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	out := make([]checkJSON, 0, len(states))
	for _, c := range states {
		out = append(out, s.toCheckJSON(c, ""))
	}
	writeJSON(w, http.StatusOK, listOf(out))
}

// ---- Query parameters --------------------------------------------------------

func boolParam(w http.ResponseWriter, r *http.Request, name string) (bool, bool) {
	v := r.URL.Query().Get(name)
	if v == "" {
		return false, true
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		writeError(w, http.StatusBadRequest, name+" must be true or false")
		return false, false
	}
	return b, true
}

func intParam(w http.ResponseWriter, r *http.Request, name string, def, lo, hi int) (int, bool) {
	v := r.URL.Query().Get(name)
	if v == "" {
		return def, true
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < lo || n > hi {
		writeError(w, http.StatusBadRequest, name+" must be an integer between "+strconv.Itoa(lo)+" and "+strconv.Itoa(hi))
		return 0, false
	}
	return n, true
}

func (s *Server) toCheckJSON(c store.CheckState, targetID string) checkJSON {
	return checkJSON{TargetID: targetID, ID: c.CheckID, Title: s.checkTitle(c.ModuleID, c.CheckID), Module: c.ModuleID,
		Category: string(c.Category), Severity: string(c.Severity), Status: string(c.Status), Findings: c.Findings, EvaluatedAt: c.EvaluatedAt}
}

// checkTitle is the catalog title of a check ("DMARC record published"),
// or its ID when the module is not in the catalog.
func (s *Server) checkTitle(moduleID, checkID string) string {
	for _, info := range s.cfg.Catalog {
		if info.ID != moduleID {
			continue
		}
		for _, c := range info.Checks {
			if c.ID == checkID {
				return c.Title
			}
		}
	}
	return checkID
}

// orgChecks lists the latest status of every check of every target: the
// posture screen's categories and inventory.
func (s *Server) orgChecks(w http.ResponseWriter, r *http.Request, req orgRequest) {
	targets, err := req.org.ListTargets(r.Context())
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	out := []checkJSON{}
	for _, t := range targets {
		states, err := req.org.CheckStatuses(r.Context(), t.ID)
		if err != nil {
			s.internalError(w, r, err)
			return
		}
		for _, c := range states {
			out = append(out, s.toCheckJSON(c, t.ID))
		}
	}
	writeJSON(w, http.StatusOK, listOf(out))
}

type orgAssetJSON struct {
	TargetID string `json:"target_id"`
	Domain   string `json:"domain"`
	assetJSON
}

// orgAssets lists the current assets of every target: the attack surface
// screen's counts and the protections (CDN, WAF) of the prioritization.
func (s *Server) orgAssets(w http.ResponseWriter, r *http.Request, req orgRequest) {
	targets, err := req.org.ListTargets(r.Context())
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	out := []orgAssetJSON{}
	for _, t := range targets {
		assets, err := req.org.ListAssets(r.Context(), t.ID, false)
		if err != nil {
			s.internalError(w, r, err)
			return
		}
		for _, a := range assets {
			details := a.Details
			if details == nil {
				details = map[string]string{}
			}
			out = append(out, orgAssetJSON{TargetID: t.ID, Domain: t.Domain, assetJSON: assetJSON{ID: a.ID, Kind: string(a.Kind), Value: a.Value,
				Details: details, Sources: a.Sources, FirstSeen: a.FirstSeen, LastSeen: a.LastSeen, GoneAt: a.GoneAt}})
		}
	}
	writeJSON(w, http.StatusOK, listOf(out))
}

type monthJSON struct {
	Month  string `json:"month"` // YYYY-MM
	Opened int    `json:"opened"`
	Fixed  int    `json:"fixed"`
}

// trends answers GET /orgs/{org}/trends?months=N (1 to 24, default 6):
// findings opened and fixed per calendar month.
func (s *Server) trends(w http.ResponseWriter, r *http.Request, req orgRequest) {
	months, ok := intParam(w, r, "months", 6, 1, 24)
	if !ok {
		return
	}
	counts, err := req.org.Trends(r.Context(), months, s.cfg.Now())
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	out := make([]monthJSON, 0, len(counts))
	for _, c := range counts {
		out = append(out, monthJSON{Month: c.Month.Format("2006-01"), Opened: c.Opened, Fixed: c.Fixed})
	}
	writeJSON(w, http.StatusOK, listOf(out))
}
