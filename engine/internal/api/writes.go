package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"time"

	"github.com/jordyorel/orus-shield/engine/internal/finding"
	"github.com/jordyorel/orus-shield/engine/internal/gate"
	"github.com/jordyorel/orus-shield/engine/internal/module"
	"github.com/jordyorel/orus-shield/engine/internal/ownership"
	"github.com/jordyorel/orus-shield/engine/internal/store"
)

// Audit actions for targets changed through the API.
const (
	actionTargetCreated = "target.created"
	actionTargetUpdated = "target.updated"
)

// writeRoutes registers the routes that change state: admin only.
func (s *Server) writeRoutes(mux *http.ServeMux) {
	write := func(pattern string, h orgHandler) {
		mux.HandleFunc(pattern, s.withOrg(store.RoleAdmin, h))
	}
	base := "/api/v1/orgs/{org}"
	write("POST "+base+"/targets", s.createTarget)
	write("PATCH "+base+"/targets/{target}", s.targetOnly(s.updateTarget))
	write("POST "+base+"/targets/{target}/verification", s.targetOnly(s.verificationInstructions))
	write("POST "+base+"/targets/{target}/verify", s.targetOnly(s.verifyTarget))
	write("POST "+base+"/targets/{target}/scans", s.targetOnly(s.startScan))
	write("PUT "+base+"/targets/{target}/findings/{finding}/status", s.targetOnly(s.setFindingStatus))
	// The audit log names who did what: admins only, like writes.
	write("GET "+base+"/audit", s.auditLog)
}

// actor is how the caller appears in the audit log.
func actor(req orgRequest) string { return "user:" + req.sess.Email }

type createTargetRequest struct {
	Domain     string          `json:"domain"`
	Exclusions json.RawMessage `json:"exclusions,omitempty"`
	RatePerSec float64         `json:"rate_per_sec,omitempty"`
}

func (s *Server) createTarget(w http.ResponseWriter, r *http.Request, req orgRequest) {
	var body createTargetRequest
	if !decode(w, r, &body) {
		return
	}
	// Same parser as the worker: a target whose exclusions the worker
	// cannot read would never be scanned.
	if _, err := gate.ParseExclusions(body.Exclusions); err != nil {
		writeError(w, http.StatusBadRequest, "invalid exclusions: "+err.Error())
		return
	}
	if _, err := module.NormalizeDomain(body.Domain); err != nil {
		writeError(w, http.StatusBadRequest, "invalid domain")
		return
	}
	if body.RatePerSec < 0 || body.RatePerSec > 100 {
		writeError(w, http.StatusBadRequest, "rate_per_sec must be between 0 (default) and 100")
		return
	}
	t, err := req.org.CreateTarget(r.Context(), store.NewTarget{Domain: body.Domain, Exclusions: body.Exclusions, RatePerSec: body.RatePerSec})
	switch {
	case errors.Is(err, store.ErrExists):
		writeError(w, http.StatusConflict, "this domain is already a target of the organization")
		return
	case err != nil:
		s.internalError(w, r, err)
		return
	}
	if err := req.org.AppendAudit(r.Context(), store.AuditEntry{
		Actor: actor(req), Action: actionTargetCreated, Target: t.Domain,
		Details: map[string]any{"target_id": t.ID},
	}); err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, toTargetJSON(t))
}

type updateTargetRequest struct {
	Exclusions json.RawMessage `json:"exclusions,omitempty"`
	RatePerSec *float64        `json:"rate_per_sec,omitempty"`
}

// updateTarget changes a target's exclusions (rule 2) and rate (rule 3).
// Both are checked like at creation; the worker applies them from the next
// scan. The audit log keeps the old and new values.
func (s *Server) updateTarget(w http.ResponseWriter, r *http.Request, req orgRequest, t store.Target) {
	var body updateTargetRequest
	if !decode(w, r, &body) {
		return
	}
	if body.Exclusions == nil && body.RatePerSec == nil {
		writeError(w, http.StatusBadRequest, "nothing to update: send exclusions and/or rate_per_sec")
		return
	}
	if body.Exclusions != nil {
		// An object, never null: the stored value must stay readable as
		// the worker's exclusions.
		if !bytes.HasPrefix(bytes.TrimSpace(body.Exclusions), []byte("{")) {
			writeError(w, http.StatusBadRequest, "invalid exclusions: must be an object")
			return
		}
		if _, err := gate.ParseExclusions(body.Exclusions); err != nil {
			writeError(w, http.StatusBadRequest, "invalid exclusions: "+err.Error())
			return
		}
	}
	if body.RatePerSec != nil && (*body.RatePerSec <= 0 || *body.RatePerSec > 100) {
		writeError(w, http.StatusBadRequest, "rate_per_sec must be greater than 0 and at most 100")
		return
	}
	updated, err := req.org.UpdateTargetSettings(r.Context(), t.ID, store.TargetSettings{Exclusions: body.Exclusions, RatePerSec: body.RatePerSec})
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if err := req.org.AppendAudit(r.Context(), store.AuditEntry{
		Actor: actor(req), Action: actionTargetUpdated, Target: t.Domain,
		Details: map[string]any{
			"target_id": t.ID,
			"before":    map[string]any{"rate_per_sec": t.RatePerSec, "exclusions": t.Exclusions},
			"after":     map[string]any{"rate_per_sec": updated.RatePerSec, "exclusions": updated.Exclusions},
		},
	}); err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, toTargetJSON(updated))
}

type instructionsJSON struct {
	Domain      string     `json:"domain"`
	RecordName  string     `json:"record_name"`
	RecordType  string     `json:"record_type"`
	RecordValue string     `json:"record_value"`
	ExpiresAt   *time.Time `json:"expires_at"`
	Verified    bool       `json:"verified"`
}

// verificationInstructions returns the DNS record to publish, issuing a
// token if needed. It is a POST: it may create a token.
func (s *Server) verificationInstructions(w http.ResponseWriter, r *http.Request, req orgRequest, t store.Target) {
	in, err := ownership.New(req.org, s.cfg.DNS).Instructions(r.Context(), t.ID, actor(req))
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, instructionsJSON{
		Domain: in.Domain, RecordName: in.RecordName, RecordType: "TXT", RecordValue: in.RecordValue,
		ExpiresAt: in.ExpiresAt, Verified: in.Verified,
	})
}

// verifyTarget looks for the record. The verifier works through the
// organization's handle, so it cannot touch another organization's target.
func (s *Server) verifyTarget(w http.ResponseWriter, r *http.Request, req orgRequest, t store.Target) {
	err := ownership.New(req.org, s.cfg.DNS).Verify(r.Context(), t.ID, actor(req))
	switch {
	case errors.Is(err, ownership.ErrNoToken):
		writeError(w, http.StatusConflict, "request the verification record first")
		return
	case errors.Is(err, ownership.ErrRecordMissing):
		writeError(w, http.StatusUnprocessableEntity, "verification record not found yet: DNS changes can take a few minutes to appear")
		return
	case err != nil:
		s.internalError(w, r, err)
		return
	}
	t, err = req.org.GetTarget(r.Context(), t.ID)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, toTargetJSON(t))
}

type startScanRequest struct {
	Modules []string `json:"modules,omitempty"`
}

// startScan queues a scan. Active modules on an unverified target are
// accepted here and refused by the worker (rule 1 is enforced where the
// probes are sent, at scan time); the response says so.
func (s *Server) startScan(w http.ResponseWriter, r *http.Request, req orgRequest, t store.Target) {
	var body startScanRequest
	if r.ContentLength != 0 && !decode(w, r, &body) {
		return
	}
	modules := body.Modules
	if len(modules) == 0 {
		modules = s.cfg.Modules
	}
	for _, m := range modules {
		if !slices.Contains(s.cfg.Modules, m) {
			writeError(w, http.StatusBadRequest, "unknown module "+m)
			return
		}
	}
	sc, err := req.org.EnqueueScan(r.Context(), t.ID, slices.Compact(slices.Sorted(slices.Values(modules))), actor(req))
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusAccepted, toScanJSON(sc))
}

type findingStatusRequest struct {
	Status finding.Status `json:"status"`
}

// setFindingStatus records a customer decision: accepted_risk, or open to
// withdraw it. "fixed" is decided by scans only.
func (s *Server) setFindingStatus(w http.ResponseWriter, r *http.Request, req orgRequest, t store.Target) {
	var body findingStatusRequest
	if !decode(w, r, &body) {
		return
	}
	if body.Status != finding.StatusAcceptedRisk && body.Status != finding.StatusOpen {
		writeError(w, http.StatusBadRequest, "status must be accepted_risk or open")
		return
	}
	err := req.org.SetFindingStatus(r.Context(), t.ID, r.PathValue("finding"), body.Status, actor(req))
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type auditEntryJSON struct {
	At      time.Time       `json:"at"`
	Actor   string          `json:"actor"`
	Action  string          `json:"action"`
	Target  string          `json:"target"`
	Details json.RawMessage `json:"details"`
}

// auditLog returns the organization's audit entries for ?target=<domain>,
// or the organization-level entries (members, organization) without it.
func (s *Server) auditLog(w http.ResponseWriter, r *http.Request, req orgRequest) {
	entries, err := req.org.AuditLog(r.Context(), r.URL.Query().Get("target"))
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	out := make([]auditEntryJSON, 0, len(entries))
	for _, e := range entries {
		details, _ := e.Details.(json.RawMessage)
		out = append(out, auditEntryJSON{At: e.At, Actor: e.Actor, Action: e.Action, Target: e.Target, Details: details})
	}
	writeJSON(w, http.StatusOK, listOf(out))
}
