package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/jordyorel/orus-shield/engine/internal/store"
)

const (
	// agentLease is how long an agent's claim lasts between extensions.
	agentLease = 10 * time.Minute
	// agentMaxAttempts mirrors the worker's: a scan its agent keeps losing
	// is abandoned.
	agentMaxAttempts = 3
	maxRanges        = 32
)

// PrivateRange checks a range an agent may scan: a private network (RFC
// 1918, or IPv6 unique local), at most a /20 in IPv4 (4096 addresses) and
// a /112 in IPv6. An agent can never be pointed at the internet: public
// addresses need the ownership proof of a domain (rule 1).
func PrivateRange(s string) (netip.Prefix, bool) {
	p, err := netip.ParsePrefix(strings.TrimSpace(s))
	if err != nil {
		return netip.Prefix{}, false
	}
	p = p.Masked()
	a := p.Addr()
	if !a.IsPrivate() {
		return netip.Prefix{}, false
	}
	if a.Is4() && p.Bits() < 20 || a.Is6() && p.Bits() < 112 {
		return netip.Prefix{}, false
	}
	return p, true
}

type agentJSON struct {
	ID              string     `json:"id"`
	TargetID        string     `json:"target_id"` // its internal network
	Name            string     `json:"name"`
	Ranges          []string   `json:"ranges"`
	EnrollExpiresAt *time.Time `json:"enroll_expires_at"`
	EnrolledAt      *time.Time `json:"enrolled_at"`
	LastSeenAt      *time.Time `json:"last_seen_at"`
	Hostname        string     `json:"hostname,omitempty"`
	OS              string     `json:"os,omitempty"`
	Version         string     `json:"version,omitempty"`
	RevokedAt       *time.Time `json:"revoked_at"`
	CreatedAt       time.Time  `json:"created_at"`
	CreatedBy       string     `json:"created_by"`
}

func toAgentJSON(a store.Agent) agentJSON {
	return agentJSON{ID: a.ID, TargetID: a.TargetID, Name: a.Name, Ranges: a.Ranges, EnrollExpiresAt: a.EnrollExpiresAt,
		EnrolledAt: a.EnrolledAt, LastSeenAt: a.LastSeenAt, Hostname: a.Hostname, OS: a.OS, Version: a.Version,
		RevokedAt: a.RevokedAt, CreatedAt: a.CreatedAt, CreatedBy: a.CreatedBy}
}

// listAgents answers GET /orgs/{org}/agents.
func (s *Server) listAgents(w http.ResponseWriter, r *http.Request, req orgRequest) {
	as, err := req.org.ListAgents(r.Context())
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	out := make([]agentJSON, 0, len(as))
	for _, a := range as {
		out = append(out, toAgentJSON(a))
	}
	writeJSON(w, http.StatusOK, listOf(out))
}

type createAgentRequest struct {
	Name   string   `json:"name"`
	Ranges []string `json:"ranges"`
}

type enrolmentJSON struct {
	Agent agentJSON `json:"agent"`
	// Code is shown once: the agent exchanges it for its token.
	Code string `json:"enrolment_code"`
}

// createAgent answers POST /orgs/{org}/agents.
func (s *Server) createAgent(w http.ResponseWriter, r *http.Request, req orgRequest) {
	var body createAgentRequest
	if !decode(w, r, &body) {
		return
	}
	name := strings.TrimSpace(body.Name)
	if name == "" || len([]rune(name)) > 100 {
		writeError(w, http.StatusBadRequest, "name must be 1 to 100 characters")
		return
	}
	if len(body.Ranges) == 0 || len(body.Ranges) > maxRanges {
		writeError(w, http.StatusBadRequest, "ranges: 1 to 32 private networks")
		return
	}
	var ranges []string
	for _, raw := range body.Ranges {
		p, ok := PrivateRange(raw)
		if !ok {
			writeError(w, http.StatusBadRequest, "range "+raw+": want a private network (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, fc00::/7), at most a /20 (IPv6: /112)")
			return
		}
		ranges = append(ranges, p.String())
	}
	p, ok := s.planOf(w, r, req)
	if !ok {
		return
	}
	if !p.Agents {
		planLimit(w, "the "+p.Name+" offer does not include internal agents")
		return
	}
	a, code, err := req.org.CreateAgent(r.Context(), name, ranges, actor(req))
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, enrolmentJSON{Agent: toAgentJSON(a), Code: code})
}

// newAgentCode answers POST /orgs/{org}/agents/{agent}/code: a new one-time
// enrolment code (install the agent again).
func (s *Server) newAgentCode(w http.ResponseWriter, r *http.Request, req orgRequest) {
	code, err := req.org.NewEnrolmentCode(r.Context(), r.PathValue("agent"), actor(req))
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"enrolment_code": code})
}

// revokeAgent answers DELETE /orgs/{org}/agents/{agent}.
func (s *Server) revokeAgent(w http.ResponseWriter, r *http.Request, req orgRequest) {
	err := req.org.RevokeAgent(r.Context(), r.PathValue("agent"), actor(req))
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

// ---- The agents' endpoints (no session: the agent's own token) -------------

func (s *Server) agentRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v1/agent/enroll", s.agentEnrol)
	mux.HandleFunc("POST /api/v1/agent/claim", s.withAgent(s.agentClaim))
	mux.HandleFunc("POST /api/v1/agent/scans/{scan}/lease", s.withAgent(s.agentLease))
	mux.HandleFunc("POST /api/v1/agent/scans/{scan}/result", s.withAgent(s.agentResult))
}

type agentHandler func(w http.ResponseWriter, r *http.Request, a store.AgentInfo)

// withAgent authenticates the agent's bearer token.
func (s *Server) withAgent(h agentHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok || token == "" {
			writeError(w, http.StatusUnauthorized, "agent token required")
			return
		}
		a, err := s.agents.Authenticate(r.Context(), token, r.Header.Get("X-Orus-Agent-Version"))
		if errors.Is(err, store.ErrRevoked) {
			writeError(w, http.StatusUnauthorized, "unknown or revoked agent")
			return
		}
		if err != nil {
			s.internalError(w, r, err)
			return
		}
		h(w, r, a)
	}
}

type agentEnrolRequest struct {
	Code     string `json:"code"`
	Hostname string `json:"hostname"`
	OS       string `json:"os"`
	Version  string `json:"version"`
}

// agentEnrol exchanges a one-time code for the agent's token.
func (s *Server) agentEnrol(w http.ResponseWriter, r *http.Request) {
	var body agentEnrolRequest
	if !decode(w, r, &body) {
		return
	}
	a, token, err := s.agents.Enrol(r.Context(), body.Code, body.Hostname, body.OS, body.Version)
	if errors.Is(err, store.ErrInvalidToken) {
		writeError(w, http.StatusUnauthorized, "invalid, expired or used enrolment code")
		return
	}
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"agent_id": a.ID, "token": token, "ranges": a.Ranges})
}

type agentJobJSON struct {
	ScanID     string          `json:"scan_id"`
	Attempt    int             `json:"attempt"`
	Modules    []string        `json:"modules"`
	Domain     string          `json:"domain"` // the internal network's target name
	Ranges     []string        `json:"ranges"`
	Exclusions json.RawMessage `json:"exclusions"`
	RatePerSec float64         `json:"rate_per_sec"`
	LeaseSecs  int             `json:"lease_seconds"`
}

// agentClaim gives the agent its next scan (204 when there is none).
func (s *Server) agentClaim(w http.ResponseWriter, r *http.Request, a store.AgentInfo) {
	job, ok, err := s.agents.ClaimScan(r.Context(), a, agentLease, agentMaxAttempts)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if !ok {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	writeJSON(w, http.StatusOK, agentJobJSON{ScanID: job.Scan.ID, Attempt: job.Scan.Attempt, Modules: job.Scan.Modules,
		Domain: job.Scan.Domain, Ranges: a.Ranges, Exclusions: job.Exclusions, RatePerSec: job.RatePerSec,
		LeaseSecs: int(agentLease.Seconds())})
}

type agentAttempt struct {
	Attempt int `json:"attempt"`
}

// agentLease keeps the agent's scan claimed (409 when it lost it).
func (s *Server) agentLease(w http.ResponseWriter, r *http.Request, a store.AgentInfo) {
	var body agentAttempt
	if !decode(w, r, &body) {
		return
	}
	err := s.agents.ExtendLease(r.Context(), a, r.PathValue("scan"), body.Attempt, agentLease)
	if errors.Is(err, store.ErrLeaseLost) {
		writeError(w, http.StatusConflict, "lease lost")
		return
	}
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type agentResultRequest struct {
	Attempt int `json:"attempt"`
	// Results and Failed, by module ID: what the worker validates and
	// records (see worker.ingestAgentResult). Stored as sent.
	Results map[string]json.RawMessage `json:"results"`
	Failed  map[string]string          `json:"failed"`
}

// agentResult receives the results of the agent's scan. The API only stores
// them: the worker validates them and records them, like its own scans.
func (s *Server) agentResult(w http.ResponseWriter, r *http.Request, a store.AgentInfo) {
	var body agentResultRequest
	if !decode(w, r, &body) {
		return
	}
	payload, err := json.Marshal(body)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid results")
		return
	}
	err = s.agents.SubmitResult(r.Context(), a, r.PathValue("scan"), body.Attempt, payload)
	if errors.Is(err, store.ErrLeaseLost) {
		writeError(w, http.StatusConflict, "lease lost")
		return
	}
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusAccepted)
}
