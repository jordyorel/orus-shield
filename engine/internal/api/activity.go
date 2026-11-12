package api

import (
	"net/http"
	"strconv"
	"time"

	"github.com/jordyorel/orus-shield/engine/internal/finding"
	"github.com/jordyorel/orus-shield/engine/internal/store"
)

type activityJSON struct {
	Kind     store.ActivityKind `json:"kind"` // finding, scan
	At       time.Time          `json:"at"`
	TargetID string             `json:"target_id"`
	Domain   string             `json:"domain"`
	// kind finding
	FindingID string           `json:"finding_id,omitempty"`
	Title     string           `json:"title,omitempty"`
	Asset     string           `json:"asset,omitempty"`
	Severity  finding.Severity `json:"severity,omitempty"`
	From      string           `json:"from,omitempty"` // absent: first seen
	To        string           `json:"to,omitempty"`
	// kind scan
	ScanID      string `json:"scan_id,omitempty"`
	RequestedBy string `json:"requested_by,omitempty"`
	Assets      int    `json:"assets,omitempty"`
}

// activity answers GET /orgs/{org}/activity?days=7&limit=10: finding
// changes and finished scans, newest first.
func (s *Server) activity(w http.ResponseWriter, r *http.Request, req orgRequest) {
	days, limit := 7, 10
	if v, err := strconv.Atoi(r.URL.Query().Get("days")); err == nil && v >= 1 && v <= 90 {
		days = v
	}
	if v, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && v >= 1 && v <= 50 {
		limit = v
	}
	since := s.cfg.Now().AddDate(0, 0, -days)
	as, err := req.org.Activity(r.Context(), since, limit)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	out := make([]activityJSON, 0, len(as))
	for _, a := range as {
		out = append(out, activityJSON{Kind: a.Kind, At: a.At, TargetID: a.TargetID, Domain: a.Domain,
			FindingID: a.FindingID, Title: a.Title, Asset: a.Asset, Severity: a.Severity, From: a.From, To: a.To,
			ScanID: a.ScanID, RequestedBy: a.RequestedBy, Assets: a.Assets})
	}
	writeJSON(w, http.StatusOK, listOf(out))
}
