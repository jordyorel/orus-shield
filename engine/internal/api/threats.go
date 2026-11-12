package api

import (
	"net/http"
	"time"
)

// maxThreatsListed bounds GET /orgs/{org}/threats.
const maxThreatsListed = 200

// threatJSON is one emerging threat that may concern a domain, and the
// rescan it triggered. It is not a finding: the rescan decides.
type threatJSON struct {
	TemplateID string    `json:"template_id"`
	CVE        string    `json:"cve"`
	Name       string    `json:"name"`
	Severity   string    `json:"severity"`
	KEV        bool      `json:"kev"`  // exploited in the wild (CISA KEV)
	EPSS       float64   `json:"epss"` // probability of exploitation within 30 days
	TargetID   string    `json:"target_id"`
	Domain     string    `json:"domain"`
	Products   []string  `json:"products"` // the detected technologies it concerns
	ScanID     string    `json:"scan_id,omitempty"`
	ScanStatus string    `json:"scan_status,omitempty"`
	At         time.Time `json:"at"`
}

// threats lists the organization's emerging threats, most recent first.
func (s *Server) threats(w http.ResponseWriter, r *http.Request, req orgRequest) {
	list, err := req.org.ListThreats(r.Context(), maxThreatsListed)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	out := make([]threatJSON, 0, len(list))
	for _, t := range list {
		products := t.Products
		if products == nil {
			products = []string{}
		}
		out = append(out, threatJSON{TemplateID: t.TemplateID, CVE: t.CVE, Name: t.Name, Severity: t.Severity, KEV: t.KEV,
			EPSS: t.EPSS, TargetID: t.TargetID, Domain: t.Domain, Products: products, ScanID: t.ScanID,
			ScanStatus: t.ScanStatus, At: t.At})
	}
	writeJSON(w, http.StatusOK, listOf(out))
}
