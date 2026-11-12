package api

import (
	"bytes"
	"net/http"
	"strings"
	"testing"
)

func TestReport(t *testing.T) {
	e := newEnv(t)
	a := e.tenant("Acme", "example.com")
	b := e.tenant("Other", "example.org")
	base := "/api/v1/orgs/" + a.orgID + "/report"

	for _, q := range []string{"", "?kind=technical&lang=en", "?kind=executive&lang=fr"} {
		r := e.do("GET", base+q, a.viewer, nil)
		if r.status != http.StatusOK || !bytes.HasPrefix(r.body, []byte("%PDF-1.4")) {
			t.Fatalf("GET report%s = %d %.80q", q, r.status, r.body)
		}
		if ct := r.header.Get("Content-Type"); ct != "application/pdf" {
			t.Errorf("content type %q", ct)
		}
		if cd := r.header.Get("Content-Disposition"); !strings.HasPrefix(cd, `attachment; filename="orus-shield-`) {
			t.Errorf("disposition %q", cd)
		}
		if r.header.Get("Cache-Control") != "no-store" {
			t.Error("report may be cached")
		}
	}
	if r := e.do("GET", base+"?lang=de", a.viewer, nil); r.status != http.StatusBadRequest {
		t.Errorf("lang=de = %d, want 400", r.status)
	}
	if r := e.do("GET", "/api/v1/orgs/"+b.orgID+"/report", a.viewer, nil); r.status != http.StatusNotFound {
		t.Errorf("another organization's report = %d, want 404", r.status)
	}
}
