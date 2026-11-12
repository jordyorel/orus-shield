package api

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/jordyorel/orus-shield/engine/internal/finding"
	"github.com/jordyorel/orus-shield/engine/internal/resolver"
)

// fakeDNS answers TXT lookups from a map (rule 6: no real DNS in tests).
type fakeDNS struct {
	mu  sync.Mutex
	txt map[string][]string
}

func (f *fakeDNS) set(name string, records ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.txt[name] = records
}

func (f *fakeDNS) LookupTXT(_ context.Context, name string) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r, ok := f.txt[name]; ok {
		return r, nil
	}
	return nil, fmt.Errorf("lookup %s: %w", name, resolver.ErrNotFound)
}

func (f *fakeDNS) LookupMX(context.Context, string) ([]*net.MX, error) {
	return nil, resolver.ErrNotFound
}
func (f *fakeDNS) LookupIP(context.Context, string) ([]netip.Addr, error) {
	return nil, resolver.ErrNotFound
}
func (f *fakeDNS) LookupAddr(context.Context, netip.Addr) ([]string, error) {
	return nil, resolver.ErrNotFound
}

func TestCreateTarget(t *testing.T) {
	e := newEnv(t)
	a := e.tenant("A", "example.com")
	path := "/api/v1/orgs/" + a.orgID + "/targets"

	r := e.do("POST", path, a.session, createTargetRequest{Domain: "Shop.Example.com", RatePerSec: 2})
	if r.status != http.StatusCreated {
		t.Fatalf("create = %d %s", r.status, r.body)
	}
	var tg targetJSON
	r.json(t, &tg)
	if tg.Domain != "shop.example.com" || tg.RatePerSec != 2 || tg.Verified {
		t.Errorf("target = %+v", tg)
	}
	tests := []struct {
		name string
		body createTargetRequest
		want int
	}{
		{"duplicate", createTargetRequest{Domain: "shop.example.com"}, http.StatusConflict},
		{"invalid domain", createTargetRequest{Domain: "not a domain"}, http.StatusBadRequest},
		{"bad exclusions", createTargetRequest{Domain: "x.example.com", Exclusions: []byte(`{"ips": ["nope"]}`)}, http.StatusBadRequest},
		{"rate too high", createTargetRequest{Domain: "y.example.com", RatePerSec: 500}, http.StatusBadRequest},
	}
	for _, tt := range tests {
		if r := e.do("POST", path, a.session, tt.body); r.status != tt.want {
			t.Errorf("%s = %d %s, want %d", tt.name, r.status, r.body, tt.want)
		}
	}
	var audit list[auditEntryJSON]
	e.do("GET", "/api/v1/orgs/"+a.orgID+"/audit?target=shop.example.com", a.session, nil).json(t, &audit)
	if len(audit.Items) != 1 || audit.Items[0].Action != actionTargetCreated || audit.Items[0].Actor != "user:admin@example.com" {
		t.Errorf("audit = %+v", audit.Items)
	}
}

func TestVerificationFlow(t *testing.T) {
	e := newEnv(t)
	a := e.tenant("A", "example.com")
	tpath := "/api/v1/orgs/" + a.orgID + "/targets/" + a.target.ID

	if r := e.do("POST", tpath+"/verify", a.session, nil); r.status != http.StatusConflict {
		t.Errorf("verify before requesting a record = %d, want 409", r.status)
	}
	r := e.do("POST", tpath+"/verification", a.session, nil)
	if r.status != http.StatusOK {
		t.Fatalf("instructions = %d %s", r.status, r.body)
	}
	var in instructionsJSON
	r.json(t, &in)
	if in.RecordName != "_orus-verify.example.com" || in.RecordType != "TXT" || !strings.HasPrefix(in.RecordValue, "orus-verify=") {
		t.Fatalf("instructions = %+v", in)
	}
	if r := e.do("POST", tpath+"/verify", a.session, nil); r.status != http.StatusUnprocessableEntity {
		t.Errorf("verify without the record = %d, want 422", r.status)
	}
	e.dns.set(in.RecordName, in.RecordValue)
	r = e.do("POST", tpath+"/verify", a.session, nil)
	var tg targetJSON
	r.json(t, &tg)
	if r.status != http.StatusOK || !tg.Verified {
		t.Errorf("verify with the record = %d %+v", r.status, tg)
	}
}

func TestStartScan(t *testing.T) {
	e := newEnv(t)
	a := e.tenant("A", "example.com")
	path := "/api/v1/orgs/" + a.orgID + "/targets/" + a.target.ID + "/scans"

	r := e.do("POST", path, a.session, nil) // no body: every module
	if r.status != http.StatusAccepted {
		t.Fatalf("scan = %d %s", r.status, r.body)
	}
	var sc scanJSON
	r.json(t, &sc)
	if sc.Status != "queued" || strings.Join(sc.Modules, ",") != "email,tls" || sc.RequestedBy != "user:admin@example.com" {
		t.Errorf("scan = %+v", sc)
	}
	r = e.do("POST", path, a.session, startScanRequest{Modules: []string{"tls", "tls"}})
	r.json(t, &sc)
	if r.status != http.StatusAccepted || strings.Join(sc.Modules, ",") != "tls" {
		t.Errorf("scan with modules = %d %+v", r.status, sc)
	}
	if r := e.do("POST", path, a.session, startScanRequest{Modules: []string{"nmap"}}); r.status != http.StatusBadRequest {
		t.Errorf("unknown module = %d, want 400", r.status)
	}
}

func TestSetFindingStatus(t *testing.T) {
	e := newEnv(t)
	a := e.tenant("A", "example.com")
	path := "/api/v1/orgs/" + a.orgID + "/targets/" + a.target.ID + "/findings/" + a.finding.ID + "/status"

	if r := e.do("PUT", path, a.session, findingStatusRequest{Status: finding.StatusAcceptedRisk}); r.status != http.StatusNoContent {
		t.Fatalf("accept = %d %s", r.status, r.body)
	}
	var findings list[finding.Finding]
	e.do("GET", "/api/v1/orgs/"+a.orgID+"/targets/"+a.target.ID+"/findings", a.session, nil).json(t, &findings)
	if findings.Items[0].Status != finding.StatusAcceptedRisk {
		t.Errorf("status = %s", findings.Items[0].Status)
	}
	// Marked fixed by the customer: recorded, and a verification scan of
	// the finding's module is queued.
	if r := e.do("PUT", path, a.session, findingStatusRequest{Status: finding.StatusFixed}); r.status != http.StatusNoContent {
		t.Fatalf("manual fixed = %d %s", r.status, r.body)
	}
	e.do("GET", "/api/v1/orgs/"+a.orgID+"/targets/"+a.target.ID+"/findings", a.session, nil).json(t, &findings)
	if findings.Items[0].Status != finding.StatusFixed || findings.Items[0].FixedAt == nil {
		t.Errorf("after manual fix: %+v", findings.Items[0])
	}
	var scans list[scanJSON]
	e.do("GET", "/api/v1/orgs/"+a.orgID+"/targets/"+a.target.ID+"/scans", a.session, nil).json(t, &scans)
	if len(scans.Items) == 0 || scans.Items[0].Status != "queued" || !slices.Equal(scans.Items[0].Modules, []string{a.finding.ModuleID}) {
		t.Errorf("verification scan not queued: %+v", scans.Items)
	}
	if r := e.do("PUT", path, a.session, findingStatusRequest{Status: "done"}); r.status != http.StatusBadRequest {
		t.Errorf("unknown status = %d, want 400", r.status)
	}
	if r := e.do("PUT", path, a.viewer, findingStatusRequest{Status: finding.StatusFixed}); r.status != http.StatusForbidden {
		t.Errorf("viewer marks fixed = %d, want 403", r.status)
	}
	unknown := strings.Replace(path, a.finding.ID, "nope", 1)
	if r := e.do("PUT", unknown, a.session, findingStatusRequest{Status: finding.StatusOpen}); r.status != http.StatusNotFound {
		t.Errorf("unknown finding = %d, want 404", r.status)
	}
}

// writes are every write route of tn with a valid body.
func writes(tn tenant) []struct {
	method, path string
	body         any
} {
	base := "/api/v1/orgs/" + tn.orgID
	t := base + "/targets/" + tn.target.ID
	return []struct {
		method, path string
		body         any
	}{
		{"POST", base + "/targets", createTargetRequest{Domain: "new.example.net"}},
		{"POST", t + "/verification", nil},
		{"POST", t + "/verify", nil},
		{"POST", t + "/scans", nil},
		{"PUT", t + "/findings/" + tn.finding.ID + "/status", findingStatusRequest{Status: finding.StatusAcceptedRisk}},
		{"GET", base + "/audit", nil},
	}
}

func TestViewersCannotWrite(t *testing.T) {
	e := newEnv(t)
	a := e.tenant("A", "example.com")
	for _, w := range writes(a) {
		if r := e.do(w.method, w.path, a.viewer, w.body); r.status != http.StatusForbidden {
			t.Errorf("viewer %s %s = %d, want 403", w.method, w.path, r.status)
		}
	}
}

func TestCrossTenantWritesAreNotFound(t *testing.T) {
	e := newEnv(t)
	a := e.tenant("A", "example.com")
	b := e.tenant("B", "example.org")
	for _, w := range writes(b) {
		if r := e.do(w.method, w.path, a.session, w.body); r.status != http.StatusNotFound {
			t.Errorf("A's admin %s %s = %d %s, want 404", w.method, w.path, r.status, r.body)
		}
	}
	// B's target and finding under A's organization.
	base := "/api/v1/orgs/" + a.orgID + "/targets/" + b.target.ID
	for _, w := range []struct{ method, path string }{
		{"POST", base + "/verification"}, {"POST", base + "/verify"}, {"POST", base + "/scans"},
		{"PUT", base + "/findings/" + b.finding.ID + "/status"},
		{"PUT", "/api/v1/orgs/" + a.orgID + "/targets/" + a.target.ID + "/findings/" + b.finding.ID + "/status"},
	} {
		var body any
		if w.method == "PUT" {
			body = findingStatusRequest{Status: finding.StatusAcceptedRisk}
		}
		if r := e.do(w.method, w.path, a.session, body); r.status != http.StatusNotFound {
			t.Errorf("%s %s = %d %s, want 404", w.method, w.path, r.status, r.body)
		}
	}
	// Nothing of B changed.
	var findings list[finding.Finding]
	e.do("GET", "/api/v1/orgs/"+b.orgID+"/targets/"+b.target.ID+"/findings", b.session, nil).json(t, &findings)
	if findings.Items[0].Status != finding.StatusOpen {
		t.Errorf("B's finding status = %s, want open", findings.Items[0].Status)
	}
}
