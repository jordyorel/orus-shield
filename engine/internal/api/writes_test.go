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
	"github.com/jordyorel/orus-shield/engine/internal/module"
	"github.com/jordyorel/orus-shield/engine/internal/plan"
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
	// Nothing is scanned before verification, not even passively.
	var scans list[scanJSON]
	e.do("GET", "/api/v1/orgs/"+a.orgID+"/targets/"+tg.ID+"/scans", a.session, nil).json(t, &scans)
	if len(scans.Items) != 0 {
		t.Errorf("scans before verification = %+v", scans.Items)
	}
}

func TestFirstScanAtVerification(t *testing.T) {
	e := newEnv(t)
	// A catalog with every kind of module: passive, active, heavy, deep only.
	for _, m := range []module.Info{
		{ID: "ports", Kind: module.KindActive}, {ID: "vulns", Kind: module.KindActive},
		{ID: "zap", Kind: module.KindActive, DeepOnly: true},
	} {
		e.srv.cfg.Modules = append(e.srv.cfg.Modules, m.ID)
		e.srv.cfg.Catalog = append(e.srv.cfg.Catalog, m)
	}
	a := e.tenant("A", "example.com")
	base := "/api/v1/orgs/" + a.orgID
	queued := func(targetID string) []string {
		var l list[scanJSON]
		e.do("GET", base+"/targets/"+targetID+"/scans", a.session, nil).json(t, &l)
		var out []string
		for _, sc := range l.Items {
			if sc.Status == "queued" {
				out = append(out, strings.Join(sc.Modules, ","))
			}
		}
		return out
	}
	add := func(domain string) string {
		var tg targetJSON
		r := e.do("POST", base+"/targets", a.session, createTargetRequest{Domain: domain})
		if r.status != http.StatusCreated {
			t.Fatalf("create %s = %d %s", domain, r.status, r.body)
		}
		r.json(t, &tg)
		return tg.ID
	}
	verify := func(targetID string) { e.verifyTarget(a.session, a.orgID, targetID) }

	// Pro: added, nothing; verified, the light modules with ports (not
	// vulns, not zap); verified again, nothing more.
	end := e.now.AddDate(0, 1, 0)
	e.setPlan(a.orgID, plan.Subscription{Plan: plan.Pro, Status: plan.Active, PeriodEnd: &end})
	id := add("shop.example.com")
	if q := queued(id); len(q) != 0 {
		t.Fatalf("queued before verification: %v", q)
	}
	verify(id)
	if q := queued(id); len(q) != 1 || q[0] != "email,ports,tls" {
		t.Errorf("first scan on Pro = %v, want email,ports,tls", q)
	}
	verify(id)
	if q := queued(id); len(q) != 1 {
		t.Errorf("second verification queued more: %v", q)
	}

	// Gratuit: the passive ones only.
	e.setPlan(a.orgID, plan.Subscription{Plan: plan.Discovery, Status: plan.Active})
	verify(a.target.ID)
	if q := queued(a.target.ID); len(q) != 1 || q[0] != "email,tls" {
		t.Errorf("first scan on Gratuit = %v, want email,tls", q)
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

// verifyTarget proves ownership of a target through the API, with the fake
// DNS serving its record.
func (e *env) verifyTarget(session, orgID, targetID string) {
	e.t.Helper()
	base := "/api/v1/orgs/" + orgID + "/targets/" + targetID
	var in instructionsJSON
	e.do("POST", base+"/verification", session, nil).json(e.t, &in)
	e.dns.set(in.RecordName, in.RecordValue)
	if r := e.do("POST", base+"/verify", session, nil); r.status != http.StatusOK {
		e.t.Fatalf("verify = %d %s", r.status, r.body)
	}
}

func TestStartScan(t *testing.T) {
	e := newEnv(t)
	a := e.tenant("A", "example.com")
	path := "/api/v1/orgs/" + a.orgID + "/targets/" + a.target.ID + "/scans"

	// Unverified: refused, not even a passive scan.
	if r := e.do("POST", path, a.session, nil); r.status != http.StatusConflict {
		t.Fatalf("scan of an unverified domain = %d %s, want 409", r.status, r.body)
	}
	e.verifyTarget(a.session, a.orgID, a.target.ID) // queues the light first scan

	r := e.do("POST", path, a.session, nil) // no body: every module
	if r.status != http.StatusAccepted {
		t.Fatalf("scan = %d %s", r.status, r.body)
	}
	var sc scanJSON
	r.json(t, &sc)
	if sc.Status != "queued" || strings.Join(sc.Modules, ",") != "email,tls" || sc.RequestedBy != "user:admin@example.com" {
		t.Errorf("scan = %+v", sc)
	}
	// Covered by the scan still waiting: that scan answers.
	first := sc.ID
	r = e.do("POST", path, a.session, startScanRequest{Modules: []string{"tls", "tls"}})
	r.json(t, &sc)
	if r.status != http.StatusAccepted || sc.ID != first {
		t.Errorf("scan with modules = %d %+v, want the waiting scan", r.status, sc)
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
