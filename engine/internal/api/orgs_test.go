package api

import (
	"context"
	"net/http"
	"net/netip"
	"testing"
	"time"

	"github.com/jordyorel/orus-shield/engine/internal/asset"
	"github.com/jordyorel/orus-shield/engine/internal/finding"
	"github.com/jordyorel/orus-shield/engine/internal/module"
	"github.com/jordyorel/orus-shield/engine/internal/store"
)

// tenant is one organization with a scanned target: a finished scan with a
// finding, an asset and a posture snapshot.
type tenant struct {
	orgID   string
	target  store.Target
	scanID  string
	finding finding.Finding
	session string // an admin's session, opened with MFA
	viewer  string // a viewer's session
}

func (e *env) tenant(name, domain string) tenant {
	e.t.Helper()
	ctx := context.Background()
	tn := tenant{orgID: e.org(name)}
	org, err := e.st.Org(tn.orgID)
	if err != nil {
		e.t.Fatal(err)
	}
	if tn.target, err = org.CreateTarget(ctx, store.NewTarget{Domain: domain}); err != nil {
		e.t.Fatal(err)
	}
	if _, err := org.EnqueueScan(ctx, tn.target.ID, []string{"email"}, "test"); err != nil {
		e.t.Fatal(err)
	}
	sc, ok, err := e.st.ClaimScan(ctx, "worker:test", time.Minute, 3)
	if err != nil || !ok {
		e.t.Fatalf("claim: %v %v", ok, err)
	}
	tn.scanID = sc.ID
	tn.finding = finding.Finding{
		SchemaVersion: finding.SchemaVersion, ModuleID: "email", CheckID: "dmarc-missing",
		ID: finding.NewID("email", "dmarc-missing", domain, "_dmarc."+domain), Target: domain,
		Asset: "_dmarc." + domain, Severity: finding.SeverityHigh, Title: "No DMARC", Description: "No DMARC record.",
	}
	if err := e.st.FinishScan(ctx, store.ScanResult{
		ScanID: sc.ID, Attempt: sc.Attempt, WorkerID: "worker:test", At: time.Now(),
		Succeeded: []string{"email"}, Findings: []finding.Finding{tn.finding},
		Assets: map[string][]asset.Asset{"email": {asset.Hostname(domain), asset.IP(netip.MustParseAddr("192.0.2.10"))}},
		Checks: map[string][]module.CheckOutcome{"email": {
			{Check: module.Check{ID: "dmarc-missing", Category: module.CategoryEmail, Severity: finding.SeverityHigh, Title: "x"}, Status: module.CheckFailed, Findings: 1},
			{Check: module.Check{ID: "spf-missing", Category: module.CategoryEmail, Severity: finding.SeverityHigh, Title: "x"}, Status: module.CheckPassed},
		}},
	}); err != nil {
		e.t.Fatal(err)
	}
	e.user("admin@"+domain, tn.orgID, store.RoleAdmin)
	e.user("viewer@"+domain, tn.orgID, store.RoleViewer)
	tn.session = e.adminSession("admin@" + domain)
	tn.viewer = e.login("viewer@" + domain)
	return tn
}

// readPaths are every read route of tn, with its own IDs.
func readPaths(tn tenant) []string {
	base := "/api/v1/orgs/" + tn.orgID
	t := base + "/targets/" + tn.target.ID
	return []string{
		base + "/overview",
		base + "/findings",
		base + "/assets",
		base + "/checks",
		base + "/trends",
		base + "/targets",
		t,
		t + "/assets?include_gone=true",
		t + "/scans",
		base + "/scans/" + tn.scanID,
		t + "/findings",
		t + "/findings/" + tn.finding.ID + "/history",
		t + "/posture",
		t + "/checks",
	}
}

func TestReadRoutes(t *testing.T) {
	e := newEnv(t)
	a := e.tenant("A", "example.com")
	for _, p := range readPaths(a) {
		r := e.do("GET", p, a.viewer, nil)
		if r.status != http.StatusOK {
			t.Errorf("viewer GET %s = %d %s", p, r.status, r.body)
		}
	}

	var findings list[finding.Finding]
	e.do("GET", readPaths(a)[10], a.viewer, nil).json(t, &findings)
	if len(findings.Items) != 1 || findings.Items[0].ID != a.finding.ID || findings.Items[0].Status != finding.StatusOpen {
		t.Errorf("findings = %+v", findings.Items)
	}
	e.do("GET", readPaths(a)[10]+"?severity=low", a.viewer, nil).json(t, &findings)
	if len(findings.Items) != 0 {
		t.Errorf("severity filter: %+v", findings.Items)
	}
	if r := e.do("GET", readPaths(a)[10]+"?status=maybe", a.viewer, nil); r.status != http.StatusBadRequest {
		t.Errorf("unknown status filter = %d, want 400", r.status)
	}

	var all list[orgFinding]
	e.do("GET", readPaths(a)[1]+"?status=open", a.viewer, nil).json(t, &all)
	if len(all.Items) != 1 || all.Items[0].TargetID != a.target.ID || all.Items[0].ID != a.finding.ID || all.Items[0].Title != "No DMARC" {
		t.Errorf("organization findings = %+v", all.Items)
	}
	if r := e.do("GET", readPaths(a)[1]+"?severity=bad", a.viewer, nil); r.status != http.StatusBadRequest {
		t.Errorf("unknown severity filter = %d, want 400", r.status)
	}

	var ov overviewJSON
	e.do("GET", readPaths(a)[0], a.viewer, nil).json(t, &ov)
	if ov.Targets != 1 || ov.VerifiedTargets != 0 || ov.OpenFindings["high"] != 1 || ov.Assets != 2 ||
		len(ov.PerTarget) != 1 || ov.PerTarget[0].Stale || ov.PerTarget[0].PostureScore == nil || *ov.PerTarget[0].PostureScore != 50 {
		t.Errorf("overview = %+v", ov)
	}

	var posture list[postureJSON]
	e.do("GET", readPaths(a)[12], a.viewer, nil).json(t, &posture)
	if len(posture.Items) != 1 || posture.Items[0].Score == nil || *posture.Items[0].Score != 50 {
		t.Errorf("posture = %+v", posture.Items)
	}
	var target targetJSON
	e.do("GET", readPaths(a)[6], a.viewer, nil).json(t, &target)
	if target.Domain != "example.com" || target.Verified {
		t.Errorf("target = %+v", target)
	}

	if r := e.do("GET", readPaths(a)[7][:len(readPaths(a)[7])-4]+"maybe", a.viewer, nil); r.status != http.StatusBadRequest {
		t.Errorf("include_gone=maybe = %d, want 400", r.status)
	}
	if r := e.do("GET", readPaths(a)[8]+"?limit=1000", a.viewer, nil); r.status != http.StatusBadRequest {
		t.Errorf("limit out of range = %d, want 400", r.status)
	}
}

// A member of A reaches nothing of B, even with B's exact IDs: every route
// answers 404, as if B's organization, targets and scans did not exist.
func TestCrossTenantReadsAreNotFound(t *testing.T) {
	e := newEnv(t)
	a := e.tenant("A", "example.com")
	b := e.tenant("B", "example.org")

	for _, p := range readPaths(b) {
		r := e.do("GET", p, a.session, nil)
		if r.status != http.StatusNotFound {
			t.Errorf("A's admin GET %s = %d %s, want 404", p, r.status, r.body)
		}
	}
	// B's resources under A's organization: still not found.
	base := "/api/v1/orgs/" + a.orgID
	for _, p := range []string{
		base + "/targets/" + b.target.ID,
		base + "/targets/" + b.target.ID + "/findings",
		base + "/targets/" + b.target.ID + "/assets",
		base + "/targets/" + b.target.ID + "/posture",
		base + "/targets/" + b.target.ID + "/checks",
		base + "/targets/" + b.target.ID + "/scans",
		base + "/scans/" + b.scanID,
		base + "/targets/" + a.target.ID + "/findings/" + b.finding.ID + "/history",
	} {
		if r := e.do("GET", p, a.session, nil); r.status != http.StatusNotFound {
			t.Errorf("GET %s = %d %s, want 404", p, r.status, r.body)
		}
	}
	// Garbage IDs too.
	for _, p := range []string{"/api/v1/orgs/not-a-uuid/targets", base + "/targets/not-a-uuid", base + "/scans/x"} {
		if r := e.do("GET", p, a.session, nil); r.status != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404", p, r.status)
		}
	}
}

func TestOrgRoutesNeedASession(t *testing.T) {
	e := newEnv(t)
	a := e.tenant("A", "example.com")
	for _, p := range readPaths(a) {
		if r := e.do("GET", p, "", nil); r.status != http.StatusUnauthorized {
			t.Errorf("GET %s without session = %d, want 401", p, r.status)
		}
	}
}
