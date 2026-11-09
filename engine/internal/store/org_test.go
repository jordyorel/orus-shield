package store

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/jordyorel/orus-shield/engine/internal/finding"
)

func newOrg(t *testing.T, s *Store, name string) *Org {
	t.Helper()
	org, err := s.CreateOrganization(context.Background(), name, "cli:jordy")
	if err != nil {
		t.Fatalf("CreateOrganization(%s): %v", name, err)
	}
	h, err := s.Org(org.ID)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func TestOrganizations(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	acme, err := s.CreateOrganization(ctx, "Acme", "cli:jordy")
	if err != nil {
		t.Fatalf("CreateOrganization: %v", err)
	}
	orgs, err := s.ListOrganizations(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(orgs) != 2 || orgs[0].Name != "Default" || orgs[1].ID != acme.ID {
		t.Errorf("ListOrganizations = %+v, want Default then Acme", orgs)
	}

	for _, ref := range []string{"Acme", acme.ID, strings.ToUpper(acme.ID)} {
		got, err := s.FindOrganization(ctx, ref)
		if err != nil || got.ID != acme.ID {
			t.Errorf("FindOrganization(%q) = %+v, %v", ref, got, err)
		}
	}
	if _, err := s.FindOrganization(ctx, "Nobody"); !errors.Is(err, ErrNotFound) {
		t.Errorf("FindOrganization(unknown) = %v, want ErrNotFound", err)
	}
	if _, err := s.CreateOrganization(ctx, "Acme", "cli:jordy"); err != nil {
		t.Fatalf("a second Acme must be allowed: %v", err)
	}
	if _, err := s.FindOrganization(ctx, "Acme"); !errors.Is(err, ErrAmbiguous) {
		t.Errorf("FindOrganization(shared name) = %v, want ErrAmbiguous", err)
	}

	for _, name := range []string{"", "   ", strings.Repeat("a", maxOrgNameChars+1)} {
		if _, err := s.CreateOrganization(ctx, name, "cli:jordy"); err == nil {
			t.Errorf("CreateOrganization(%q) = nil, want error", name)
		}
	}
	for _, id := range []string{"", "not-a-uuid", "0190a000-0000-7000-8000-00000000000"} {
		if _, err := s.Org(id); !errors.Is(err, ErrNotFound) {
			t.Errorf("Org(%q) = %v, want ErrNotFound", id, err)
		}
	}

	h, err := s.Org(acme.ID)
	if err != nil {
		t.Fatal(err)
	}
	entries, err := h.AuditLog(ctx, "")
	if err != nil || len(entries) != 1 || entries[0].Action != ActionOrgCreated {
		t.Errorf("audit of the new organization = %+v, %v", entries, err)
	}
}

func TestDomainIsUniquePerOrganization(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	a, b := newOrg(t, s, "A"), newOrg(t, s, "B")

	ta, err := a.CreateTarget(ctx, NewTarget{Domain: "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	tb, err := b.CreateTarget(ctx, NewTarget{Domain: "example.com"})
	if err != nil {
		t.Fatalf("the same domain in another organization must be allowed: %v", err)
	}
	if ta.ID == tb.ID || ta.OrgID != a.ID() || tb.OrgID != b.ID() {
		t.Errorf("targets %+v and %+v must be distinct, one per organization", ta, tb)
	}
	if _, err := a.CreateTarget(ctx, NewTarget{Domain: "EXAMPLE.com"}); err == nil {
		t.Error("duplicate domain in the same organization = nil, want error")
	}
}

// crossTenant sets up two organizations with the same domain, each with a
// scan, a finding and audit entries.
type crossTenant struct {
	s        *Store
	a, b     *Org
	ta, tb   Target
	scanB    Scan
	findingB finding.Finding
	tokenOfB string
}

func newCrossTenant(t *testing.T) *crossTenant {
	t.Helper()
	ctx := context.Background()
	s := newTestStore(t)
	c := &crossTenant{s: s, a: newOrg(t, s, "A"), b: newOrg(t, s, "B")}
	var err error
	if c.ta, err = c.a.CreateTarget(ctx, NewTarget{Domain: "example.com"}); err != nil {
		t.Fatal(err)
	}
	if c.tb, err = c.b.CreateTarget(ctx, NewTarget{Domain: "example.com"}); err != nil {
		t.Fatal(err)
	}
	// B gets a finished scan with one finding.
	if _, err := c.b.EnqueueScan(ctx, c.tb.ID, []string{"email"}, "user:b"); err != nil {
		t.Fatal(err)
	}
	claimed, ok, err := s.ClaimScan(ctx, "worker:test", time.Minute, 3)
	if err != nil || !ok {
		t.Fatalf("claim: %v, %v", ok, err)
	}
	if claimed.OrgID != c.b.ID() {
		t.Errorf("claimed scan org = %s, want B", claimed.OrgID)
	}
	c.findingB = makeFinding("email", "spf-missing", "example.com")
	if err := s.FinishScan(ctx, ScanResult{
		ScanID: claimed.ID, Attempt: claimed.Attempt, WorkerID: "worker:test", At: t1,
		Succeeded: []string{"email"}, Findings: []finding.Finding{c.findingB},
	}); err != nil {
		t.Fatal(err)
	}
	c.scanB = claimed
	c.tokenOfB = token
	if err := c.b.IssueVerificationToken(ctx, c.tb.ID, token, time.Now().Add(time.Hour), "user:b"); err != nil {
		t.Fatal(err)
	}
	return c
}

// Layer 1: an Org handle never reads or changes another organization's
// rows, even with their exact IDs.
func TestOrgHandleIsolation(t *testing.T) {
	c := newCrossTenant(t)
	ctx := context.Background()
	a := c.a

	if _, err := a.GetTarget(ctx, c.tb.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("GetTarget(B's target) = %v, want ErrNotFound", err)
	}
	if got, err := a.TargetByDomain(ctx, "example.com"); err != nil || got.ID != c.ta.ID {
		t.Errorf("TargetByDomain = %+v, %v; want A's own target", got, err)
	}
	if _, err := a.EnqueueScan(ctx, c.tb.ID, []string{"email"}, "user:a"); !errors.Is(err, ErrNotFound) {
		t.Errorf("EnqueueScan(B's target) = %v, want ErrNotFound", err)
	}
	if _, err := a.GetScan(ctx, c.scanB.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("GetScan(B's scan) = %v, want ErrNotFound", err)
	}
	if got, err := a.FindingHistory(ctx, c.tb.ID, c.findingB.ID); err != nil || len(got) != 0 {
		t.Errorf("FindingHistory(B's finding) = %v, %v; want none", got, err)
	}
	if got, err := a.ListFindings(ctx, c.tb.ID); err != nil || len(got) != 0 {
		t.Errorf("ListFindings(B's target) = %v, %v; want none", got, err)
	}
	err := a.SetFindingStatus(ctx, c.tb.ID, c.findingB.ID, finding.StatusAcceptedRisk, "user:a")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("SetFindingStatus(B's finding) = %v, want ErrNotFound", err)
	}
	if err := a.IssueVerificationToken(ctx, c.tb.ID, "a-token", time.Now().Add(time.Hour), "user:a"); !errors.Is(err, ErrNotFound) {
		t.Errorf("IssueVerificationToken(B's target) = %v, want ErrNotFound", err)
	}
	if err := a.MarkVerified(ctx, c.tb.ID, c.tokenOfB, "user:a"); !errors.Is(err, ErrTokenMismatch) {
		t.Errorf("MarkVerified(B's target, B's token) = %v, want ErrTokenMismatch", err)
	}
	if err := a.AppendAudit(ctx, AuditEntry{OrgID: c.b.ID(), Actor: "user:a", Action: "x", Target: "example.com"}); err == nil {
		t.Error("AppendAudit for another organization = nil, want error")
	}
	entries, err := a.AuditLog(ctx, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.OrgID != a.ID() {
			t.Errorf("A's audit log contains %+v from another organization", e)
		}
	}

	// Nothing of B changed.
	tb, err := c.b.GetTarget(ctx, c.tb.ID)
	if err != nil || tb.Verified() || tb.VerifyToken != c.tokenOfB {
		t.Errorf("B's target after A's attempts = %+v, %v", tb, err)
	}
	fb, err := c.b.ListFindings(ctx, c.tb.ID)
	if err != nil || len(fb) != 1 || fb[0].Status != finding.StatusOpen {
		t.Errorf("B's findings after A's attempts = %+v, %v", fb, err)
	}

	// Verification state of B, through B's own handle, after it verifies.
	if err := c.b.MarkVerified(ctx, c.tb.ID, c.tokenOfB, "user:b"); err != nil {
		t.Fatal(err)
	}
	if err := a.TouchVerification(ctx, c.tb.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("TouchVerification(B's target) = %v, want ErrNotFound", err)
	}
	if err := a.RevokeVerification(ctx, c.tb.ID, "user:a", "x", time.Hour); !errors.Is(err, ErrNotFound) {
		t.Errorf("RevokeVerification(B's target) = %v, want ErrNotFound", err)
	}
	if tb, _ := c.b.GetTarget(ctx, c.tb.ID); !tb.Verified() {
		t.Error("A revoked B's verification")
	}
}

// Layer 2: inside an Org transaction, PostgreSQL itself hides the other
// organizations, even from queries with no org_id filter at all. These are
// the queries a future bug could write.
func TestRowLevelSecurity(t *testing.T) {
	c := newCrossTenant(t)
	ctx := context.Background()

	tx, err := c.a.begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)

	for _, table := range []string{"organizations", "targets", "scans", "findings", "finding_events", "audit_log"} {
		var foreign int
		err := tx.QueryRow(ctx, "SELECT count(*) FROM "+table+" WHERE "+orgColumn(table)+" <> $1", c.a.ID()).Scan(&foreign)
		if err != nil {
			t.Fatalf("%s: %v", table, err)
		}
		if foreign != 0 {
			t.Errorf("%s: %d rows of other organizations visible", table, foreign)
		}
	}
	var own int
	if err := tx.QueryRow(ctx, "SELECT count(*) FROM targets").Scan(&own); err != nil || own != 1 {
		t.Errorf("unfiltered SELECT on targets = %d, %v; want A's single target", own, err)
	}

	// Writes to B's rows touch nothing.
	tag, err := tx.Exec(ctx, "UPDATE findings SET status = 'accepted_risk'")
	if err != nil || tag.RowsAffected() != 0 {
		t.Errorf("unfiltered UPDATE findings = %v rows, %v; want 0", tag.RowsAffected(), err)
	}
	// Creating a row for B is refused (WITH CHECK).
	if _, err := tx.Exec(ctx, "SAVEPOINT s1"); err != nil {
		t.Fatal(err)
	}
	_, err = tx.Exec(ctx, "INSERT INTO targets (org_id, domain) VALUES ($1, 'b-only.example')", c.b.ID())
	if err == nil || !strings.Contains(err.Error(), "row-level security") {
		t.Errorf("INSERT for B = %v, want a row-level security violation", err)
	}
	if _, err := tx.Exec(ctx, "ROLLBACK TO SAVEPOINT s1"); err != nil {
		t.Fatal(err)
	}
	// The API role cannot record findings or delete anything (least
	// privilege): only the worker does.
	for _, stmt := range []string{
		"DELETE FROM targets",
		"INSERT INTO findings (org_id, target_id, id, module_id, check_id, severity, status, first_seen, last_seen, data) " +
			"VALUES ('" + c.a.ID() + "', '" + c.ta.ID + "', 'x', 'm', 'c', 'low', 'open', now(), now(), '{}')",
	} {
		if _, err := tx.Exec(ctx, "SAVEPOINT s2"); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, stmt); err == nil || !strings.Contains(err.Error(), "permission denied") {
			t.Errorf("%s = %v, want permission denied", stmt, err)
		}
		if _, err := tx.Exec(ctx, "ROLLBACK TO SAVEPOINT s2"); err != nil {
			t.Fatal(err)
		}
	}
}

func orgColumn(table string) string {
	if table == "organizations" {
		return "id"
	}
	return "org_id"
}

// Without app.org_id, the API role sees nothing at all: forgetting to set
// the organization fails closed.
func TestRowLevelSecurityWithoutOrganization(t *testing.T) {
	c := newCrossTenant(t)
	ctx := context.Background()
	tx, err := c.s.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, "SET LOCAL ROLE "+appRole); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := tx.QueryRow(ctx, "SELECT (SELECT count(*) FROM targets) + (SELECT count(*) FROM findings) + (SELECT count(*) FROM audit_log)").Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("API role without organization sees %d rows, want 0", n)
	}
}

// SET LOCAL and set_config(..., true) end with the transaction: a pooled
// connection must not keep the role or organization of the previous caller.
func TestOrgSettingsDoNotLeakAcrossTransactions(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	cfg := s.pool.Config()
	cfg.MaxConns = 1 // force every transaction onto the same connection
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()

	org := defaultOrg(t, s)
	scoped := scope{pool: pool, orgID: org.ID()}
	tx, err := scoped.begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var role, setting string
	if err := tx.QueryRow(ctx, "SELECT current_user, current_setting('app.org_id')").Scan(&role, &setting); err != nil {
		t.Fatal(err)
	}
	if role != appRole || setting != org.ID() {
		t.Errorf("inside the transaction: %s, %s; want %s, %s", role, setting, appRole, org.ID())
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}

	err = pool.QueryRow(ctx, "SELECT current_user, coalesce(current_setting('app.org_id', true), '')").Scan(&role, &setting)
	if err != nil {
		t.Fatal(err)
	}
	if role == appRole || setting != "" {
		t.Errorf("after the transaction: role %s, app.org_id %q; want both reset", role, setting)
	}
}

// Migration 0003 attaches everything that existed before organizations to
// the Default organization.
func TestOrganizationsMigrationBackfill(t *testing.T) {
	s := newEmptyTestStore(t)
	ctx := context.Background()
	if err := s.migrate(ctx, "0002_ownership"); err != nil {
		t.Fatal(err)
	}
	var targetID string
	err := s.pool.QueryRow(ctx, "INSERT INTO targets (domain) VALUES ('orushield.xyz') RETURNING id::text").Scan(&targetID)
	if err != nil {
		t.Fatal(err)
	}
	for _, stmt := range []string{
		"INSERT INTO scans (target_id, modules, requested_by) VALUES ($1, '{email}', 'cli:jordy')",
		"INSERT INTO findings (target_id, id, module_id, check_id, severity, status, first_seen, last_seen, data) " +
			"VALUES ($1, 'f1', 'email', 'spf-missing', 'high', 'open', now(), now(), '{}')",
		"INSERT INTO audit_log (actor, action, target, details) VALUES ('cli:jordy', 'scan.requested', 'orushield.xyz', jsonb_build_object('target_id', $1::text))",
	} {
		if _, err := s.pool.Exec(ctx, stmt, targetID); err != nil {
			t.Fatalf("%s: %v", stmt, err)
		}
	}

	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	org := defaultOrg(t, s)
	for _, table := range []string{"targets", "scans", "findings", "audit_log"} {
		var total, inDefault int
		err := s.pool.QueryRow(ctx, "SELECT count(*), count(*) FILTER (WHERE org_id = $1) FROM "+table, org.ID()).
			Scan(&total, &inDefault)
		if err != nil {
			t.Fatal(err)
		}
		if total != 1 || inDefault != 1 {
			t.Errorf("%s: %d rows, %d in Default; want 1, 1", table, total, inDefault)
		}
	}
	// The backfill reopened audit_log only for itself.
	if _, err := s.pool.Exec(ctx, "UPDATE audit_log SET actor = 'x'"); err == nil || !strings.Contains(err.Error(), "append-only") {
		t.Errorf("UPDATE audit_log after migration = %v, want append-only refusal", err)
	}
	if got, err := org.TargetByDomain(ctx, "orushield.xyz"); err != nil || got.ID != targetID {
		t.Errorf("Default's target = %+v, %v", got, err)
	}
}
