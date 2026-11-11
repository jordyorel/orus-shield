package store

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/jordyorel/orus-shield/engine/internal/asset"
	"github.com/jordyorel/orus-shield/engine/internal/finding"
)

// portFinding is a ports-module finding on ipA:port.
func portFinding(checkID string, port uint16) finding.Finding {
	f := makeFinding("ports", checkID, "example.com")
	f.Asset = netip.AddrPortFrom(ipA, port).String()
	f.ID = finding.NewID("ports", checkID, "example.com", f.Asset)
	return f
}

// finishPorts runs one scan where the ports module succeeded with these
// results, and unobserved says what was out of reach.
func (l *lifecycle) finishPorts(at time.Time, unobserved func(asset.Kind, string) bool, findings []finding.Finding, assets []asset.Asset) {
	l.t.Helper()
	ctx := context.Background()
	if _, err := l.org.EnqueueScan(ctx, l.target.ID, []string{"ports"}, "jordy"); err != nil {
		l.t.Fatal(err)
	}
	sc, ok, err := l.s.ClaimScan(ctx, "worker:test", time.Minute, 3)
	if err != nil || !ok {
		l.t.Fatalf("claim: %v, %v", ok, err)
	}
	err = l.s.FinishScan(ctx, ScanResult{
		ScanID: sc.ID, Attempt: sc.Attempt, WorkerID: "worker:test", At: at,
		Succeeded: []string{"ports"}, Failed: map[string]string{},
		Findings: findings, Assets: map[string][]asset.Asset{"ports": assets},
		Unobserved: unobserved,
	})
	if err != nil {
		l.t.Fatalf("FinishScan: %v", err)
	}
}

// A port the customer excluded after it was found is not "fixed": the scan
// did not look at it. Its finding stays open and its asset stays current,
// both with the last real observation as last_seen. A port that was
// scanned and is now closed is fixed as before.
func TestExcludedDestinationsAreNotMarkedFixedOrGone(t *testing.T) {
	l := newLifecycle(t)
	admin := portFinding("port-admin-web-exposed", 8080)
	ssh := portFinding("port-ssh-exposed", 22)
	adminSvc := asset.Service(ipA, 8080, nil)
	sshSvc := asset.Service(ipA, 22, nil)
	ip := asset.IP(ipA)

	// Scan 1: both ports open.
	l.finishPorts(t1, nil, []finding.Finding{admin, ssh}, []asset.Asset{ip, adminSvc, sshSvc})

	// Scan 2: port 8080 is excluded (not probed) and SSH was closed.
	excluded8080 := func(kind asset.Kind, value string) bool {
		return value == admin.Asset || value == adminSvc.Value
	}
	l.finishPorts(t2, excluded8080, nil, []asset.Asset{ip})

	l.expect("port-admin-web-exposed", finding.StatusOpen, t1, t1)
	l.expect("port-ssh-exposed", finding.StatusFixed, t1, t1)

	all := l.inventory(true)
	if a := all[adminSvc.Key()]; a.GoneAt != nil || !a.LastSeen.Equal(t1) {
		t.Errorf("excluded service = gone %v, last seen %v; want current, last seen %v", a.GoneAt, a.LastSeen, t1)
	}
	if a := all[sshSvc.Key()]; a.GoneAt == nil {
		t.Error("closed SSH service is still current")
	}

	var unobserved, assetsUnobserved, fixed int
	err := l.s.pool.QueryRow(context.Background(), `
		SELECT (details->>'unobserved')::int, (details->>'assets_unobserved')::int, (details->>'fixed')::int
		FROM audit_log WHERE action = $1 ORDER BY id DESC LIMIT 1`, ActionScanFinished).
		Scan(&unobserved, &assetsUnobserved, &fixed)
	if err != nil || unobserved != 1 || assetsUnobserved != 1 || fixed != 1 {
		t.Errorf("audit unobserved/assets_unobserved/fixed = %d/%d/%d, %v; want 1/1/1", unobserved, assetsUnobserved, fixed, err)
	}

	// Scan 3: the exclusion is removed and the port is really closed now:
	// the finding is fixed and the asset gone, as usual.
	l.finishPorts(t3, nil, nil, []asset.Asset{ip})
	l.expect("port-admin-web-exposed", finding.StatusFixed, t1, t1)
	if a := l.inventory(true)[adminSvc.Key()]; a.GoneAt == nil || !a.GoneAt.Equal(t3) {
		t.Errorf("service after the exclusion was lifted = gone %v, want %v", a.GoneAt, t3)
	}
}
