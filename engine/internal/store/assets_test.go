package store

import (
	"context"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jordyorel/orus-shield/engine/internal/asset"
)

var (
	ipA = netip.MustParseAddr("192.0.2.10")
	ipB = netip.MustParseAddr("192.0.2.20")
)

// scanAssets runs one scan where the given modules succeeded and reported
// these assets; failed modules report nothing.
func (l *lifecycle) scanAssets(at time.Time, failed []string, assets map[string][]asset.Asset) error {
	l.t.Helper()
	ctx := context.Background()
	if _, err := l.org.EnqueueScan(ctx, l.target.ID, []string{"tls", "ports"}, "jordy"); err != nil {
		l.t.Fatal(err)
	}
	sc, ok, err := l.s.ClaimScan(ctx, "worker:test", time.Minute, 3)
	if err != nil || !ok {
		l.t.Fatalf("claim: %v, %v", ok, err)
	}
	var succeeded []string
	failures := map[string]string{}
	for _, m := range []string{"tls", "ports"} {
		if slices.Contains(failed, m) {
			failures[m] = "timeout"
		} else {
			succeeded = append(succeeded, m)
		}
	}
	return l.s.FinishScan(ctx, ScanResult{
		ScanID: sc.ID, Attempt: sc.Attempt, WorkerID: "worker:test", At: at,
		Succeeded: succeeded, Failed: failures, Assets: assets,
	})
}

func (l *lifecycle) mustScanAssets(at time.Time, failed []string, assets map[string][]asset.Asset) {
	l.t.Helper()
	if err := l.scanAssets(at, failed, assets); err != nil {
		l.t.Fatalf("FinishScan: %v", err)
	}
}

// inventory describes the assets as "key [sources] gone?".
func (l *lifecycle) inventory(includeGone bool) map[string]Asset {
	l.t.Helper()
	assets, err := l.org.ListAssets(context.Background(), l.target.ID, includeGone)
	if err != nil {
		l.t.Fatalf("ListAssets: %v", err)
	}
	out := make(map[string]Asset)
	for _, a := range assets {
		out[string(a.Kind)+" "+a.Value] = a
	}
	return out
}

func TestAssetInventoryLifecycle(t *testing.T) {
	l := newLifecycle(t)
	host := asset.Hostname("example.com")
	ip := asset.IP(ipA)
	https := asset.Service(ipA, 443, map[string]string{"expected": "https"})
	ssh := asset.Service(ipA, 22, map[string]string{"expected": "SSH"})

	// Scan 1: tls and ports both see the host and the IP.
	l.mustScanAssets(t1, nil, map[string][]asset.Asset{
		"tls":   {host, ip, https},
		"ports": {host, ip, ssh},
	})
	inv := l.inventory(false)
	if len(inv) != 4 {
		t.Fatalf("inventory = %v, want 4 assets", inv)
	}
	if got := inv[ip.Key()].Sources; !slices.Equal(got, []string{"tls", "ports"}) {
		t.Errorf("IP sources = %v, want both modules", got)
	}

	// Scan 2: SSH was closed; ports still sees the IP. tls fails: it says
	// nothing, so its assets stay as they were.
	l.mustScanAssets(t2, []string{"tls"}, map[string][]asset.Asset{"ports": {host, ip}})
	inv = l.inventory(false)
	if _, ok := inv[ssh.Key()]; ok {
		t.Error("closed SSH port still listed as current")
	}
	if a := inv[https.Key()]; a.GoneAt != nil || !a.LastSeen.Equal(t1) {
		t.Errorf("https after a failed tls run = %+v, want unchanged", a)
	}
	if a := inv[ip.Key()]; !a.LastSeen.Equal(t2) || !a.FirstSeen.Equal(t1) {
		t.Errorf("IP first/last seen = %v/%v, want %v/%v", a.FirstSeen, a.LastSeen, t1, t2)
	}
	all := l.inventory(true)
	if a := all[ssh.Key()]; a.GoneAt == nil || !a.GoneAt.Equal(t2) || len(a.Sources) != 0 {
		t.Errorf("SSH = %+v, want gone at %v", a, t2)
	}

	// Scan 3: ports no longer sees the IP, tls still does: still current,
	// with tls as its only source.
	l.mustScanAssets(t3, nil, map[string][]asset.Asset{"tls": {host, ip, https}})
	if got := l.inventory(false)[ip.Key()].Sources; !slices.Equal(got, []string{"tls"}) {
		t.Errorf("IP sources = %v, want [tls]", got)
	}

	// Scan 4: SSH is open again: back, gone_at cleared, first_seen kept.
	l.mustScanAssets(t4, nil, map[string][]asset.Asset{"tls": {host, ip, https}, "ports": {ssh}})
	if a := l.inventory(false)[ssh.Key()]; a.GoneAt != nil || !a.FirstSeen.Equal(t1) {
		t.Errorf("SSH back = %+v, want current, first seen %v", a, t1)
	}

	// The audit entry of the last scan counts the asset changes.
	var back int
	err := l.s.pool.QueryRow(context.Background(), `SELECT (details->>'assets_back')::int FROM audit_log
		WHERE action = $1 ORDER BY id DESC LIMIT 1`, ActionScanFinished).Scan(&back)
	if err != nil || back != 1 {
		t.Errorf("assets_back in audit = %d, %v; want 1", back, err)
	}
}

func TestAssetDetailsAreMerged(t *testing.T) {
	l := newLifecycle(t)
	l.mustScanAssets(t1, nil, map[string][]asset.Asset{
		"tls":   {asset.Service(ipA, 443, map[string]string{"expected": "https", "tls_version": "TLS 1.2"})},
		"ports": {asset.Service(ipA, 443, map[string]string{"banner": "x"})},
	})
	l.mustScanAssets(t2, nil, map[string][]asset.Asset{
		"tls":   {asset.Service(ipA, 443, map[string]string{"tls_version": "TLS 1.3"})},
		"ports": {asset.Service(ipA, 443, nil)},
	})
	d := l.inventory(false)["service 192.0.2.10:443/tcp"].Details
	if d["expected"] != "https" || d["tls_version"] != "TLS 1.3" || d["banner"] != "x" {
		t.Errorf("details = %v, want merged with the latest values", d)
	}
}

func TestFinishScanRejectsBadAssets(t *testing.T) {
	tests := []struct {
		name   string
		failed []string
		assets map[string][]asset.Asset
		want   string
	}{
		{"another domain", nil, map[string][]asset.Asset{"tls": {asset.Hostname("mx.provider.net")}}, "not example.com"},
		{"not canonical", nil, map[string][]asset.Asset{"tls": {{Kind: asset.KindIP, Value: "2001:DB8::1"}}}, "canonical"},
		{"from a failed module", []string{"ports"}, map[string][]asset.Asset{"ports": {asset.IP(ipB)}}, "did not succeed"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := newLifecycle(t)
			err := l.scanAssets(t1, tt.failed, tt.assets)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("FinishScan = %v, want error mentioning %q", err, tt.want)
			}
			if inv := l.inventory(true); len(inv) != 0 {
				t.Errorf("inventory after a rejected scan = %v, want empty (all or nothing)", inv)
			}
		})
	}
}

func TestSameAssetInTwoTargets(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	org := defaultOrg(t, s)
	for _, domain := range []string{"example.com", "example.org"} {
		target, err := org.CreateTarget(ctx, NewTarget{Domain: domain})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := org.EnqueueScan(ctx, target.ID, []string{"tls"}, "jordy"); err != nil {
			t.Fatal(err)
		}
		sc, _, err := s.ClaimScan(ctx, "worker:test", time.Minute, 3)
		if err != nil {
			t.Fatal(err)
		}
		// Shared hosting: both domains point to the same IP.
		if err := s.FinishScan(ctx, ScanResult{ScanID: sc.ID, Attempt: sc.Attempt, WorkerID: "worker:test", At: t1,
			Succeeded: []string{"tls"}, Assets: map[string][]asset.Asset{"tls": {asset.IP(ipA)}}}); err != nil {
			t.Fatal(err)
		}
		assets, err := org.ListAssets(ctx, target.ID, false)
		if err != nil || len(assets) != 1 {
			t.Errorf("%s inventory = %v, %v; want its own copy of the IP", domain, assets, err)
		}
	}
}
