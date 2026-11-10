package store

import (
	"context"
	"testing"
	"time"

	"github.com/jordyorel/orus-shield/engine/internal/asset"
	"github.com/jordyorel/orus-shield/engine/internal/finding"
	"github.com/jordyorel/orus-shield/engine/internal/module"
)

func TestRemediation(t *testing.T) {
	l := newLifecycle(t)
	ctx := context.Background()
	spf := makeFinding("email", "spf-missing", "example.com")
	email := []string{"email"}

	l.mustScan(t1, email, nil, spf)              // opened
	l.mustScan(t2, email, nil)                   // fixed after 1 day
	l.mustScan(t3, email, nil, spf)              // reopened
	l.mustScan(t4.Add(24*time.Hour), email, nil) // fixed after 2 days

	end := t4.Add(72 * time.Hour)
	for _, tc := range []struct {
		since, until time.Time
		fixed        int
		mean         time.Duration
	}{
		{t1, end, 2, 36 * time.Hour}, // (1 day + 2 days) / 2
		{t3, end, 1, 48 * time.Hour}, // only the second fix, measured from the reopening
		{t1, t3, 1, 24 * time.Hour},  // until is exclusive of later fixes
		{t1, t2, 0, 0},               // and of a fix exactly at until
		{t4.Add(48 * time.Hour), end, 0, 0},
	} {
		r, err := l.org.Remediation(ctx, tc.since, tc.until)
		if err != nil {
			t.Fatal(err)
		}
		if r.Fixed != tc.fixed || r.Mean != tc.mean {
			t.Errorf("Remediation(since %s) = %+v, want %d fixes, mean %s", tc.since.Format("01-02"), r, tc.fixed, tc.mean)
		}
	}

	// Another organization sees none of it.
	other, err := l.s.CreateOrganization(ctx, "Other", "test")
	if err != nil {
		t.Fatal(err)
	}
	oh, err := l.s.Org(other.ID)
	if err != nil {
		t.Fatal(err)
	}
	if r, err := oh.Remediation(ctx, t1, end); err != nil || r.Fixed != 0 {
		t.Errorf("other organization's remediation = %+v, %v", r, err)
	}
}

func TestPosturePoints(t *testing.T) {
	l := newLifecycle(t)
	ctx := context.Background()
	passed := outcome("dmarc-policy", finding.SeverityHigh, module.CheckPassed, 0)
	failed := outcome("spf-missing", finding.SeverityMedium, module.CheckFailed, 1)
	spf := makeFinding("email", "spf-missing", "example.com")
	spf.Severity = finding.SeverityMedium

	for _, at := range []time.Time{t1, t2, t3} {
		if err := l.scanChecks(at, []module.CheckOutcome{passed, failed}, nil, spf); err != nil {
			t.Fatal(err)
		}
	}

	points, err := l.org.PosturePoints(ctx, t2)
	if err != nil {
		t.Fatal(err)
	}
	// t1 is before the period: kept as the starting value. Then t2, t3.
	if len(points) != 3 || !points[0].At.Equal(t1) || !points[1].At.Equal(t2) || !points[2].At.Equal(t3) {
		t.Fatalf("points = %+v, want t1 (start), t2, t3", points)
	}
	for _, p := range points {
		if p.TargetID != l.target.ID || p.Total.PassedWeight != 6 || p.Total.EvaluatedWeight != 9 {
			t.Errorf("point = %+v, want passed weight 6 of 9", p)
		}
	}

	// After the last snapshot: only the starting value remains.
	points, err = l.org.PosturePoints(ctx, t4)
	if err != nil {
		t.Fatal(err)
	}
	if len(points) != 1 || !points[0].At.Equal(t3) {
		t.Errorf("points after the last snapshot = %+v, want only t3", points)
	}
}

func TestNewAssets(t *testing.T) {
	l := newLifecycle(t)
	ctx := context.Background()
	host := asset.Hostname("example.com")
	ip := asset.IP(ipA)
	ssh := asset.Service(ipA, 22, map[string]string{"expected": "SSH"})
	https := asset.Service(ipA, 443, map[string]string{"expected": "https"})

	l.mustScanAssets(t1, nil, map[string][]asset.Asset{"tls": {host, ip}, "ports": {host, ip, ssh}})
	// Day 3: HTTPS appears, SSH is closed (gone: no longer counted).
	l.mustScanAssets(t3, nil, map[string][]asset.Asset{"tls": {host, ip, https}, "ports": {host, ip}})

	for since, want := range map[time.Time]int{t1: 3, t2: 1, t4: 0} {
		n, err := l.org.NewAssets(ctx, since)
		if err != nil {
			t.Fatal(err)
		}
		if n != want {
			t.Errorf("NewAssets(since %s) = %d, want %d", since.Format("01-02"), n, want)
		}
	}
}
