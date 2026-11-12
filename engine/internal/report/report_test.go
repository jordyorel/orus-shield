package report

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jordyorel/orus-shield/engine/internal/asset"
	"github.com/jordyorel/orus-shield/engine/internal/finding"
)

func ptr[T any](v T) *T { return &v }

func sample() Data {
	at := time.Date(2026, 11, 12, 9, 0, 0, 0, time.UTC)
	f := func(sev finding.Severity, title, assetValue string, status finding.Status, days int) finding.Finding {
		return finding.Finding{
			ID: title, Severity: sev, Title: title, Asset: assetValue, Status: status,
			Description: "What the problem is, in a few sentences, so that someone in charge understands why it matters to the business.",
			Evidence:    "template: git-config\nmatched at: https://example.com/.git/config",
			Remediation: []string{"Remove the file from the web server, or deny access to it.", "Change any password it contains."},
			References:  []string{"CVE-2021-41773", "https://nvd.nist.gov/vuln/detail/CVE-2021-41773"},
			FirstSeen:   at.AddDate(0, 0, -days),
		}
	}
	return Data{
		OrgName: "Microfinance du Congo (« MFC »)", GeneratedAt: at, Score: ptr(72), ScoreChange: ptr(6), PeriodDays: 30,
		Fixed: 4, MeanFixHours: ptr(53.0),
		Targets: []Target{
			{Domain: "example.com", Verified: true, LastScanAt: &at, Score: ptr(68), Findings: []finding.Finding{
				f(finding.SeverityCritical, "Remote Desktop (RDP) reachable from the internet (port 3389)", "203.0.113.5:3389", finding.StatusOpen, 3),
				f(finding.SeverityHigh, "Git Configuration - Detect", "https://example.com/.git/config#git-config", finding.StatusOpen, 10),
				f(finding.SeverityMedium, "No DMARC policy enforcement", "_dmarc.example.com", finding.StatusOpen, 40),
				f(finding.SeverityLow, "Server software version revealed", "www.example.com", finding.StatusAcceptedRisk, 50),
			}, Assets: []asset.Asset{
				{Kind: asset.KindHostname, Value: "www.example.com", Details: map[string]string{"technologies": "nginx 1.18.0, WordPress 6.1"}},
				{Kind: asset.KindIP, Value: "203.0.113.5"},
				{Kind: asset.KindService, Value: "203.0.113.5:3389/tcp", Details: map[string]string{"expected": "Remote Desktop (RDP)"}},
			}},
			{Domain: "unverified.example", Findings: nil},
		},
	}
}

func TestWrite(t *testing.T) {
	for _, o := range []Options{{Executive, French}, {Technical, French}, {Executive, English}, {Technical, English}} {
		var buf bytes.Buffer
		if err := Write(&buf, sample(), o); err != nil {
			t.Fatalf("%v: %v", o, err)
		}
		out := buf.Bytes()
		if !bytes.HasPrefix(out, []byte("%PDF-1.4")) || !bytes.Contains(out, []byte("/Lang ("+string(o.Lang)+")")) {
			t.Errorf("%v: not a PDF in the right language", o)
		}
		// The technical version is longer: details and inventory.
		if dir := os.Getenv("ORUS_REPORT_OUT"); dir != "" {
			_ = os.WriteFile(filepath.Join(dir, string(o.Kind)+"-"+string(o.Lang)+".pdf"), out, 0o600) //nolint:gosec // G703: the developer's own output directory
		}
	}
	if err := Write(&bytes.Buffer{}, sample(), Options{Kind: "x", Lang: French}); err == nil {
		t.Error("bad kind: nil error")
	}
	if err := Write(&bytes.Buffer{}, sample(), Options{Kind: Executive, Lang: "de"}); err == nil {
		t.Error("bad language: nil error")
	}
}

func TestEmptyData(t *testing.T) {
	var buf bytes.Buffer
	if err := Write(&buf, Data{OrgName: "Vide", GeneratedAt: time.Now(), PeriodDays: 30}, Options{Technical, French}); err != nil {
		t.Fatal(err)
	}
}

func TestOrderAndTexts(t *testing.T) {
	open := openFindings(sample())
	if len(open) != 3 || open[0].f.Severity != finding.SeverityCritical || open[2].f.Severity != finding.SeverityMedium {
		t.Errorf("order = %+v", open)
	}
	fr, en := texts[French], texts[English]
	if got := fr.fixedInPeriod(4, 30, ptr(53.0)); got != "4 problèmes corrigés ces 30 derniers jours, en 2 jours en moyenne." {
		t.Errorf("fr = %q", got)
	}
	if got := en.change(-3, 30); got != "Down 3 points over 30 days." {
		t.Errorf("en = %q", got)
	}
	if got := fr.date(time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)); got != "1 août 2026" {
		t.Errorf("fr date = %q", got)
	}
	if !strings.Contains(clip(strings.Repeat("a", 200), 0, 9, 50), "…") {
		t.Error("clip did not cut")
	}
}
