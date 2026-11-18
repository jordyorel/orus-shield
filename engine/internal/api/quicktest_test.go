package api

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jordyorel/orus-shield/engine/internal/finding"
	"github.com/jordyorel/orus-shield/engine/internal/quicktest"
)

// fakeQuickTest stands for the real passive modules (rule 6): a fixed
// report, and a count of the tests that actually ran.
func fakeQuickTest(runs *atomic.Int32) func(context.Context, string) (quicktest.Report, error) {
	return func(_ context.Context, domain string) (quicktest.Report, error) {
		runs.Add(1)
		if domain == "dead.example.com" {
			return quicktest.Report{}, errors.New("no check could run")
		}
		score := 50
		dmarc := func(asset string) finding.Finding {
			return finding.Finding{ModuleID: "email", CheckID: "dmarc-missing", Asset: asset, Severity: finding.SeverityHigh,
				Title: "No DMARC record", Description: "Anyone can send email in your name.", Remediation: []string{"Publish a DMARC record."},
				Translations: map[string]finding.Text{"fr": {Title: "Aucun enregistrement DMARC", Description: "N’importe qui peut envoyer des emails en votre nom.", Remediation: []string{"Publiez un enregistrement DMARC."}}}}
		}
		hsts := finding.Finding{ModuleID: "web", CheckID: "hsts-missing", Asset: "https://www." + domain + "/", Severity: finding.SeverityLow, Title: "No HSTS"}
		return quicktest.Report{Domain: domain, Score: &score, At: time.Now(),
			Checks: []quicktest.Check{{ID: "dmarc-missing", Severity: finding.SeverityHigh, Status: "failed"}, {ID: "spf-missing", Severity: finding.SeverityHigh, Status: "passed"}},
			Findings: []finding.Finding{hsts, dmarc("_dmarc." + domain), dmarc("_dmarc.www." + domain),
				{ModuleID: "email", CheckID: "dmarc-no-reports", Asset: "_dmarc." + domain, Severity: finding.SeverityInfo, Title: "DMARC reports not collected"}}}, nil
	}
}

func TestQuickTest(t *testing.T) {
	var runs atomic.Int32
	e := newEnvWith(t, func(c *Config) { c.QuickTest = fakeQuickTest(&runs) })

	var got quickResponse
	r := e.do("POST", "/api/v1/quicktest", "", quickRequest{Domain: " Example.COM "})
	r.json(t, &got)
	if r.status != http.StatusOK || got.Domain != "example.com" || got.Score == nil || *got.Score != 50 || got.ID == "" {
		t.Fatalf("test = %d %+v", r.status, got)
	}
	// One line per check, most severe first, without explanations yet.
	if len(got.Problems) != 2 || got.Problems[0].CheckID != "dmarc-missing" || got.Problems[0].TitleFR != "Aucun enregistrement DMARC" ||
		strings.Join(got.Problems[0].Hosts, ",") != "example.com,www.example.com" || got.Problems[1].Hosts[0] != "www.example.com" {
		t.Errorf("problems = %+v", got.Problems)
	}
	if strings.Contains(string(r.body), "Publish a DMARC record") || strings.Contains(string(r.body), "Anyone can send") {
		t.Error("explanations shown before an email was left")
	}

	// The same domain within the hour: the cached result, not a new run.
	if r := e.do("POST", "/api/v1/quicktest", "", quickRequest{Domain: "example.com"}); r.status != http.StatusOK || runs.Load() != 1 {
		t.Errorf("second test = %d, runs %d", r.status, runs.Load())
	}

	for _, bad := range []string{"localhost", "10.0.0.1", "printer.local", ""} {
		if r := e.do("POST", "/api/v1/quicktest", "", quickRequest{Domain: bad}); r.status != http.StatusBadRequest {
			t.Errorf("%q = %d, want 400", bad, r.status)
		}
	}
	if r := e.do("POST", "/api/v1/quicktest", "", quickRequest{Domain: "dead.example.com"}); r.status != http.StatusUnprocessableEntity {
		t.Errorf("unreachable domain = %d, want 422", r.status)
	}

	// Leaving an email: the explanations and steps, and the report by email
	// in the page's language.
	var unlocked struct {
		Problems []quickProblem `json:"problems"`
		Emailed  bool           `json:"emailed"`
	}
	r = e.doHeaders("POST", "/api/v1/quicktest/"+got.ID+"/unlock", map[string]string{"Sec-Fetch-Site": "same-origin", "Accept-Language": "fr-FR"},
		unlockRequest{Email: "Boss@Example.com", Marketing: false})
	r.json(t, &unlocked)
	if r.status != http.StatusOK || !unlocked.Emailed || unlocked.Problems[0].Details == nil ||
		unlocked.Problems[0].Details.RemediationFR[0] != "Publiez un enregistrement DMARC." {
		t.Fatalf("unlock = %d %+v", r.status, unlocked)
	}
	m := e.nextMail()
	if m.To != "boss@example.com" || m.Subject != "Orus Shield : le rapport de sécurité de example.com" ||
		!strings.Contains(m.Text, "1. Publiez un enregistrement DMARC.") || !strings.Contains(m.Text, "https://app.example/inscription?domaine=example.com") {
		t.Errorf("report email %q:\n%s", m.Subject, m.Text)
	}
	if r := e.do("POST", "/api/v1/quicktest/"+got.ID+"/unlock", "", unlockRequest{Email: "nope"}); r.status != http.StatusBadRequest {
		t.Errorf("bad email = %d, want 400", r.status)
	}
	if r := e.do("POST", "/api/v1/quicktest/0192f000-0000-7000-8000-000000000000/unlock", "", unlockRequest{Email: "a@example.com"}); r.status != http.StatusNotFound {
		t.Errorf("unknown test = %d, want 404", r.status)
	}
	// One address cannot have reports sent to it over and over.
	for i := 0; i < leadsPerEmail-1; i++ {
		e.do("POST", "/api/v1/quicktest/"+got.ID+"/unlock", "", unlockRequest{Email: "boss@example.com"})
		e.nextMail()
	}
	if r := e.do("POST", "/api/v1/quicktest/"+got.ID+"/unlock", "", unlockRequest{Email: "boss@example.com"}); r.status != http.StatusTooManyRequests {
		t.Errorf("report flood = %d, want 429", r.status)
	}
}

func TestQuickTestLimitsAnAddress(t *testing.T) {
	var runs atomic.Int32
	e := newEnvWith(t, func(c *Config) { c.QuickTest = fakeQuickTest(&runs) })
	for i := 0; i < quickPerIP; i++ {
		if r := e.do("POST", "/api/v1/quicktest", "", quickRequest{Domain: "example.com"}); r.status != http.StatusOK {
			t.Fatalf("test %d = %d", i, r.status)
		}
	}
	if r := e.do("POST", "/api/v1/quicktest", "", quickRequest{Domain: "other.com"}); r.status != http.StatusTooManyRequests {
		t.Errorf("over the limit = %d, want 429", r.status)
	}
	if runs.Load() != 1 {
		t.Errorf("runs = %d, want 1 (the others came from the cache)", runs.Load())
	}
}
