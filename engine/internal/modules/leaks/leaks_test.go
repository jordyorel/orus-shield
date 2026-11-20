package leaks

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jordyorel/orus-shield/engine/internal/finding"
	"github.com/jordyorel/orus-shield/engine/internal/module"
)

// fakeXON answers like XposedOrNot's breach-analytics endpoint (rule 6:
// never the real service in tests). answers maps an address to its
// breaches_details; an address absent gets XON's "not found" shape.
func fakeXON(t *testing.T, answers map[string][]map[string]any, limitAfter int) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		if r.URL.Path != "/v1/breach-analytics" {
			http.NotFound(w, r)
			return
		}
		if limitAfter > 0 && int(n) > limitAfter {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		email := r.URL.Query().Get("email")
		w.Header().Set("Content-Type", "application/json")
		details, ok := answers[email]
		if !ok {
			_ = json.NewEncoder(w).Encode(map[string]any{"BreachesSummary": map[string]any{"site": ""}, "ExposedBreaches": nil})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"ExposedBreaches": map[string]any{"breaches_details": details}})
	}))
	t.Cleanup(srv.Close)
	return srv, &calls
}

func run(t *testing.T, m *Module, domain string, emails []string) module.Result {
	t.Helper()
	cfg, _ := json.Marshal(module.RunConfig{Emails: emails})
	res, err := m.Run(context.Background(), module.Request{Target: module.Target{Domain: domain, Verified: true}, Config: cfg})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	return res
}

func TestRun(t *testing.T) {
	answers := map[string][]map[string]any{
		"alice@example.com": {
			{"breach": "Adobe", "domain": "adobe.com", "password_risk": "easytocrack", "xposed_data": "Email addresses;Passwords;Usernames", "xposed_date": "2013"},
			{"breach": "Canva", "domain": "canva.com", "password_risk": "hardtocrack", "xposed_data": "Email addresses;Names", "xposed_date": 2019},
		},
		"bob@example.com": {
			{"breach": "Dropbox", "domain": "dropbox.com", "password_risk": "hardtocrack", "xposed_data": "Email addresses;Passwords", "xposed_date": "2012"},
		},
	}
	srv, calls := fakeXON(t, answers, 0)
	m := New(Config{BaseURL: srv.URL, Pace: time.Millisecond})

	res := run(t, m, "example.com", []string{"Alice@Example.com", "bob@example.com", "carol@example.com", "eve@other.org", "alice@example.com"})

	if got := calls.Load(); got != 3 {
		t.Errorf("XON calls = %d, want 3 (other domains and duplicates skipped)", got)
	}
	want := map[string]finding.Severity{
		CheckPassword + " alice@example.com": finding.SeverityHigh,   // easy to crack
		CheckEmail + " alice@example.com":    finding.SeverityLow,    // Canva: no password
		CheckPassword + " bob@example.com":   finding.SeverityMedium, // hashed well
	}
	if len(res.Findings) != len(want) {
		t.Fatalf("findings = %d, want %d: %+v", len(res.Findings), len(want), res.Findings)
	}
	for _, f := range res.Findings {
		sev, ok := want[f.CheckID+" "+f.Asset]
		if !ok {
			t.Errorf("unexpected finding %s on %s", f.CheckID, f.Asset)
			continue
		}
		if f.Severity != sev {
			t.Errorf("%s on %s: severity %s, want %s", f.CheckID, f.Asset, f.Severity, sev)
		}
		// Dates and status are set by the engine when it records findings.
		now := time.Now()
		f.FirstSeen, f.LastSeen, f.Status = now, now, finding.StatusOpen
		if err := f.Validate(); err != nil {
			t.Errorf("%s: %v", f.CheckID, err)
		}
		if f.Translations["fr"].Title == "" || len(f.Translations["fr"].Remediation) != len(f.Remediation) {
			t.Errorf("%s: French text incomplete", f.CheckID)
		}
		if !strings.Contains(f.Evidence, "XposedOrNot") {
			t.Errorf("%s: evidence does not name the source", f.CheckID)
		}
		if strings.Contains(strings.ToLower(f.Evidence), "hunter2") {
			t.Errorf("evidence must never hold a password")
		}
	}
	if len(res.Evaluated) != 2 {
		t.Errorf("Evaluated = %v, want both checks", res.Evaluated)
	}
}

func TestNoAddressIsNotApplicable(t *testing.T) {
	srv, calls := fakeXON(t, nil, 0)
	res := run(t, New(Config{BaseURL: srv.URL}), "example.com", []string{"someone@other.org"})
	if calls.Load() != 0 || len(res.Findings) != 0 || len(res.Evaluated) != 0 {
		t.Errorf("no address on the domain: calls %d, result %+v", calls.Load(), res)
	}
}

func TestRateLimitKeepsTheRestUnreached(t *testing.T) {
	answers := map[string][]map[string]any{
		"a@example.com": {{"breach": "X", "xposed_data": "Email addresses;Passwords", "password_risk": "plaintext"}},
	}
	srv, _ := fakeXON(t, answers, 1)
	res := run(t, New(Config{BaseURL: srv.URL, Pace: time.Millisecond}), "example.com", []string{"a@example.com", "b@example.com", "c@example.com"})
	if len(res.Findings) != 1 || res.Findings[0].Severity != finding.SeverityHigh {
		t.Errorf("findings = %+v", res.Findings)
	}
	if strings.Join(res.Unreached, ",") != "b@example.com,c@example.com" {
		t.Errorf("Unreached = %v, want the addresses not checked", res.Unreached)
	}
}

func TestServerErrorFailsTheRun(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer srv.Close()
	cfg, _ := json.Marshal(module.RunConfig{Emails: []string{"a@example.com"}})
	_, err := New(Config{BaseURL: srv.URL}).Run(context.Background(), module.Request{Target: module.Target{Domain: "example.com"}, Config: cfg})
	if err == nil {
		t.Fatal("a failing XON must fail the run, not pass the checks")
	}
}

func TestAddresses(t *testing.T) {
	for _, tc := range []struct {
		in   []string
		want string
	}{
		{[]string{"A@Example.com", "a@example.com"}, "a@example.com"},
		{[]string{"x@mail.example.com"}, "x@mail.example.com"},
		{[]string{"x@notexample.com", "x@example.com.evil.org", "@example.com", "bad"}, ""},
	} {
		if got := strings.Join(Addresses(tc.in, "example.com"), ","); got != tc.want {
			t.Errorf("Addresses(%v) = %q, want %q", tc.in, got, tc.want)
		}
	}
	many := make([]string, 30)
	for i := range many {
		many[i] = string(rune('a'+i%26)) + strings.Repeat("x", i) + "@example.com"
	}
	if got := len(Addresses(many, "example.com")); got != MaxAddresses {
		t.Errorf("Addresses keeps %d, want at most %d", got, MaxAddresses)
	}
}
