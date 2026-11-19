package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jordyorel/orus-shield/engine/internal/finding"
	"github.com/jordyorel/orus-shield/engine/internal/plan"
	"github.com/jordyorel/orus-shield/engine/internal/store"
)

func TestWebhooks(t *testing.T) {
	e := newEnv(t)
	a := e.tenant("A", "example.com")
	base := "/api/v1/orgs/" + a.orgID + "/webhooks"

	for _, bad := range []string{"http://hooks.acme.com/x", "https://localhost/x", "https://10.0.0.1/x", "https://127.0.0.1/x", "https://u:p@hooks.acme.com/x", "ftp://x.com"} {
		if r := e.do("POST", base, a.session, createWebhookRequest{URL: bad, Events: []string{"finding.opened"}}); r.status != http.StatusBadRequest {
			t.Errorf("%s = %d, want 400", bad, r.status)
		}
	}
	if r := e.do("POST", base, a.session, createWebhookRequest{URL: "https://hooks.acme.com/orus", Events: []string{"nope"}}); r.status != http.StatusBadRequest {
		t.Errorf("unknown event = %d", r.status)
	}
	var created struct {
		Webhook webhookJSON `json:"webhook"`
		Secret  string      `json:"secret"`
	}
	r := e.do("POST", base, a.session, createWebhookRequest{URL: "https://hooks.acme.com/orus", Events: []string{"finding.opened", "scan.finished"}})
	r.json(t, &created)
	if r.status != http.StatusCreated || !strings.HasPrefix(created.Secret, "whsec_") || created.Webhook.ID == "" {
		t.Fatalf("create = %d %s", r.status, r.body)
	}
	// The secret is never shown again.
	if r := e.do("GET", base, a.session, nil); r.status != http.StatusOK || strings.Contains(string(r.body), created.Secret) || !strings.Contains(string(r.body), "hooks.acme.com") {
		t.Errorf("list = %d %s", r.status, r.body)
	}
	// Never with an API key, nor for a viewer.
	_, key := e.newKey(a.orgID, a.session, "write")
	if r := e.keyDo("GET", base, key, nil); r.status != http.StatusUnauthorized {
		t.Errorf("key lists webhooks = %d, want 401", r.status)
	}
	if r := e.do("GET", base, a.viewer, nil); r.status != http.StatusForbidden {
		t.Errorf("viewer lists webhooks = %d, want 403", r.status)
	}

	ctx := context.Background()
	claim := func() []store.WebhookDelivery {
		t.Helper()
		ds, err := e.st.ClaimWebhookDeliveries(ctx, time.Now().Add(time.Hour), time.Minute, 50)
		if err != nil {
			t.Fatal(err)
		}
		return ds
	}
	if r := e.do("POST", base+"/"+created.Webhook.ID+"/test", a.session, nil); r.status != http.StatusAccepted {
		t.Fatalf("test = %d %s", r.status, r.body)
	}
	if ds := claim(); len(ds) != 1 || ds[0].EventType != store.EventPing || ds[0].URL != "https://hooks.acme.com/orus" {
		t.Fatalf("ping deliveries = %+v", ds)
	}

	// A scan that opens a finding: one finding.opened and one scan.finished
	// (the endpoint did not subscribe to finding.fixed).
	org, _ := e.st.Org(a.orgID)
	spf := finding.Finding{SchemaVersion: finding.SchemaVersion, ModuleID: "email", CheckID: "spf-missing",
		ID: finding.NewID("email", "spf-missing", "example.com", "example.com"), Target: "example.com", Asset: "example.com",
		Severity: finding.SeverityHigh, Title: "No SPF", Description: "No SPF record."}
	e.emailScan(org, a.target.ID, time.Now(), nil, a.finding, spf)
	ds := claim()
	types := map[string]int{}
	for _, d := range ds {
		types[d.EventType]++
	}
	if types[store.EventFindingOpened] != 1 || types[store.EventScanFinished] != 1 || types[store.EventFindingFixed] != 0 {
		t.Fatalf("deliveries = %v", types)
	}
	for _, d := range ds {
		if d.EventType != store.EventFindingOpened {
			continue
		}
		var env struct {
			ID   string `json:"id"`
			Type string `json:"type"`
			Data struct {
				Domain  string               `json:"domain"`
				Finding store.WebhookFinding `json:"finding"`
			} `json:"data"`
		}
		if err := json.Unmarshal(d.Payload, &env); err != nil || !strings.HasPrefix(env.ID, "evt_") || env.Data.Finding.CheckID != "spf-missing" || env.Data.Domain != "example.com" {
			t.Errorf("payload %s: %v", d.Payload, err)
		}
	}

	if r := e.do("DELETE", base+"/"+created.Webhook.ID, a.session, nil); r.status != http.StatusNoContent {
		t.Errorf("delete = %d", r.status)
	}
	e.setPlan(a.orgID, plan.Subscription{Plan: plan.SME, Status: plan.Active})
	if r := e.do("POST", base, a.session, createWebhookRequest{URL: "https://hooks.acme.com/orus", Events: []string{"scan.finished"}}); r.status != http.StatusForbidden {
		t.Errorf("Essentiel creates a webhook = %d, want 403", r.status)
	}
}

func TestWebhookURL(t *testing.T) {
	for in, want := range map[string]bool{
		"https://hooks.acme.com/orus":   true,
		"https://hooks.acme.com:8443/x": true,
		"https://93.184.216.34/x":       true,
		"http://hooks.acme.com/x":       false,
		"https://intranet/x":            false,
		"https://printer.local/x":       false,
		"https://[::1]/x":               false,
		"https://169.254.169.254/x":     false,
		"https://a@hooks.acme.com/x":    false,
	} {
		if _, ok := webhookURL(in); ok != want {
			t.Errorf("webhookURL(%q) = %v, want %v", in, ok, want)
		}
	}
}
