package api

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jordyorel/orus-shield/engine/internal/modules/m365"
	"github.com/jordyorel/orus-shield/engine/internal/plan"
)

const testTenant = "0b1c2d3e-4f50-6172-8394-a5b6c7d8e9f0"

// fakeMicrosoft answers our app's token requests and /organization (rule 6:
// never Microsoft's real service in tests). domains are the tenant's
// verified domains.
func fakeMicrosoft(t *testing.T, domains *atomic.Value) *httptest.Server {
	t.Helper()
	claims, _ := json.Marshal(map[string]any{"roles": m365.Permissions})
	token := "eyJhbGciOiJub25lIn0." + base64.RawURLEncoding.EncodeToString(claims) + ".sig"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/"+testTenant+"/oauth2/v2.0/token" && r.FormValue("client_secret") == "s3cret":
			_ = json.NewEncoder(w).Encode(map[string]string{"access_token": token})
		case r.URL.Path == "/v1.0/organization" && r.Header.Get("Authorization") == "Bearer "+token:
			var vd []map[string]any
			for i, d := range domains.Load().([]string) {
				vd = append(vd, map[string]any{"name": d, "isInitial": i == 0})
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"value": []any{map[string]any{"id": testTenant, "verifiedDomains": vd}}})
		default:
			w.WriteHeader(http.StatusUnauthorized)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestConnectMicrosoft365(t *testing.T) {
	var domains atomic.Value
	domains.Store([]string{"contoso.onmicrosoft.com", "example.com"})
	ms := fakeMicrosoft(t, &domains)
	e := newEnvWith(t, func(c *Config) {
		c.M365 = m365.Config{ClientID: "app-id", ClientSecret: "s3cret", LoginURL: ms.URL, GraphURL: ms.URL + "/v1.0"}
		c.M365Retry = time.Millisecond
	})
	a := e.tenant("A", "example.com")
	b := e.tenant("B", "example.org") // before A's scans are queued: the helper claims one
	base := "/api/v1/orgs/" + a.orgID
	connect := base + "/targets/" + a.target.ID + "/identities/m365"

	if r := e.do("POST", connect, a.session, nil); r.status != http.StatusConflict {
		t.Errorf("unverified domain = %d, want 409", r.status)
	}
	e.verifyTarget(a.session, a.orgID, a.target.ID)
	if r := e.do("POST", connect, a.viewer, nil); r.status != http.StatusForbidden {
		t.Errorf("viewer = %d, want 403", r.status)
	}

	// start returns Microsoft's consent URL and its state.
	start := func() url.Values {
		t.Helper()
		var out struct {
			URL string `json:"url"`
		}
		r := e.do("POST", connect, a.session, nil)
		r.json(t, &out)
		u, err := url.Parse(out.URL)
		if r.status != http.StatusOK || err != nil || u.Path != "/common/adminconsent" {
			t.Fatalf("start = %d %s", r.status, r.body)
		}
		q := u.Query()
		if q.Get("client_id") != "app-id" || q.Get("redirect_uri") != "https://app.example/api/v1/identities/m365/callback" || q.Get("state") == "" {
			t.Fatalf("consent URL = %s", out.URL)
		}
		return q
	}
	// back is Microsoft's return; it answers where the browser goes.
	back := func(params url.Values) string {
		t.Helper()
		r := e.do("GET", "/api/v1/identities/m365/callback?"+params.Encode(), "", nil)
		if r.status != http.StatusSeeOther {
			t.Fatalf("callback = %d %s", r.status, r.body)
		}
		return r.header.Get("Location")
	}
	actifs := "https://app.example/orgs/" + url.PathEscape(a.orgID) + "/actifs?m365="

	q := start()
	if got := back(url.Values{"state": {q.Get("state")}, "error": {"access_denied"}}); got != actifs+"refused" {
		t.Errorf("declined = %s", got)
	}
	if got := back(url.Values{"state": {"forged"}, "tenant": {testTenant}, "admin_consent": {"True"}}); got != "https://app.example/app?m365=invalid" {
		t.Errorf("forged state = %s", got)
	}

	// A tenant that does not manage the domain is not connected.
	domains.Store([]string{"contoso.onmicrosoft.com", "contoso.com"})
	if got := back(url.Values{"state": {start().Get("state")}, "tenant": {testTenant}, "admin_consent": {"True"}}); got != actifs+"not_bound" {
		t.Errorf("unbound tenant = %s", got)
	}

	domains.Store([]string{"contoso.onmicrosoft.com", "example.com"})
	state := start().Get("state")
	if got := back(url.Values{"state": {state}, "tenant": {strings.ToUpper(testTenant)}, "admin_consent": {"True"}}); got != actifs+"ok" {
		t.Fatalf("consent = %s", got)
	}
	var got struct {
		Items       []identityJSON `json:"items"`
		Available   bool           `json:"available"`
		Permissions []string       `json:"permissions"`
	}
	e.do("GET", base+"/identities", a.viewer, nil).json(t, &got)
	if !got.Available || len(got.Items) != 1 || got.Items[0].TenantID != testTenant || got.Items[0].TenantName != "contoso.onmicrosoft.com" ||
		got.Items[0].Domain != "example.com" || got.Items[0].ConnectedBy != "user:admin@example.com" || len(got.Permissions) != len(m365.Permissions) {
		t.Fatalf("identities = %+v", got)
	}
	// The first audit is queued at once.
	var scans list[scanJSON]
	e.do("GET", base+"/targets/"+a.target.ID+"/scans", a.viewer, nil).json(t, &scans)
	queued := false
	for _, sc := range scans.Items {
		queued = queued || (strings.Join(sc.Modules, ",") == "m365" && sc.RequestedBy == "user:admin@example.com")
	}
	if !queued {
		t.Errorf("no m365 scan queued: %+v", scans.Items)
	}

	// Another organization neither sees nor removes it.
	if r := e.do("DELETE", "/api/v1/orgs/"+b.orgID+"/targets/"+a.target.ID+"/identities/m365", b.session, nil); r.status != http.StatusNotFound {
		t.Errorf("cross-org delete = %d, want 404", r.status)
	}
	if r := e.do("DELETE", connect, a.session, nil); r.status != http.StatusNoContent {
		t.Errorf("disconnect = %d", r.status)
	}
	if r := e.do("DELETE", connect, a.session, nil); r.status != http.StatusNotFound {
		t.Errorf("second disconnect = %d, want 404", r.status)
	}

	// A state is valid 15 minutes.
	state = start().Get("state")
	e.now = e.now.Add(16 * time.Minute)
	if got := back(url.Values{"state": {state}, "tenant": {testTenant}, "admin_consent": {"True"}}); got != "https://app.example/app?m365=invalid" {
		t.Errorf("expired state = %s", got)
	}

	// The free offer does not include it.
	e.setPlan(a.orgID, plan.Subscription{Plan: plan.Discovery, Status: plan.Active})
	if r := e.do("POST", connect, a.session, nil); r.status != http.StatusForbidden || !strings.Contains(string(r.body), codePlanLimit) {
		t.Errorf("Gratuit = %d %s, want 403 plan_limit", r.status, r.body)
	}
}

func TestMicrosoft365NotConfigured(t *testing.T) {
	e := newEnv(t)
	a := e.tenant("A", "example.com")
	e.verifyTarget(a.session, a.orgID, a.target.ID)
	if r := e.do("POST", "/api/v1/orgs/"+a.orgID+"/targets/"+a.target.ID+"/identities/m365", a.session, nil); r.status != http.StatusServiceUnavailable {
		t.Errorf("start = %d, want 503", r.status)
	}
	var got struct {
		Available bool `json:"available"`
	}
	if e.do("GET", "/api/v1/orgs/"+a.orgID+"/identities", a.viewer, nil).json(t, &got); got.Available {
		t.Error("available without our app")
	}
}
