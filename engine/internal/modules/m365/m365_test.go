package m365

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jordyorel/orus-shield/engine/internal/finding"
	"github.com/jordyorel/orus-shield/engine/internal/module"
)

const tenant = "0b1c2d3e-4f50-6172-8394-a5b6c7d8e9f0"

var now = time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)

// fakeTenant is a Microsoft 365 tenant as Graph shows it (rule 6: never
// Microsoft's real service in tests). routes maps a request path (without
// /v1.0 and the query) to its JSON answer; a status in forbidden answers
// that path 403.
type fakeTenant struct {
	routes    map[string]any
	forbidden map[string]bool
	throttle  string // path answered 429
}

func (ft fakeTenant) serve(t *testing.T) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var calls atomic.Int32
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.URL.Path == "/"+tenant+"/oauth2/v2.0/token" {
			if r.Method != http.MethodPost || r.FormValue("client_secret") != "s3cret" || r.FormValue("grant_type") != "client_credentials" {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"error":"invalid_client"}`))
				return
			}
			_, _ = w.Write([]byte(`{"token_type":"Bearer","expires_in":3599,"access_token":"tok"}`))
			return
		}
		if r.Header.Get("Authorization") != "Bearer tok" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		path := strings.TrimPrefix(r.URL.Path, "/v1.0")
		if path == "/users" && strings.Contains(r.URL.Query().Get("$select"), "signInActivity") {
			path = "/users#signin"
		}
		switch {
		case path == ft.throttle:
			w.WriteHeader(http.StatusTooManyRequests)
			return
		case ft.forbidden[path]:
			w.WriteHeader(http.StatusForbidden)
			return
		}
		body, ok := ft.routes[path]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if s, ok := body.(string); ok {
			_, _ = w.Write([]byte(strings.ReplaceAll(s, "{base}", srv.URL)))
			return
		}
		_ = json.NewEncoder(w).Encode(body)
	}))
	t.Cleanup(srv.Close)
	return srv, &calls
}

func values(v ...any) map[string]any { return map[string]any{"value": v} }

// contoso: a small tenant with most of the problems the module looks for.
func contoso() fakeTenant {
	old := now.AddDate(-1, 0, 0).Format(time.RFC3339)
	return fakeTenant{routes: map[string]any{
		"/organization": values(map[string]any{"id": tenant, "verifiedDomains": []any{
			map[string]any{"name": "contoso.onmicrosoft.com", "isInitial": true},
			map[string]any{"name": "Example.com", "isDefault": true},
		}}),
		"/users": values(
			map[string]any{"id": "u1", "userPrincipalName": "Admin@example.com", "accountEnabled": true, "userType": "Member", "createdDateTime": old},
			map[string]any{"id": "u2", "userPrincipalName": "alice@example.com", "accountEnabled": true, "userType": "Member", "createdDateTime": old},
			map[string]any{"id": "u3", "userPrincipalName": "bob@example.com", "accountEnabled": true, "userType": "Member", "createdDateTime": old},
			map[string]any{"id": "u4", "userPrincipalName": "gone@example.com", "accountEnabled": false, "userType": "Member", "createdDateTime": old},
			map[string]any{"id": "u5", "userPrincipalName": "partner_ext#EXT#@contoso.onmicrosoft.com", "accountEnabled": true, "userType": "Guest", "createdDateTime": old},
		),
		"/reports/authenticationMethods/userRegistrationDetails": values(
			map[string]any{"id": "u1", "isMfaRegistered": false},
			map[string]any{"id": "u2", "isMfaRegistered": false},
			map[string]any{"id": "u3", "isMfaRegistered": true},
			map[string]any{"id": "u4", "isMfaRegistered": false}, // disabled: ignored
			map[string]any{"id": "u5", "isMfaRegistered": false}, // guest: ignored
		),
		"/directoryRoles(roleTemplateId='" + globalAdminRole + "')/members": values(
			map[string]any{"@odata.type": "#microsoft.graph.user", "id": "u1", "userPrincipalName": "Admin@example.com"},
			map[string]any{"@odata.type": "#microsoft.graph.servicePrincipal", "id": "sp1"},
		),
		"/policies/identitySecurityDefaultsEnforcementPolicy": map[string]any{"isEnabled": false},
		"/identity/conditionalAccess/policies": values(
			// Report-only: does not count.
			map[string]any{"state": "enabledForReportingButNotEnforced", "conditions": map[string]any{"clientAppTypes": []string{"all"}, "users": map[string]any{"includeUsers": []string{"All"}}}, "grantControls": map[string]any{"builtInControls": []string{"mfa"}}},
		),
		"/policies/authorizationPolicy": map[string]any{
			"allowInvitesFrom": "everyone",
			"defaultUserRolePermissions": map[string]any{
				"allowedToCreateApps":             true,
				"permissionGrantPoliciesAssigned": []string{"ManagePermissionGrantsForSelf.microsoft-user-default-legacy"},
			},
		},
		"/users#signin": values(
			map[string]any{"id": "u1", "signInActivity": map[string]any{"lastSignInDateTime": now.AddDate(0, 0, -2).Format(time.RFC3339)}},
			map[string]any{"id": "u2", "signInActivity": map[string]any{"lastSignInDateTime": now.AddDate(0, -6, 0).Format(time.RFC3339)}},
			map[string]any{"id": "u3", "signInActivity": map[string]any{"lastNonInteractiveSignInDateTime": now.AddDate(0, 0, -1).Format(time.RFC3339)}},
		),
		"/users/u1/mailFolders/inbox/messageRules": values(),
		"/users/u2/mailFolders/inbox/messageRules": values(
			map[string]any{"isEnabled": true, "actions": map[string]any{"forwardTo": []any{
				map[string]any{"emailAddress": map[string]any{"address": "Collect@evil.example.net"}},
				map[string]any{"emailAddress": map[string]any{"address": "bob@example.com"}}, // inside: fine
			}}},
			map[string]any{"isEnabled": false, "actions": map[string]any{"redirectTo": []any{
				map[string]any{"emailAddress": map[string]any{"address": "old@elsewhere.example"}},
			}}},
		),
		// u3 has no mailbox: 404.
	}}
}

func newModule(srv *httptest.Server) *Module {
	return New(Config{ClientID: "app", ClientSecret: "s3cret", LoginURL: srv.URL, GraphURL: srv.URL + "/v1.0",
		Pace: time.Microsecond, Now: func() time.Time { return now }})
}

func run(m *Module, domain string, id *module.ScanIdentity) (module.Result, error) {
	cfg, _ := json.Marshal(module.RunConfig{Identity: id})
	return m.Run(context.Background(), module.Request{Target: module.Target{Domain: domain, Verified: true}, Config: cfg})
}

var connected = &module.ScanIdentity{Provider: Provider, TenantID: strings.ToUpper(tenant)}

func keys(res module.Result) []string {
	var out []string
	for _, f := range res.Findings {
		out = append(out, f.CheckID+" "+f.Asset)
	}
	slices.Sort(out)
	return out
}

func TestRun(t *testing.T) {
	srv, _ := contoso().serve(t)
	res, err := run(newModule(srv), "example.com", connected)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	want := []string{
		CheckAdminMFA + " admin@example.com",
		CheckAppRegistration + " contoso.onmicrosoft.com",
		CheckForward + " alice@example.com",
		CheckGuestInvites + " contoso.onmicrosoft.com",
		CheckInactive + " alice@example.com",
		CheckLegacyAuth + " contoso.onmicrosoft.com",
		CheckBaseline + " contoso.onmicrosoft.com",
		CheckSingleAdmin + " contoso.onmicrosoft.com", // the service principal is not counted
		CheckUserConsent + " contoso.onmicrosoft.com",
		CheckUserMFA + " alice@example.com",
	}
	slices.Sort(want)
	if got := keys(res); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("findings:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}

	for _, f := range res.Findings {
		f.FirstSeen, f.LastSeen, f.Status = now, now, finding.StatusOpen
		if err := f.Validate(); err != nil {
			t.Errorf("%s: %v", f.CheckID, err)
		}
		if f.CheckID == CheckForward {
			if !strings.Contains(f.Evidence, "collect@evil.example.net") || strings.Contains(f.Evidence, "bob@example.com") || strings.Contains(f.Evidence, "old@") {
				t.Errorf("forward evidence = %q: want only the enabled rule's outside address", f.Evidence)
			}
		}
	}
	// Every check was readable: all evaluated.
	if got, want := len(res.Evaluated), len(checkOrder); got != want {
		t.Errorf("evaluated %d checks (%v), want %d", got, res.Evaluated, want)
	}
	if _, err := module.Evaluate(newModule(srv).Info(), res); err != nil {
		t.Errorf("Evaluate: %v", err)
	}
}

func TestHealthyTenant(t *testing.T) {
	ft := contoso()
	ft.routes["/policies/identitySecurityDefaultsEnforcementPolicy"] = map[string]any{"isEnabled": true}
	ft.routes["/reports/authenticationMethods/userRegistrationDetails"] = values(
		map[string]any{"id": "u1", "isMfaRegistered": true}, map[string]any{"id": "u2", "isMfaRegistered": true}, map[string]any{"id": "u3", "isMfaRegistered": true})
	ft.routes["/policies/authorizationPolicy"] = map[string]any{"allowInvitesFrom": "adminsAndGuestInviters",
		"defaultUserRolePermissions": map[string]any{"permissionGrantPoliciesAssigned": []string{"ManagePermissionGrantsForSelf.microsoft-user-default-low"}}}
	ft.routes["/directoryRoles(roleTemplateId='"+globalAdminRole+"')/members"] = values(
		map[string]any{"id": "u1", "userPrincipalName": "admin@example.com"}, map[string]any{"id": "u3", "userPrincipalName": "bob@example.com"})
	delete(ft.routes, "/users/u2/mailFolders/inbox/messageRules")
	ft.routes["/users#signin"] = values(
		map[string]any{"id": "u1", "signInActivity": map[string]any{"lastSignInDateTime": now.Format(time.RFC3339)}},
		map[string]any{"id": "u2", "signInActivity": map[string]any{"lastSuccessfulSignInDateTime": now.Format(time.RFC3339)}},
		map[string]any{"id": "u3", "signInActivity": map[string]any{"lastSignInDateTime": now.Format(time.RFC3339)}})
	srv, _ := ft.serve(t)
	res, err := run(newModule(srv), "example.com", connected)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 0 {
		t.Errorf("findings = %v, want none", keys(res))
	}
	if len(res.Evaluated) != len(checkOrder) {
		t.Errorf("evaluated = %v, want every check", res.Evaluated)
	}
}

// A tenant without Entra ID P1 and with some permissions withheld: what
// cannot be read is not applicable, never passed.
func TestUnreadableParts(t *testing.T) {
	ft := contoso()
	ft.forbidden = map[string]bool{
		"/reports/authenticationMethods/userRegistrationDetails": true, // falls back to methods
		"/identity/conditionalAccess/policies":                   true,
		"/users#signin":                                          true, // no P1
		"/users/u1/mailFolders/inbox/messageRules":               true, // MailboxSettings.Read not granted
	}
	ft.routes["/users/u1/authentication/methods"] = values(map[string]any{"@odata.type": "#microsoft.graph.passwordAuthenticationMethod"})
	ft.routes["/users/u2/authentication/methods"] = values(
		map[string]any{"@odata.type": "#microsoft.graph.passwordAuthenticationMethod"},
		map[string]any{"@odata.type": "#microsoft.graph.emailAuthenticationMethod"}) // reset only: not a second factor
	ft.routes["/users/u3/authentication/methods"] = values(map[string]any{"@odata.type": "#microsoft.graph.microsoftAuthenticatorAuthenticationMethod"})
	srv, _ := ft.serve(t)
	res, err := run(newModule(srv), "example.com", connected)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{CheckBaseline, CheckLegacyAuth, CheckInactive, CheckForward} {
		if slices.Contains(res.Evaluated, id) {
			t.Errorf("%s evaluated, want not applicable", id)
		}
		for _, f := range res.Findings {
			if f.CheckID == id {
				t.Errorf("finding for unreadable %s", id)
			}
		}
	}
	got := keys(res)
	for _, w := range []string{CheckAdminMFA + " admin@example.com", CheckUserMFA + " alice@example.com"} {
		if !slices.Contains(got, w) {
			t.Errorf("missing %s (methods fallback) in %v", w, got)
		}
	}
	if slices.Contains(got, CheckUserMFA+" bob@example.com") {
		t.Error("bob has Authenticator: want no MFA finding")
	}
}

func TestSecurityDefaultsCoverBaseline(t *testing.T) {
	ft := contoso()
	ft.routes["/policies/identitySecurityDefaultsEnforcementPolicy"] = map[string]any{"isEnabled": true}
	ft.forbidden = map[string]bool{"/identity/conditionalAccess/policies": true}
	srv, _ := ft.serve(t)
	res, err := run(newModule(srv), "example.com", connected)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(res.Evaluated, CheckBaseline) || !slices.Contains(res.Evaluated, CheckLegacyAuth) {
		t.Errorf("evaluated = %v: security defaults on decide both checks", res.Evaluated)
	}
	for _, k := range keys(res) {
		if strings.HasPrefix(k, CheckBaseline) || strings.HasPrefix(k, CheckLegacyAuth) {
			t.Errorf("unexpected %s", k)
		}
	}
}

func TestConditionalAccessCoversBaseline(t *testing.T) {
	all := map[string]any{"includeUsers": []string{"All"}}
	ft := contoso()
	ft.routes["/identity/conditionalAccess/policies"] = values(
		map[string]any{"state": "enabled", "conditions": map[string]any{"clientAppTypes": []string{"all"}, "users": all}, "grantControls": map[string]any{"builtInControls": []string{"mfa"}}},
		map[string]any{"state": "enabled", "conditions": map[string]any{"clientAppTypes": []string{"exchangeActiveSync", "other"}, "users": all}, "grantControls": map[string]any{"builtInControls": []string{"block"}}},
	)
	srv, _ := ft.serve(t)
	res, err := run(newModule(srv), "example.com", connected)
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range keys(res) {
		if strings.HasPrefix(k, CheckBaseline) || strings.HasPrefix(k, CheckLegacyAuth) {
			t.Errorf("unexpected %s", k)
		}
	}
}

func TestTooManyAdmins(t *testing.T) {
	ft := contoso()
	var admins []any
	for _, id := range []string{"a1", "a2", "a3", "a4", "a5"} {
		admins = append(admins, map[string]any{"id": id, "userPrincipalName": id + "@example.com"})
	}
	ft.routes["/directoryRoles(roleTemplateId='"+globalAdminRole+"')/members"] = values(admins...)
	srv, _ := ft.serve(t)
	res, err := run(newModule(srv), "example.com", connected)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range res.Findings {
		if f.CheckID == CheckTooManyAdmins {
			if f.Title != "5 global administrators" || f.Translations["fr"].Title != "5 administrateurs généraux" {
				t.Errorf("titles = %q / %q", f.Title, f.Translations["fr"].Title)
			}
			return
		}
	}
	t.Errorf("no %s in %v", CheckTooManyAdmins, keys(res))
}

func TestRefusals(t *testing.T) {
	srv, calls := contoso().serve(t)
	m := newModule(srv)

	// No tenant connected: nothing read, nothing evaluated.
	res, err := run(m, "example.com", nil)
	if err != nil || len(res.Findings)+len(res.Evaluated) != 0 || calls.Load() != 0 {
		t.Errorf("no identity: %+v, %v, %d calls; want an empty result and no call", res, err, calls.Load())
	}
	if res, err := run(m, "example.com", &module.ScanIdentity{Provider: "google", TenantID: tenant}); err != nil || len(res.Evaluated) != 0 {
		t.Errorf("other provider: %+v, %v", res, err)
	}

	// A tenant that does not manage the domain is never audited.
	if _, err := run(m, "other.org", connected); !errors.Is(err, ErrNotBound) {
		t.Errorf("unbound domain: %v, want ErrNotBound", err)
	}
	// A subdomain of a verified domain is managed by the tenant.
	if _, err := run(m, "shop.example.com", connected); err != nil {
		t.Errorf("subdomain: %v", err)
	}

	for _, bad := range []string{"../../evil", "contoso.onmicrosoft.com", tenant + "x", ""} {
		if _, err := run(m, "example.com", &module.ScanIdentity{Provider: Provider, TenantID: bad}); err == nil {
			t.Errorf("tenant %q accepted", bad)
		}
	}

	noSecret := New(Config{ClientID: "app", LoginURL: srv.URL, GraphURL: srv.URL + "/v1.0"})
	if _, err := run(noSecret, "example.com", connected); err == nil {
		t.Error("no client secret: Run() = nil, want error")
	}
	wrong := New(Config{ClientID: "app", ClientSecret: "nope", LoginURL: srv.URL, GraphURL: srv.URL + "/v1.0"})
	if _, err := run(wrong, "example.com", connected); err == nil || !strings.Contains(err.Error(), "invalid_client") {
		t.Errorf("wrong secret: %v", err)
	}
}

func TestThrottled(t *testing.T) {
	ft := contoso()
	ft.throttle = "/policies/authorizationPolicy"
	srv, _ := ft.serve(t)
	if _, err := run(newModule(srv), "example.com", connected); !errors.Is(err, ErrThrottled) {
		t.Errorf("Run() = %v, want ErrThrottled", err)
	}
}

func TestPaging(t *testing.T) {
	ft := contoso()
	ft.routes["/users"] = `{"value":[{"id":"u1","userPrincipalName":"admin@example.com","accountEnabled":true,"userType":"Member"}],"@odata.nextLink":"{base}/v1.0/users/page2"}`
	ft.routes["/users/page2"] = values(map[string]any{"id": "u2", "userPrincipalName": "alice@example.com", "accountEnabled": true, "userType": "Member"})
	srv, _ := ft.serve(t)
	res, err := run(newModule(srv), "example.com", connected)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(keys(res), CheckUserMFA+" alice@example.com") {
		t.Errorf("second page not read: %v", keys(res))
	}

	// A next link to another host would carry our token there: refused.
	ft.routes["/users"] = `{"value":[],"@odata.nextLink":"https://attacker.example/steal"}`
	srv2, _ := ft.serve(t)
	if _, err := run(newModule(srv2), "example.com", connected); err == nil || !strings.Contains(err.Error(), "refusing link") {
		t.Errorf("foreign next link: %v, want refusal", err)
	}
}

func TestCatalog(t *testing.T) {
	info := New(Config{}).Info()
	if len(info.Checks) != len(catalog) || len(checkOrder) != len(catalog) {
		t.Fatalf("catalog %d, order %d, checks %d", len(catalog), len(checkOrder), len(info.Checks))
	}
	if err := module.NewRegistry().Register(New(Config{})); err != nil {
		t.Fatalf("Register: %v", err)
	}
	for id, c := range catalog {
		if c.titleFR == "" || c.findingFR == "" || c.descFR == "" || len(c.steps) == 0 || len(c.steps) != len(c.stepsFR) {
			t.Errorf("%s: French text incomplete or steps differ (%d en, %d fr)", id, len(c.steps), len(c.stepsFR))
		}
	}
}
