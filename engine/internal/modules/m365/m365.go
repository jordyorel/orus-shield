// Package m365 audits a customer's Microsoft 365 tenant (step K): accounts
// without multi-factor authentication, global administrators, the tenant's
// baseline protection (security defaults or conditional access), legacy
// authentication, user consent to applications, guest invitations, inactive
// accounts and inbox rules that forward mail outside the organization.
//
// It reads Microsoft Graph with our own multi-tenant app's credentials
// (client credentials grant), in the tenant whose administrator consented
// to read-only permissions; the worker passes the tenant ID as
// module.RunConfig.Identity. The permissions it needs, all application and
// read-only: Organization.Read.All, User.Read.All, AuditLog.Read.All,
// UserAuthenticationMethod.Read.All, RoleManagement.Read.Directory,
// Policy.Read.All, MailboxSettings.Read. It never reads mail, files or
// calendars, and never writes.
//
// The tenant must list the target's domain among its verified domains:
// otherwise the run fails, so a connection cannot be used to audit a
// tenant that does not manage the customer's verified domain.
//
// A permission not granted, or data the tenant's licence does not include
// (sign-in activity needs Microsoft Entra ID P1), leaves the checks that
// need it not applicable: never passed.
package m365

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/jordyorel/orus-shield/engine/internal/finding"
	"github.com/jordyorel/orus-shield/engine/internal/module"
)

// ID is the stable module ID.
const ID = "m365"

// Provider is the value of module.ScanIdentity.Provider this module audits.
const Provider = "m365"

// Check IDs.
const (
	CheckAdminMFA        = "m365-admin-without-mfa"
	CheckUserMFA         = "m365-user-without-mfa"
	CheckBaseline        = "m365-no-mfa-policy"
	CheckLegacyAuth      = "m365-legacy-auth-allowed"
	CheckTooManyAdmins   = "m365-too-many-global-admins"
	CheckSingleAdmin     = "m365-single-global-admin"
	CheckUserConsent     = "m365-user-consent-allowed"
	CheckGuestInvites    = "m365-guest-invites-everyone"
	CheckAppRegistration = "m365-users-can-register-apps"
	CheckInactive        = "m365-inactive-accounts"
	CheckForward         = "m365-inbox-forward-external"
)

const (
	// DefaultLoginURL and DefaultGraphURL are Microsoft's public endpoints.
	DefaultLoginURL = "https://login.microsoftonline.com"
	DefaultGraphURL = "https://graph.microsoft.com/v1.0"
	// globalAdminRole is the Global Administrator role's template ID, the
	// same in every tenant.
	globalAdminRole = "62e90394-69f5-4237-9190-012177145e10"
	// MaxUsers bounds the accounts read in one run; MaxLookups the
	// per-account calls (authentication methods, inbox rules).
	MaxUsers   = 1000
	MaxLookups = 300
	// maxAdmins: Microsoft recommends fewer than five global administrators.
	maxAdmins = 4
	// inactiveAfter: an enabled account without a sign-in for this long.
	inactiveAfter = 90 * 24 * time.Hour
	// pace spaces Graph calls, well under its per-app limits.
	pace           = 50 * time.Millisecond
	requestTimeout = 30 * time.Second
	userAgent      = "OrusShield-M365/1"
)

// Config is how the module reaches Microsoft. ClientID and ClientSecret
// are our multi-tenant app's (ORUS_M365_CLIENT_ID, ORUS_M365_CLIENT_SECRET,
// worker only); without them the module refuses to run.
type Config struct {
	ClientID     string
	ClientSecret string
	// LoginURL and GraphURL override Microsoft's endpoints (tests).
	LoginURL, GraphURL string
	HTTP               *http.Client
	Pace               time.Duration // zero: pace
	Now                func() time.Time
}

// Module is the Microsoft 365 audit.
type Module struct{ cfg Config }

// New returns the module.
func New(cfg Config) *Module {
	if cfg.LoginURL == "" {
		cfg.LoginURL = DefaultLoginURL
	}
	if cfg.GraphURL == "" {
		cfg.GraphURL = DefaultGraphURL
	}
	cfg.LoginURL = strings.TrimRight(cfg.LoginURL, "/")
	cfg.GraphURL = strings.TrimRight(cfg.GraphURL, "/")
	if cfg.HTTP == nil {
		// No redirect is followed: Graph answers directly, and a redirect
		// would carry our token elsewhere.
		cfg.HTTP = &http.Client{Timeout: requestTimeout, CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}}
	}
	if cfg.Pace == 0 {
		cfg.Pace = pace
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Module{cfg: cfg}
}

// Info implements module.Module.
func (m *Module) Info() module.Info {
	checks := make([]module.Check, 0, len(catalog))
	for _, id := range checkOrder {
		c := catalog[id]
		checks = append(checks, module.Check{ID: id, Category: module.CategoryIdentity, Severity: c.severity, Title: c.title, TitleFR: c.titleFR})
	}
	return module.Info{ID: ID, Name: "Microsoft 365", Kind: module.KindPassive, UsesIdentity: true, Checks: checks}
}

// ErrNotBound: the tenant does not list the target's domain among its
// verified domains.
var ErrNotBound = errors.New("the tenant does not manage this domain")

// ErrPermissions: the permissions granted to our app in the tenant are not
// exactly the read-only ones it needs (one missing, or one more).
var ErrPermissions = errors.New("the permissions granted do not match the read-only set")

// Permissions are the application permissions the module needs, all read
// only. The admin consents to exactly these; the token's roles must be
// these and nothing else.
var Permissions = []string{
	"AuditLog.Read.All",
	"MailboxSettings.Read",
	"Organization.Read.All",
	"Policy.Read.All",
	"RoleManagement.Read.Directory",
	"User.Read.All",
	"UserAuthenticationMethod.Read.All",
}

// Tenant is what a connection check learns about a tenant.
type Tenant struct {
	ID      string
	Name    string   // the initial domain, e.g. contoso.onmicrosoft.com
	Domains []string // verified domains, lowercased
	Roles   []string // the permissions granted to our app
}

// Inspect checks a tenant before it is connected to domain: our app gets a
// token there with exactly the read-only permissions, and the tenant lists
// domain (or a parent of it) among its verified domains. The API calls it
// after the admin consent; Run makes the same checks at every scan.
func (m *Module) Inspect(ctx context.Context, tenant, domain string) (Tenant, error) {
	tenant = strings.ToLower(tenant)
	if !isGUID(tenant) {
		return Tenant{}, fmt.Errorf("m365: tenant ID %q is not a GUID", clip(tenant, 40))
	}
	domain, err := module.NormalizeDomain(domain)
	if err != nil {
		return Tenant{}, fmt.Errorf("m365: %w", err)
	}
	g, err := m.open(ctx, tenant)
	if err != nil {
		return Tenant{}, fmt.Errorf("m365: %w", err)
	}
	t := &tenantData{}
	if err := readOrganization(ctx, g, t, tenant, domain); err != nil {
		return Tenant{}, fmt.Errorf("m365: %w", err)
	}
	return Tenant{ID: tenant, Name: t.name, Domains: t.domains, Roles: g.roles}, nil
}

// open gets a token in tenant and checks the permissions it carries.
func (m *Module) open(ctx context.Context, tenant string) (*graph, error) {
	if m.cfg.ClientID == "" || m.cfg.ClientSecret == "" {
		return nil, errors.New("app credentials not configured (ORUS_M365_CLIENT_ID, ORUS_M365_CLIENT_SECRET)")
	}
	token, err := fetchToken(ctx, m.cfg.HTTP, m.cfg.LoginURL, tenant, m.cfg.ClientID, m.cfg.ClientSecret)
	if err != nil {
		return nil, err
	}
	roles, err := tokenRoles(token)
	if err != nil {
		return nil, err
	}
	if missing, extra := diff(Permissions, roles); len(missing)+len(extra) > 0 {
		return nil, fmt.Errorf("%w: missing %v, unexpected %v", ErrPermissions, missing, extra)
	}
	return &graph{http: m.cfg.HTTP, base: m.cfg.GraphURL, token: token, pace: m.cfg.Pace, roles: roles}, nil
}

// tokenRoles reads the application permissions ("roles") of an access
// token. The token came straight from Microsoft over TLS, so its signature
// is not checked here: we only read what Microsoft granted us.
func tokenRoles(token string) ([]string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("token: not a JWT")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("token: payload: %w", err)
	}
	var claims struct {
		Roles []string `json:"roles"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("token: claims: %w", err)
	}
	slices.Sort(claims.Roles)
	return slices.Compact(claims.Roles), nil
}

// diff returns what want lacks in got, and what got has beyond want.
func diff(want, got []string) (missing, extra []string) {
	for _, w := range want {
		if !slices.Contains(got, w) {
			missing = append(missing, w)
		}
	}
	for _, g := range got {
		if !slices.Contains(want, g) {
			extra = append(extra, clip(g, 80))
		}
	}
	return missing, extra
}

// Run implements module.Module.
func (m *Module) Run(ctx context.Context, req module.Request) (module.Result, error) {
	domain, err := module.NormalizeDomain(req.Target.Domain)
	if err != nil {
		return module.Result{}, fmt.Errorf("m365: %w", err)
	}
	var rc module.RunConfig
	if len(req.Config) > 0 {
		if err := json.Unmarshal(req.Config, &rc); err != nil {
			return module.Result{}, fmt.Errorf("m365: config: %w", err)
		}
	}
	if rc.Identity == nil || rc.Identity.Provider != Provider {
		// No tenant connected: every check is not applicable.
		return module.Result{}, nil
	}
	tenant := strings.ToLower(rc.Identity.TenantID)
	if !isGUID(tenant) {
		return module.Result{}, fmt.Errorf("m365: tenant ID %q is not a GUID", clip(tenant, 40))
	}
	g, err := m.open(ctx, tenant)
	if err != nil {
		return module.Result{}, fmt.Errorf("m365: %w", err)
	}
	t, err := m.collect(ctx, g, tenant, domain)
	if err != nil {
		return module.Result{}, fmt.Errorf("m365: %w", err)
	}
	return t.evaluate(domain, m.cfg.Now()), nil
}

// tenantData is what one run read. A nil field was not readable.
type tenantData struct {
	name      string   // the tenant's initial domain (contoso.onmicrosoft.com), in evidence
	domains   []string // verified domains, lowercased
	users     []user
	truncated bool
	mfa       map[string]bool // user ID → MFA registered; nil: unknown
	admins    []user          // global administrators (users only); nil: unknown
	defaults  *bool           // security defaults enabled
	policies  []caPolicy      // conditional access; nil with caKnown false: unknown
	caKnown   bool
	authz     *authzPolicy
	lastSign  map[string]time.Time // user ID → last sign-in; nil: unknown (licence)
	forwards  map[string][]string  // user ID → external addresses its inbox rules send to; nil: unknown
}

type user struct {
	ID          string    `json:"id"`
	UPN         string    `json:"userPrincipalName"`
	Enabled     bool      `json:"accountEnabled"`
	UserType    string    `json:"userType"`
	Created     time.Time `json:"createdDateTime"`
	ODataType   string    `json:"@odata.type"`
	SignInState *struct {
		Last           time.Time `json:"lastSignInDateTime"`
		NonInteractive time.Time `json:"lastNonInteractiveSignInDateTime"`
		Successful     time.Time `json:"lastSuccessfulSignInDateTime"`
	} `json:"signInActivity"`
}

// member: an enabled account of the organization (not a guest).
func (u user) member() bool { return u.Enabled && !strings.EqualFold(u.UserType, "guest") }

type caPolicy struct {
	State      string `json:"state"`
	Conditions struct {
		ClientAppTypes []string `json:"clientAppTypes"`
		Users          struct {
			IncludeUsers []string `json:"includeUsers"`
		} `json:"users"`
	} `json:"conditions"`
	GrantControls *struct {
		BuiltInControls []string `json:"builtInControls"`
	} `json:"grantControls"`
}

type authzPolicy struct {
	AllowInvitesFrom string `json:"allowInvitesFrom"`
	Defaults         struct {
		CreateApps bool     `json:"allowedToCreateApps"`
		Grants     []string `json:"permissionGrantPoliciesAssigned"`
	} `json:"defaultUserRolePermissions"`
}

// collect reads the tenant. Only ErrThrottled, a refused binding and
// unexpected failures stop the run; a forbidden read leaves its part unknown.
func (m *Module) collect(ctx context.Context, g *graph, tenant, domain string) (*tenantData, error) {
	t := &tenantData{}

	if err := readOrganization(ctx, g, t, tenant, domain); err != nil {
		return nil, err
	}

	var err error
	if t.users, t.truncated, err = list[user](ctx, g, "/users?$select=id,userPrincipalName,accountEnabled,userType,createdDateTime&$top=999", MaxUsers); err != nil {
		return nil, fmt.Errorf("users: %w", err)
	}

	if err := m.readMFA(ctx, g, t); err != nil {
		return nil, err
	}

	admins, _, err := list[user](ctx, g, "/directoryRoles(roleTemplateId='"+globalAdminRole+"')/members?$select=id,userPrincipalName,accountEnabled", MaxUsers)
	switch {
	case err == nil:
		t.admins = []user{}
		for _, a := range admins {
			if a.ODataType == "" || a.ODataType == "#microsoft.graph.user" {
				t.admins = append(t.admins, a)
			}
		}
	case !isUnreadable(err):
		return nil, fmt.Errorf("global administrators: %w", err)
	}

	var sd struct {
		IsEnabled bool `json:"isEnabled"`
	}
	switch err := g.get(ctx, "/policies/identitySecurityDefaultsEnforcementPolicy", &sd); {
	case err == nil:
		t.defaults = &sd.IsEnabled
	case !isUnreadable(err):
		return nil, fmt.Errorf("security defaults: %w", err)
	}

	policies, _, err := list[caPolicy](ctx, g, "/identity/conditionalAccess/policies", 500)
	switch {
	case err == nil:
		t.policies, t.caKnown = policies, true
	case !isUnreadable(err):
		return nil, fmt.Errorf("conditional access: %w", err)
	}

	var az authzPolicy
	switch err := g.get(ctx, "/policies/authorizationPolicy", &az); {
	case err == nil:
		t.authz = &az
	case !isUnreadable(err):
		return nil, fmt.Errorf("authorization policy: %w", err)
	}

	// Sign-in activity needs an Entra ID P1 licence: forbidden without it.
	signed, _, err := list[user](ctx, g, "/users?$select=id,signInActivity&$top=500", MaxUsers)
	switch {
	case err == nil:
		t.lastSign = map[string]time.Time{}
		for _, u := range signed {
			if s := u.SignInState; s != nil {
				t.lastSign[u.ID] = latest(s.Last, s.NonInteractive, s.Successful)
			}
		}
	case !isUnreadable(err):
		return nil, fmt.Errorf("sign-in activity: %w", err)
	}

	if err := m.readForwards(ctx, g, t); err != nil {
		return nil, err
	}
	return t, nil
}

// readOrganization reads the tenant's verified domains and checks that it
// manages domain.
func readOrganization(ctx context.Context, g *graph, t *tenantData, tenant, domain string) error {
	orgs, _, err := list[struct {
		ID       string `json:"id"`
		Verified []struct {
			Name      string `json:"name"`
			IsInitial bool   `json:"isInitial"`
		} `json:"verifiedDomains"`
	}](ctx, g, "/organization?$select=id,verifiedDomains", 1)
	if err != nil {
		return fmt.Errorf("organization: %w", err)
	}
	if len(orgs) != 1 || !strings.EqualFold(orgs[0].ID, tenant) {
		return fmt.Errorf("organization: %w", ErrNotBound)
	}
	for _, d := range orgs[0].Verified {
		n, err := module.NormalizeDomain(d.Name)
		if err != nil {
			continue
		}
		t.domains = append(t.domains, n)
		if d.IsInitial {
			t.name = n
		}
	}
	if !t.manages(domain) {
		return ErrNotBound
	}
	if t.name == "" {
		t.name = domain
	}
	return nil
}

// readMFA uses the registration report, else each member's methods.
func (m *Module) readMFA(ctx context.Context, g *graph, t *tenantData) error {
	type reg struct {
		ID         string `json:"id"`
		Registered bool   `json:"isMfaRegistered"`
	}
	regs, _, err := list[reg](ctx, g, "/reports/authenticationMethods/userRegistrationDetails?$select=id,isMfaRegistered", MaxUsers)
	if err == nil {
		t.mfa = map[string]bool{}
		for _, r := range regs {
			t.mfa[r.ID] = r.Registered
		}
		return nil
	}
	if !isUnreadable(err) {
		return fmt.Errorf("registration details: %w", err)
	}
	// Fallback: the methods of each member account, at most MaxLookups.
	mfa := map[string]bool{}
	n := 0
	for _, u := range t.users {
		if !u.member() {
			continue
		}
		if n == MaxLookups {
			break
		}
		n++
		methods, _, err := list[struct {
			Type string `json:"@odata.type"`
		}](ctx, g, "/users/"+url.PathEscape(u.ID)+"/authentication/methods", 50)
		if errors.Is(err, errForbidden) {
			return nil // permission not granted: MFA unknown
		}
		if errors.Is(err, errNotFound) {
			continue
		}
		if err != nil {
			return fmt.Errorf("authentication methods: %w", err)
		}
		for _, me := range methods {
			if mfaMethods[me.Type] {
				mfa[u.ID] = true
			}
		}
		if !mfa[u.ID] {
			mfa[u.ID] = false
		}
	}
	t.mfa = mfa
	return nil
}

// mfaMethods are the methods that count as a second factor. Password and
// email (self-service reset only) do not.
var mfaMethods = map[string]bool{
	"#microsoft.graph.microsoftAuthenticatorAuthenticationMethod":  true,
	"#microsoft.graph.phoneAuthenticationMethod":                   true,
	"#microsoft.graph.fido2AuthenticationMethod":                   true,
	"#microsoft.graph.softwareOathAuthenticationMethod":            true,
	"#microsoft.graph.windowsHelloForBusinessAuthenticationMethod": true,
	"#microsoft.graph.platformCredentialAuthenticationMethod":      true,
}

// readForwards reads the inbox rules of member accounts, at most MaxLookups.
func (m *Module) readForwards(ctx context.Context, g *graph, t *tenantData) error {
	type recipient struct {
		EmailAddress struct {
			Address string `json:"address"`
		} `json:"emailAddress"`
	}
	type rule struct {
		Enabled bool `json:"isEnabled"`
		Actions struct {
			ForwardTo             []recipient `json:"forwardTo"`
			RedirectTo            []recipient `json:"redirectTo"`
			ForwardAsAttachmentTo []recipient `json:"forwardAsAttachmentTo"`
		} `json:"actions"`
	}
	fw := map[string][]string{}
	n := 0
	for _, u := range t.users {
		if !u.member() {
			continue
		}
		if n == MaxLookups {
			break
		}
		n++
		rules, _, err := list[rule](ctx, g, "/users/"+url.PathEscape(u.ID)+"/mailFolders/inbox/messageRules", 100)
		if errors.Is(err, errForbidden) {
			return nil // permission not granted: forwards unknown
		}
		if errors.Is(err, errNotFound) {
			continue // no mailbox
		}
		if err != nil {
			return fmt.Errorf("inbox rules: %w", err)
		}
		for _, r := range rules {
			if !r.Enabled {
				continue
			}
			for _, list := range [][]recipient{r.Actions.ForwardTo, r.Actions.RedirectTo, r.Actions.ForwardAsAttachmentTo} {
				for _, rc := range list {
					a := strings.ToLower(clip(rc.EmailAddress.Address, 254))
					if _, host, ok := strings.Cut(a, "@"); ok && !t.manages(host) && !slices.Contains(fw[u.ID], a) {
						fw[u.ID] = append(fw[u.ID], a)
					}
				}
			}
		}
	}
	t.forwards = fw
	return nil
}

// manages reports whether host is one of the tenant's verified domains or
// under one.
func (t *tenantData) manages(host string) bool {
	for _, d := range t.domains {
		if host == d || strings.HasSuffix(host, "."+d) {
			return true
		}
	}
	return false
}

// evaluate turns what was read into findings and evaluated checks.
func (t *tenantData) evaluate(domain string, now time.Time) module.Result {
	var res module.Result
	evaluated := func(ids ...string) { res.Evaluated = append(res.Evaluated, ids...) }
	add := func(check, asset string, sev finding.Severity, evidence string, args ...any) {
		res.Findings = append(res.Findings, build(domain, check, asset, sev, "Tenant: "+t.name+"\n"+evidence, args...))
	}
	// Tenant-wide findings are about the domain the tenant is connected
	// to; the tenant's own name is in their evidence.
	tenantAsset := domain
	note := ""
	if t.truncated {
		note = fmt.Sprintf("\nOnly the first %d accounts were read.", MaxUsers)
	}

	// Global administrators.
	isAdmin := map[string]bool{}
	if t.admins != nil {
		evaluated(CheckTooManyAdmins, CheckSingleAdmin)
		var names []string
		for _, a := range t.admins {
			isAdmin[a.ID] = true
			names = append(names, a.UPN)
		}
		ev := "Global administrators: " + strings.Join(names, ", ")
		switch n := len(t.admins); {
		case n > maxAdmins:
			add(CheckTooManyAdmins, tenantAsset, catalog[CheckTooManyAdmins].severity, ev, n)
		case n == 1:
			add(CheckSingleAdmin, tenantAsset, catalog[CheckSingleAdmin].severity, ev)
		}
	}

	// Multi-factor authentication, per account.
	if t.mfa != nil {
		if t.admins != nil {
			evaluated(CheckAdminMFA)
		}
		evaluated(CheckUserMFA)
		for _, u := range t.users {
			registered, known := t.mfa[u.ID]
			if !u.member() || !known || registered {
				continue
			}
			ev := "Account: " + u.UPN + "\nNo second factor registered (Microsoft Entra registration details)." + note
			if isAdmin[u.ID] {
				add(CheckAdminMFA, lower(u.UPN), catalog[CheckAdminMFA].severity, ev)
			} else {
				add(CheckUserMFA, lower(u.UPN), catalog[CheckUserMFA].severity, ev)
			}
		}
	}

	// Baseline protection and legacy authentication.
	if t.defaults != nil && (*t.defaults || t.caKnown) {
		evaluated(CheckBaseline, CheckLegacyAuth)
		if !*t.defaults {
			if !slices.ContainsFunc(t.policies, requiresMFAForAll) {
				add(CheckBaseline, tenantAsset, catalog[CheckBaseline].severity,
					fmt.Sprintf("Security defaults: off\nConditional access policies: %d, none enabled that requires MFA for all users", len(t.policies)))
			}
			if !slices.ContainsFunc(t.policies, blocksLegacy) {
				add(CheckLegacyAuth, tenantAsset, catalog[CheckLegacyAuth].severity,
					"Security defaults: off\nNo enabled conditional access policy blocks legacy authentication (Exchange ActiveSync, other clients) for all users")
			}
		}
	}

	// Tenant-wide settings.
	if a := t.authz; a != nil {
		evaluated(CheckUserConsent, CheckGuestInvites, CheckAppRegistration)
		if slices.Contains(a.Defaults.Grants, "ManagePermissionGrantsForSelf.microsoft-user-default-legacy") {
			add(CheckUserConsent, tenantAsset, catalog[CheckUserConsent].severity,
				"permissionGrantPoliciesAssigned: ManagePermissionGrantsForSelf.microsoft-user-default-legacy")
		}
		if strings.EqualFold(a.AllowInvitesFrom, "everyone") {
			add(CheckGuestInvites, tenantAsset, catalog[CheckGuestInvites].severity, "allowInvitesFrom: everyone")
		}
		if a.Defaults.CreateApps {
			add(CheckAppRegistration, tenantAsset, catalog[CheckAppRegistration].severity, "defaultUserRolePermissions.allowedToCreateApps: true")
		}
	}

	// Inactive accounts.
	if t.lastSign != nil {
		evaluated(CheckInactive)
		for _, u := range t.users {
			if !u.member() || u.Created.IsZero() || now.Sub(u.Created) < inactiveAfter {
				continue
			}
			last := t.lastSign[u.ID]
			if !last.IsZero() && now.Sub(last) < inactiveAfter {
				continue
			}
			ev := "Account: " + u.UPN + "\nCreated: " + u.Created.UTC().Format("2006-01-02")
			if last.IsZero() {
				ev += "\nLast sign-in: never"
			} else {
				ev += "\nLast sign-in: " + last.UTC().Format("2006-01-02")
			}
			add(CheckInactive, lower(u.UPN), catalog[CheckInactive].severity, ev)
		}
	}

	// Inbox rules forwarding outside.
	if t.forwards != nil {
		evaluated(CheckForward)
		for _, u := range t.users {
			if to := t.forwards[u.ID]; len(to) > 0 {
				add(CheckForward, lower(u.UPN), catalog[CheckForward].severity,
					"Mailbox: "+u.UPN+"\nEnabled inbox rules send mail to: "+strings.Join(to, ", "))
			}
		}
	}
	return res
}

// requiresMFAForAll: an enabled policy for all users granting access only
// with MFA, on browsers and apps.
func requiresMFAForAll(p caPolicy) bool {
	return p.State == "enabled" && slices.Contains(p.Conditions.Users.IncludeUsers, "All") &&
		p.GrantControls != nil && slices.Contains(p.GrantControls.BuiltInControls, "mfa") &&
		(len(p.Conditions.ClientAppTypes) == 0 || slices.Contains(p.Conditions.ClientAppTypes, "all") ||
			slices.Contains(p.Conditions.ClientAppTypes, "browser"))
}

// blocksLegacy: an enabled policy for all users blocking the legacy
// clients (Exchange ActiveSync and other clients).
func blocksLegacy(p caPolicy) bool {
	return p.State == "enabled" && slices.Contains(p.Conditions.Users.IncludeUsers, "All") &&
		p.GrantControls != nil && slices.Contains(p.GrantControls.BuiltInControls, "block") &&
		(slices.Contains(p.Conditions.ClientAppTypes, "exchangeActiveSync") || slices.Contains(p.Conditions.ClientAppTypes, "other"))
}

func isUnreadable(err error) bool { return errors.Is(err, errForbidden) || errors.Is(err, errNotFound) }

func latest(ts ...time.Time) time.Time {
	var out time.Time
	for _, t := range ts {
		if t.After(out) {
			out = t
		}
	}
	return out
}

func lower(s string) string { return strings.ToLower(clip(s, 254)) }

// isGUID reports whether s is a lowercase GUID (8-4-4-4-12 hex digits). The
// tenant ID ends up in a URL: nothing else may get through.
func isGUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, c := range s {
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return false
			}
		default:
			if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
				return false
			}
		}
	}
	return true
}

// ConfigFromEnv reads our app's credentials, ORUS_M365_CLIENT_ID and
// ORUS_M365_CLIENT_SECRET: both or neither. Neither: Microsoft 365 cannot
// be connected, and the module refuses to run.
func ConfigFromEnv(getenv func(string) string) (Config, error) {
	c := Config{ClientID: strings.TrimSpace(getenv("ORUS_M365_CLIENT_ID")), ClientSecret: getenv("ORUS_M365_CLIENT_SECRET")}
	if (c.ClientID == "") != (c.ClientSecret == "") {
		return Config{}, errors.New("ORUS_M365_CLIENT_ID and ORUS_M365_CLIENT_SECRET: set both or neither")
	}
	if c.ClientID != "" && !isGUID(strings.ToLower(c.ClientID)) {
		return Config{}, fmt.Errorf("ORUS_M365_CLIENT_ID=%q: want the app's client ID (a GUID)", clip(c.ClientID, 40))
	}
	return c, nil
}
