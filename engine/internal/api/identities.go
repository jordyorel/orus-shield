package api

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/jordyorel/orus-shield/engine/internal/modules/m365"
	"github.com/jordyorel/orus-shield/engine/internal/store"
)

// Identity providers connected to a domain (step K): Microsoft 365 so far.
//
// Connecting is Microsoft's admin consent: the dashboard asks for a consent
// URL, the customer's Microsoft administrator accepts our app's read-only
// permissions, and Microsoft sends the browser back to the callback with
// the tenant's ID. The callback checks the tenant before recording it: it
// must list the domain among its verified domains, and our app must hold
// exactly the read-only permissions (m365.Inspect). Nothing secret is
// stored: our app reaches the tenant with its own credentials.
//
// The round trip carries a state sealed with the server's key: which
// organization, domain and admin started it, and until when it is valid.
// A forged or expired state is refused. A state used by someone else's
// administrator could only connect their tenant to our customer's domain if
// that tenant manages the domain, which the check refuses otherwise.

const (
	// consentTTL bounds the time between the click and Microsoft's return.
	consentTTL = 15 * time.Minute
	// consentOwner binds sealed states to this use of the key.
	consentOwner = "identity-consent:m365"
	// inspectAttempts: just after a consent, Microsoft may take a few
	// seconds before the token carries the new permissions.
	inspectAttempts = 4
	m365Callback    = "/api/v1/identities/m365/callback"
)

type consentState struct {
	Org    string `json:"o"`
	Target string `json:"t"`
	Actor  string `json:"a"`
	Exp    int64  `json:"e"`
	Nonce  string `json:"n"`
}

func (s *Server) sealState(st consentState) (string, error) {
	b, err := json.Marshal(st)
	if err != nil {
		return "", err
	}
	sealed, err := s.states.Seal(b, consentOwner)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(sealed), nil
}

func (s *Server) openState(v string) (consentState, bool) {
	raw, err := base64.RawURLEncoding.DecodeString(v)
	if err != nil || len(raw) > 2048 {
		return consentState{}, false
	}
	b, err := s.states.Open(raw, consentOwner)
	if err != nil {
		return consentState{}, false
	}
	var st consentState
	if json.Unmarshal(b, &st) != nil || s.cfg.Now().Unix() > st.Exp {
		return consentState{}, false
	}
	return st, true
}

type identityJSON struct {
	TargetID    string    `json:"target_id"`
	Domain      string    `json:"domain"`
	Provider    string    `json:"provider"`
	TenantID    string    `json:"tenant_id"`
	TenantName  string    `json:"tenant_name"`
	Permissions []string  `json:"permissions"`
	ConnectedAt time.Time `json:"connected_at"`
	ConnectedBy string    `json:"connected_by"`
}

// listIdentities answers GET /orgs/{org}/identities: the connections, and
// whether connecting is possible on this server (our app configured).
func (s *Server) listIdentities(w http.ResponseWriter, r *http.Request, req orgRequest) {
	list, err := req.org.IdentityConnections(r.Context())
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	out := make([]identityJSON, 0, len(list))
	for _, c := range list {
		out = append(out, identityJSON{TargetID: c.TargetID, Domain: c.Domain, Provider: c.Provider, TenantID: c.TenantID,
			TenantName: c.TenantName, Permissions: c.Permissions, ConnectedAt: c.ConnectedAt.UTC(), ConnectedBy: c.ConnectedBy})
	}
	writeJSON(w, http.StatusOK, struct {
		Items       []identityJSON `json:"items"`
		Available   bool           `json:"available"`
		Permissions []string       `json:"permissions"`
	}{out, s.m365 != nil && s.cfg.PublicURL != "", m365.Permissions})
}

// connectM365 answers POST /orgs/{org}/targets/{target}/identities/m365
// with {"url"}: Microsoft's admin consent page, to open in the browser.
func (s *Server) connectM365(w http.ResponseWriter, r *http.Request, req orgRequest, t store.Target) {
	if s.m365 == nil || s.cfg.PublicURL == "" {
		writeErrorCode(w, http.StatusServiceUnavailable, "identities_off", "Microsoft 365 connections are not configured on this server")
		return
	}
	if t.Internal {
		writeError(w, http.StatusBadRequest, "not for an internal network")
		return
	}
	if !t.Verified() {
		writeError(w, http.StatusConflict, "verify the domain first")
		return
	}
	p, ok := s.planOf(w, r, req)
	if !ok {
		return
	}
	if !p.Identities {
		planLimit(w, "the "+p.Name+" offer does not include identity audits")
		return
	}
	nonce := make([]byte, 12)
	_, _ = rand.Read(nonce) // crypto/rand.Read never fails (Go 1.24+)
	state, err := s.sealState(consentState{Org: req.org.ID(), Target: t.ID, Actor: actor(req),
		Exp: s.cfg.Now().Add(consentTTL).Unix(), Nonce: hex.EncodeToString(nonce)})
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	q := url.Values{
		"client_id":    {s.cfg.M365.ClientID},
		"state":        {state},
		"redirect_uri": {s.cfg.PublicURL + m365Callback},
	}
	writeJSON(w, http.StatusOK, map[string]string{"url": s.m365Login() + "/common/adminconsent?" + q.Encode()})
}

func (s *Server) m365Login() string {
	if s.cfg.M365.LoginURL != "" {
		return strings.TrimRight(s.cfg.M365.LoginURL, "/")
	}
	return m365.DefaultLoginURL
}

// m365Callback answers Microsoft's return after the admin consent. It
// always redirects to the dashboard, with ?m365= telling how it went:
// ok, refused (the admin declined), not_bound (the tenant does not manage
// the domain), permissions (not exactly the read-only set), in_use (the
// tenant is connected to another domain), plan, error; invalid without a
// valid state.
func (s *Server) m365Callback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	st, ok := s.openState(q.Get("state"))
	if !ok || s.m365 == nil {
		http.Redirect(w, r, s.cfg.PublicURL+"/app?m365=invalid", http.StatusSeeOther)
		return
	}
	done := func(outcome string) {
		http.Redirect(w, r, s.cfg.PublicURL+"/orgs/"+url.PathEscape(st.Org)+"/actifs?m365="+outcome, http.StatusSeeOther)
	}
	if q.Get("error") != "" || !strings.EqualFold(q.Get("admin_consent"), "true") {
		done("refused")
		return
	}
	org, err := s.org(st.Org)
	if err != nil {
		done("error")
		return
	}
	ctx := r.Context()
	t, err := org.GetTarget(ctx, st.Target)
	if err != nil || !t.Verified() || t.Internal {
		done("error")
		return
	}
	eff, err := org.Plan(ctx, s.cfg.Now())
	if err != nil {
		done("error")
		return
	}
	if !eff.Plan.Identities {
		done("plan")
		return
	}
	tenant, err := s.inspectTenant(ctx, q.Get("tenant"), t.Domain)
	switch {
	case errors.Is(err, m365.ErrNotBound):
		done("not_bound")
		return
	case errors.Is(err, m365.ErrPermissions):
		done("permissions")
		return
	case err != nil:
		s.log.Warn("m365 connection check", "err", err)
		done("error")
		return
	}
	err = org.ConnectIdentity(ctx, store.IdentityConnection{TargetID: t.ID, Provider: store.ProviderM365, TenantID: tenant.ID,
		TenantName: tenant.Name, Permissions: tenant.Roles}, st.Actor)
	switch {
	case errors.Is(err, store.ErrTenantInUse):
		done("in_use")
		return
	case err != nil:
		s.log.Error("record m365 connection", "err", err)
		done("error")
		return
	}
	// The first audit right away; a failure here only delays it to the
	// next scheduled scan.
	if _, err := org.EnqueueScan(ctx, t.ID, []string{m365.ID}, st.Actor); err != nil {
		s.log.Warn("queue m365 scan", "err", err)
	}
	done("ok")
}

// inspectTenant checks the tenant, retrying for a few seconds while the
// new consent reaches Microsoft's token service.
func (s *Server) inspectTenant(ctx context.Context, tenant, domain string) (m365.Tenant, error) {
	var last error
	for i := range inspectAttempts {
		if i > 0 {
			select {
			case <-ctx.Done():
				return m365.Tenant{}, ctx.Err()
			case <-time.After(s.cfg.M365Retry):
			}
		}
		t, err := s.m365.Inspect(ctx, tenant, domain)
		if err == nil || errors.Is(err, m365.ErrNotBound) {
			return t, err
		}
		last = err
	}
	return m365.Tenant{}, last
}

// disconnectM365 answers DELETE /orgs/{org}/targets/{target}/identities/m365.
// It forgets the tenant; the customer removes our app on their side.
func (s *Server) disconnectM365(w http.ResponseWriter, r *http.Request, req orgRequest, t store.Target) {
	err := req.org.DisconnectIdentity(r.Context(), t.ID, store.ProviderM365, actor(req))
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
