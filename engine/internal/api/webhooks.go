package api

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/jordyorel/orus-shield/engine/internal/quicktest"
	"github.com/jordyorel/orus-shield/engine/internal/store"
)

// Outgoing webhooks (Réglages > API, offers with plan.PublicAPI), managed
// by a signed-in admin only. The worker delivers them (package webhook).

type webhookJSON struct {
	ID             string     `json:"id"`
	URL            string     `json:"url"`
	Events         []string   `json:"events"`
	CreatedBy      string     `json:"created_by"`
	CreatedAt      time.Time  `json:"created_at"`
	LastDeliveryAt *time.Time `json:"last_delivery_at"`
	LastStatus     *int       `json:"last_status"`
	LastError      *string    `json:"last_error"`
}

func toWebhookJSON(w store.Webhook) webhookJSON {
	return webhookJSON{ID: w.ID, URL: w.URL, Events: w.Events, CreatedBy: w.CreatedBy, CreatedAt: w.CreatedAt,
		LastDeliveryAt: w.LastDeliveryAt, LastStatus: w.LastStatus, LastError: w.LastError}
}

// webhookURL checks an endpoint's URL as far as it can be checked now: an
// https URL on a public name or address, without credentials. The worker
// checks again at every delivery that the name resolves to public
// addresses only (a name can change).
func webhookURL(raw string) (string, bool) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" || len(raw) > 2000 {
		return "", false
	}
	host := u.Hostname()
	if ip, err := netip.ParseAddr(host); err == nil {
		if !quicktest.Public(ip) {
			return "", false
		}
	} else if _, err := quicktest.NormalizeDomain(host); err != nil {
		return "", false
	}
	return u.String(), true
}

// listWebhooks answers GET /orgs/{org}/webhooks.
func (s *Server) listWebhooks(w http.ResponseWriter, r *http.Request, req orgRequest) {
	hooks, err := req.org.Webhooks(r.Context())
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	out := make([]webhookJSON, 0, len(hooks))
	for _, h := range hooks {
		out = append(out, toWebhookJSON(h))
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": out, "events": store.WebhookEvents})
}

type createWebhookRequest struct {
	URL    string   `json:"url"`
	Events []string `json:"events"`
}

// createWebhook answers POST /orgs/{org}/webhooks: 201 with the endpoint
// and its signing secret, shown this once.
func (s *Server) createWebhook(w http.ResponseWriter, r *http.Request, req orgRequest) {
	if s.creds == nil {
		writeError(w, http.StatusServiceUnavailable, "webhooks are not configured on this server (ORUS_CREDENTIALS_KEY)")
		return
	}
	var body createWebhookRequest
	if !decode(w, r, &body) {
		return
	}
	p, ok := s.planOf(w, r, req)
	if !ok {
		return
	}
	if !p.PublicAPI {
		planLimit(w, "webhooks are included in the Pro and custom plans")
		return
	}
	u, ok := webhookURL(body.URL)
	if !ok {
		writeErrorCode(w, http.StatusBadRequest, "bad_url", "the URL must be https, on a public name, without credentials")
		return
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		s.internalError(w, r, err)
		return
	}
	secret := "whsec_" + base64.RawURLEncoding.EncodeToString(raw)
	sealed, err := s.creds.Seal([]byte(secret), store.WebhookSealOwner(req.org.ID(), u))
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	hook, err := req.org.CreateWebhook(r.Context(), u, body.Events, sealed, actor(req))
	switch {
	case errors.Is(err, store.ErrBadWebhook):
		writeErrorCode(w, http.StatusBadRequest, "bad_events", "choose at least one event among "+strings.Join(store.WebhookEvents, ", "))
		return
	case errors.Is(err, store.ErrTooManyWebhooks):
		writeErrorCode(w, http.StatusConflict, "too_many_webhooks", "10 endpoints at most: remove one first")
		return
	case err != nil:
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"webhook": toWebhookJSON(hook), "secret": secret})
}

// deleteWebhook answers DELETE /orgs/{org}/webhooks/{webhook}.
func (s *Server) deleteWebhook(w http.ResponseWriter, r *http.Request, req orgRequest) {
	err := req.org.DeleteWebhook(r.Context(), r.PathValue("webhook"), actor(req))
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

// pingWebhook answers POST /orgs/{org}/webhooks/{webhook}/test: a "ping"
// event is queued; the endpoint's last status shows how it went.
func (s *Server) pingWebhook(w http.ResponseWriter, r *http.Request, req orgRequest) {
	err := req.org.QueueWebhookPing(r.Context(), r.PathValue("webhook"), s.cfg.Now())
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusAccepted)
}
