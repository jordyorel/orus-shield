package api

import (
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/jordyorel/orus-shield/engine/internal/store"
)

// Public API (offers with plan.PublicAPI): the organization's own tools
// call the same routes as the dashboard with "Authorization: Bearer
// orus_…". A key reaches only its organization, and only:
//   - the read routes (any key);
//   - starting a scan and changing a finding's status ("write" keys).
//
// Everything else (members, billing, test accounts, agents, settings, the
// keys themselves) needs a signed-in admin: a leaked key must not be able
// to take over an account or reach a secret.

// keyRate bounds the requests of one key per minute, in this process.
const keyRate = 120

// keyLimiter counts each key's requests in fixed one-minute windows.
type keyLimiter struct {
	mu      sync.Mutex
	windows map[string]keyWindow
}

type keyWindow struct {
	start time.Time
	n     int
}

// allow reports whether key may make one more request at now.
func (l *keyLimiter) allow(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.windows == nil {
		l.windows = map[string]keyWindow{}
	}
	w := l.windows[key]
	if now.Sub(w.start) >= time.Minute {
		w = keyWindow{start: now}
	}
	if w.n >= keyRate {
		return false
	}
	w.n++
	l.windows[key] = w
	// Forget idle keys now and then, so the map stays small.
	if len(l.windows) > 10000 {
		for k, x := range l.windows {
			if now.Sub(x.start) >= time.Minute {
				delete(l.windows, k)
			}
		}
	}
	return true
}

// bearerKey returns the API key of an "Authorization: Bearer" header.
func bearerKey(r *http.Request) (string, bool) {
	h := r.Header.Get("Authorization")
	key, ok := strings.CutPrefix(h, "Bearer ")
	if !ok {
		return "", false
	}
	key = strings.TrimSpace(key)
	return key, key != ""
}

// withOrgOrKey serves a route to a signed-in member (as withOrg), or to an
// API key of the organization with at least scope.
func (s *Server) withOrgOrKey(minRole, scope string, h orgHandler) http.HandlerFunc {
	session := s.withOrg(minRole, h)
	return func(w http.ResponseWriter, r *http.Request) {
		key, ok := bearerKey(r)
		if !ok {
			session(w, r)
			return
		}
		now := s.cfg.Now()
		ka, err := s.keys.KeyAccess(r.Context(), key, now)
		if errors.Is(err, store.ErrInvalidKey) {
			writeErrorCode(w, http.StatusUnauthorized, "invalid_key", "invalid, revoked or expired API key")
			return
		}
		if err != nil {
			s.internalError(w, r, err)
			return
		}
		// A key of another organization: as if this one did not exist.
		if ka.OrgID != r.PathValue("org") {
			writeError(w, http.StatusNotFound, "not found")
			return
		}
		if scope == store.ScopeWrite && ka.Scope != store.ScopeWrite {
			writeErrorCode(w, http.StatusForbidden, "read_only_key", "this API key can only read")
			return
		}
		if !s.keyLimit.allow(ka.KeyID, now) {
			w.Header().Set("Retry-After", "60")
			writeErrorCode(w, http.StatusTooManyRequests, "rate_limited", "too many requests for this API key, try again in a minute")
			return
		}
		org, err := s.org(ka.OrgID)
		if err != nil {
			writeError(w, http.StatusNotFound, "not found")
			return
		}
		req := orgRequest{org: org, role: store.RoleViewer, keyName: ka.Name, sess: store.Session{Email: "api-key:" + ka.Name}}
		if ka.Scope == store.ScopeWrite {
			req.role = store.RoleAdmin
		}
		// The offer in force decides, at every call: a key outlives a trial.
		p, ok := s.planOf(w, r, req)
		if !ok {
			return
		}
		if !p.PublicAPI {
			planLimit(w, "API access is included in the Pro and custom plans")
			return
		}
		h(w, r, req)
	}
}

type apiKeyJSON struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	Prefix     string     `json:"prefix"`
	Scope      string     `json:"scope"`
	CreatedBy  string     `json:"created_by"`
	CreatedAt  time.Time  `json:"created_at"`
	ExpiresAt  *time.Time `json:"expires_at"`
	LastUsedAt *time.Time `json:"last_used_at"`
	RevokedAt  *time.Time `json:"revoked_at"`
}

func toAPIKeyJSON(k store.APIKey) apiKeyJSON {
	return apiKeyJSON{ID: k.ID, Name: k.Name, Prefix: k.Prefix, Scope: k.Scope, CreatedBy: k.CreatedBy,
		CreatedAt: k.CreatedAt, ExpiresAt: k.ExpiresAt, LastUsedAt: k.LastUsedAt, RevokedAt: k.RevokedAt}
}

// listAPIKeys answers GET /orgs/{org}/apikeys (admins, signed in).
func (s *Server) listAPIKeys(w http.ResponseWriter, r *http.Request, req orgRequest) {
	keys, err := req.org.APIKeys(r.Context())
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	out := make([]apiKeyJSON, 0, len(keys))
	for _, k := range keys {
		out = append(out, toAPIKeyJSON(k))
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": out})
}

type createKeyRequest struct {
	Name  string `json:"name"`
	Scope string `json:"scope"`
	// ExpiresInDays: 0 for a key valid until revoked.
	ExpiresInDays int `json:"expires_in_days"`
}

// createAPIKey answers POST /orgs/{org}/apikeys (admins, signed in): 201
// with the key, shown this once; 403 plan_limit without the offer.
func (s *Server) createAPIKey(w http.ResponseWriter, r *http.Request, req orgRequest) {
	var body createKeyRequest
	if !decode(w, r, &body) {
		return
	}
	p, ok := s.planOf(w, r, req)
	if !ok {
		return
	}
	if !p.PublicAPI {
		planLimit(w, "API access is included in the Pro and custom plans")
		return
	}
	if body.ExpiresInDays < 0 || body.ExpiresInDays > 3650 {
		writeError(w, http.StatusBadRequest, "expires_in_days must be between 0 and 3650")
		return
	}
	var expires *time.Time
	if body.ExpiresInDays > 0 {
		t := s.cfg.Now().Add(time.Duration(body.ExpiresInDays) * 24 * time.Hour)
		expires = &t
	}
	k, secret, err := req.org.CreateAPIKey(r.Context(), body.Name, body.Scope, expires, actor(req))
	if errors.Is(err, store.ErrTooManyKeys) {
		writeErrorCode(w, http.StatusConflict, "too_many_keys", "revoke a key first: 20 active keys at most")
		return
	}
	if errors.Is(err, store.ErrBadKeyRequest) {
		writeError(w, http.StatusBadRequest, "a name (80 characters at most) and a scope, read or write, are required")
		return
	}
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"key": toAPIKeyJSON(k), "secret": secret})
}

// revokeAPIKey answers DELETE /orgs/{org}/apikeys/{key} (admins).
func (s *Server) revokeAPIKey(w http.ResponseWriter, r *http.Request, req orgRequest) {
	err := req.org.RevokeAPIKey(r.Context(), r.PathValue("key"), actor(req))
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
