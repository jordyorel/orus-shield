package api

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/jordyorel/orus-shield/engine/internal/dnsname"
	"github.com/jordyorel/orus-shield/engine/internal/store"
)

// maxSpec bounds an uploaded API description: requests are bounded at
// 1 MB (maxBodyBytes); a larger document is given by its URL instead.
const maxSpec = 900 << 10

type apiJSON struct {
	ID        string    `json:"id"`
	TargetID  string    `json:"target_id"`
	Name      string    `json:"name"`
	Kind      string    `json:"kind"` // openapi, graphql
	BaseURL   string    `json:"base_url"`
	SpecURL   string    `json:"spec_url,omitempty"`
	SpecSize  int       `json:"spec_size,omitempty"` // uploaded document, bytes
	CreatedAt time.Time `json:"created_at"`
	CreatedBy string    `json:"created_by"`
}

func toAPIJSON(a store.API) apiJSON {
	return apiJSON{ID: a.ID, TargetID: a.TargetID, Name: a.Name, Kind: a.Kind, BaseURL: a.BaseURL, SpecURL: a.SpecURL,
		SpecSize: len(a.Spec), CreatedAt: a.CreatedAt, CreatedBy: a.CreatedBy}
}

type createAPIRequest struct {
	Name    string `json:"name"`
	Kind    string `json:"kind"`
	BaseURL string `json:"base_url"`
	SpecURL string `json:"spec_url"`
	Spec    string `json:"spec"`
}

// inDomain checks that raw is an http(s) URL on domain or a name under it,
// without credentials or fragment, and returns it normalized. A declared
// API is scanned actively: it must belong to the verified target.
func inDomain(raw, domain string) (string, bool) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.User != nil || u.Fragment != "" || u.Host == "" {
		return "", false
	}
	host, err := dnsname.Normalize(u.Hostname())
	if err != nil || (host != domain && !strings.HasSuffix(host, "."+domain)) {
		return "", false
	}
	u.Scheme = strings.ToLower(u.Scheme)
	return u.String(), len(u.String()) <= 2000
}

// listAPIs answers GET /orgs/{org}/targets/{target}/apis.
func (s *Server) listAPIs(w http.ResponseWriter, r *http.Request, req orgRequest, t store.Target) {
	apis, err := req.org.ListAPIs(r.Context(), t.ID)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	out := make([]apiJSON, 0, len(apis))
	for _, a := range apis {
		out = append(out, toAPIJSON(a))
	}
	writeJSON(w, http.StatusOK, listOf(out))
}

// createAPI answers POST /orgs/{org}/targets/{target}/apis.
func (s *Server) createAPI(w http.ResponseWriter, r *http.Request, req orgRequest, t store.Target) {
	if t.Internal {
		writeError(w, http.StatusBadRequest, "not for an internal network: it is verified by its agent")
		return
	}
	var body createAPIRequest
	if !decode(w, r, &body) {
		return
	}
	n := store.NewAPI{Name: strings.TrimSpace(body.Name), Kind: body.Kind, Spec: body.Spec}
	switch {
	case n.Name == "" || len([]rune(n.Name)) > 100:
		writeError(w, http.StatusBadRequest, "name must be 1 to 100 characters")
		return
	case n.Kind != store.APIOpenAPI && n.Kind != store.APIGraphQL:
		writeError(w, http.StatusBadRequest, "kind must be openapi or graphql")
		return
	case len(body.Spec) > maxSpec:
		writeError(w, http.StatusBadRequest, "spec must be at most 900 KB: give a larger document by its spec_url")
		return
	}
	var ok bool
	if n.BaseURL, ok = inDomain(body.BaseURL, t.Domain); !ok {
		writeError(w, http.StatusBadRequest, "base_url must be an http(s) URL on "+t.Domain+" or a name under it")
		return
	}
	if body.SpecURL != "" {
		if n.SpecURL, ok = inDomain(body.SpecURL, t.Domain); !ok {
			writeError(w, http.StatusBadRequest, "spec_url must be an http(s) URL on "+t.Domain+" or a name under it")
			return
		}
	}
	if n.Kind == store.APIOpenAPI && n.SpecURL == "" && strings.TrimSpace(n.Spec) == "" {
		writeError(w, http.StatusBadRequest, "an OpenAPI API needs spec_url or spec")
		return
	}
	p, ok := s.planOf(w, r, req)
	if !ok {
		return
	}
	if !p.APIScans {
		planLimit(w, "the "+p.Name+" offer does not include API scans")
		return
	}
	a, err := req.org.CreateAPI(r.Context(), t.ID, n, actor(req))
	switch {
	case errors.Is(err, store.ErrExists):
		writeError(w, http.StatusConflict, "an API with this base URL is already declared")
		return
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "not found")
		return
	case err != nil:
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, toAPIJSON(a))
}

// deleteAPI answers DELETE /orgs/{org}/targets/{target}/apis/{api}.
func (s *Server) deleteAPI(w http.ResponseWriter, r *http.Request, req orgRequest, t store.Target) {
	err := req.org.DeleteAPI(r.Context(), t.ID, r.PathValue("api"), actor(req))
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
