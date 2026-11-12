package api

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/jordyorel/orus-shield/engine/internal/store"
)

type credentialJSON struct {
	Kind          string    `json:"kind"` // header, form
	HeaderName    string    `json:"header_name,omitempty"`
	LoginURL      string    `json:"login_url,omitempty"`
	Username      string    `json:"username,omitempty"`
	UsernameField string    `json:"username_field,omitempty"`
	PasswordField string    `json:"password_field,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
	CreatedBy     string    `json:"created_by"`
	// The secret is never sent back.
}

type setCredentialRequest struct {
	Kind          string `json:"kind"`
	HeaderName    string `json:"header_name"`
	HeaderValue   string `json:"header_value"`
	LoginURL      string `json:"login_url"`
	Username      string `json:"username"`
	Password      string `json:"password"`
	UsernameField string `json:"username_field"`
	PasswordField string `json:"password_field"`
	// Consent: the admin confirms it is a test account, allowed to be used
	// by the scans, and not an administrator's.
	Consent bool `json:"consent"`
}

// forbiddenHeaders are headers a test account may not set: the transport's
// own, or ones that would change where requests go.
var forbiddenHeaders = []string{"host", "content-length", "transfer-encoding", "connection", "proxy-authorization", "upgrade", "te"}

// validToken reports whether name is an HTTP header name (RFC 9110 token).
func validToken(name string) bool {
	if name == "" || len(name) > 100 {
		return false
	}
	for _, r := range name {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("!#$%&'*+-.^_`|~", r)) {
			return false
		}
	}
	return true
}

// cleanValue rejects control characters (CR and LF would let a value add
// headers of its own) and bounds the length.
func cleanValue(v string, max int) bool {
	if v == "" || len(v) > max {
		return false
	}
	for _, r := range v {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

func toCredentialJSON(c *store.Credential) credentialJSON {
	return credentialJSON{Kind: c.Kind, HeaderName: c.HeaderName, LoginURL: c.LoginURL, Username: c.Username,
		UsernameField: c.UsernameField, PasswordField: c.PasswordField, CreatedAt: c.CreatedAt, CreatedBy: c.CreatedBy}
}

// getCredential answers GET /orgs/{org}/targets/{target}/credential (admins):
// the test account without its secret; 404 when there is none.
func (s *Server) getCredential(w http.ResponseWriter, r *http.Request, req orgRequest, t store.Target) {
	c, err := req.org.Credential(r.Context(), t.ID)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if c == nil {
		writeError(w, http.StatusNotFound, "no test account")
		return
	}
	writeJSON(w, http.StatusOK, toCredentialJSON(c))
}

// setCredential answers PUT /orgs/{org}/targets/{target}/credential.
func (s *Server) setCredential(w http.ResponseWriter, r *http.Request, req orgRequest, t store.Target) {
	if s.creds == nil {
		writeError(w, http.StatusServiceUnavailable, "test accounts are not configured on this server (ORUS_CREDENTIALS_KEY)")
		return
	}
	var body setCredentialRequest
	if !decode(w, r, &body) {
		return
	}
	if !body.Consent {
		writeErrorCode(w, http.StatusBadRequest, "consent_required", "confirm that this is a test account the scans may use")
		return
	}
	c := store.Credential{TargetID: t.ID, Kind: body.Kind}
	var secret string
	switch body.Kind {
	case store.CredentialHeader:
		name := strings.TrimSpace(body.HeaderName)
		if !validToken(name) || containsFold(forbiddenHeaders, name) {
			writeError(w, http.StatusBadRequest, "header_name must be an HTTP header name such as Authorization, X-API-Key or Cookie")
			return
		}
		if !cleanValue(body.HeaderValue, 4096) {
			writeError(w, http.StatusBadRequest, "header_value must be 1 to 4096 characters, on one line")
			return
		}
		c.HeaderName, secret = name, body.HeaderValue
	case store.CredentialForm:
		login, ok := inDomain(body.LoginURL, t.Domain)
		if !ok {
			writeError(w, http.StatusBadRequest, "login_url must be an http(s) URL on "+t.Domain+" or a name under it")
			return
		}
		if !cleanValue(body.Username, 200) || !cleanValue(body.Password, 1000) {
			writeError(w, http.StatusBadRequest, "username (200 characters at most) and password (1000) are required, on one line")
			return
		}
		for _, f := range []string{body.UsernameField, body.PasswordField} {
			if f != "" && !validToken(f) {
				writeError(w, http.StatusBadRequest, "username_field and password_field must be form field names")
				return
			}
		}
		c.LoginURL, c.Username, c.UsernameField, c.PasswordField, secret = login, body.Username, body.UsernameField, body.PasswordField, body.Password
	default:
		writeError(w, http.StatusBadRequest, "kind must be header or form")
		return
	}
	p, ok := s.planOf(w, r, req)
	if !ok {
		return
	}
	if !p.AuthScans {
		planLimit(w, "the "+p.Name+" offer does not include authenticated scans")
		return
	}
	sealed, err := s.creds.Seal([]byte(secret), store.CredentialOwner(t.ID))
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if err := req.org.SetCredential(r.Context(), c, sealed, actor(req)); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "not found")
			return
		}
		s.internalError(w, r, err)
		return
	}
	saved, err := req.org.Credential(r.Context(), t.ID)
	if err != nil || saved == nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, toCredentialJSON(saved))
}

// deleteCredential answers DELETE /orgs/{org}/targets/{target}/credential.
func (s *Server) deleteCredential(w http.ResponseWriter, r *http.Request, req orgRequest, t store.Target) {
	err := req.org.DeleteCredential(r.Context(), t.ID, actor(req))
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "no test account")
		return
	}
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func containsFold(list []string, s string) bool {
	for _, x := range list {
		if strings.EqualFold(x, s) {
			return true
		}
	}
	return false
}
