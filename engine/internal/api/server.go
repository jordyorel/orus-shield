// Package api is the HTTP API of the dashboard (roadmap step 7.6).
//
// Isolation between customers is enforced by types: handlers of
// organization routes receive a *store.Org for the caller's organization,
// never the cross-organization *store.Store. The server itself holds only
// the authentication handle and a function that builds Org handles.
//
// Every route is JSON under /api/v1. Requests that change state are
// protected against cross-site request forgery by the standard library's
// http.CrossOriginProtection, on top of SameSite session cookies.
package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"runtime/debug"
	"strings"
	"time"

	"github.com/jordyorel/orus-shield/engine/internal/account"
	"github.com/jordyorel/orus-shield/engine/internal/mailer"
	"github.com/jordyorel/orus-shield/engine/internal/module"
	"github.com/jordyorel/orus-shield/engine/internal/resolver"
	"github.com/jordyorel/orus-shield/engine/internal/store"
)

// Config tunes the server. Zero values get the defaults below.
type Config struct {
	// SessionIdle closes a session unused for this long.
	SessionIdle time.Duration
	// SessionMax closes a session this long after login, used or not.
	SessionMax time.Duration
	// TrustedOrigins are other origins allowed to send state-changing
	// requests (a dashboard served on another port in development).
	TrustedOrigins []string
	// Now is the clock; tests replace it.
	Now func() time.Time
	// DNS is the resolver used for ownership verification; nil means the
	// system resolver. Tests use a fake one (rule 6).
	DNS resolver.Resolver
	// Modules are the module IDs a scan may request; a scan without a list
	// runs them all.
	Modules []string
	// Catalog describes the modules of Modules (name, passive or active)
	// for GET /orgs/{org}/modules. Optional: without it the route lists
	// the IDs only.
	Catalog []module.Info
	// MFAKey encrypts TOTP secrets in the database (seal.KeyLen bytes,
	// from ORUS_MFA_KEY). Required.
	MFAKey []byte
	// Mailer sends account emails; nil: not configured.
	Mailer mailer.Sender
	// PublicURL is the dashboard's address, for links in emails.
	PublicURL string
	// SignupClosed hides self-service signup (accounts by invitation only).
	SignupClosed bool
}

const (
	// maxBodyBytes bounds request bodies: every request here is small JSON.
	maxBodyBytes = 1 << 20
)

// Server is the API. Build it with New.
type Server struct {
	// acct runs the authentication flows (package account).
	acct *account.Service
	// org returns the handle of one organization. It is the only way
	// handlers reach customer data.
	org func(orgID string) (*store.Org, error)
	cfg Config
	log *slog.Logger
}

// New returns the API server on st. It keeps only st's authentication
// handle (inside the account service) and its Org constructor.
func New(st *store.Store, cfg Config, log *slog.Logger) (*Server, error) {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.DNS == nil {
		cfg.DNS = resolver.NewSystem()
	}
	if len(cfg.Modules) == 0 {
		return nil, errors.New("api: no modules configured")
	}
	acct, err := account.New(st.Auth(), account.Config{
		SessionIdle: cfg.SessionIdle, SessionMax: cfg.SessionMax, Now: cfg.Now, MFAKey: cfg.MFAKey,
		Mailer: cfg.Mailer, PublicURL: cfg.PublicURL, Log: log,
	})
	if err != nil {
		return nil, fmt.Errorf("api: %w", err)
	}
	return &Server{acct: acct, org: st.Org, cfg: cfg, log: log}, nil
}

// Handler returns the API's HTTP handler with every protection applied.
func (s *Server) Handler() (http.Handler, error) {
	mux := http.NewServeMux()
	s.routes(mux)

	csrf := http.NewCrossOriginProtection()
	for _, o := range s.cfg.TrustedOrigins {
		if err := csrf.AddTrustedOrigin(o); err != nil {
			return nil, fmt.Errorf("trusted origin %q: %w", o, err)
		}
	}
	csrf.SetDenyHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeError(w, http.StatusForbidden, "cross-origin request refused")
	}))
	return s.recoverPanics(securityHeaders(limitBody(csrf.Handler(mux)))), nil
}

func (s *Server) routes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v1/auth/login", s.login)
	mux.HandleFunc("POST /api/v1/auth/logout", s.withSession(s.logout))
	mux.HandleFunc("GET /api/v1/auth/me", s.withSession(s.me))
	mux.HandleFunc("PATCH /api/v1/auth/me", s.withSession(s.updateMe))
	mux.HandleFunc("GET /api/v1/auth/sessions", s.withSession(s.listSessions))
	mux.HandleFunc("DELETE /api/v1/auth/sessions/{session}", s.withSession(s.endSession))
	mux.HandleFunc("GET /api/v1/auth/activity", s.withSession(s.authActivity))
	mux.HandleFunc("POST /api/v1/auth/setup-password", s.setupPassword)
	mux.HandleFunc("POST /api/v1/auth/forgot-password", s.forgotPassword)
	if !s.cfg.SignupClosed {
		mux.HandleFunc("POST /api/v1/auth/signup", s.signup)
		mux.HandleFunc("POST /api/v1/auth/signup/complete", s.completeSignup)
	}
	mux.HandleFunc("POST /api/v1/auth/login/mfa", s.loginMFA)
	mux.HandleFunc("POST /api/v1/auth/mfa/setup", s.withSession(s.mfaSetup))
	mux.HandleFunc("POST /api/v1/auth/mfa/confirm", s.withSession(s.mfaConfirm))
	mux.HandleFunc("POST /api/v1/auth/mfa/disable", s.withSession(s.mfaDisable))
	// The offers, for the public pricing page: no session needed.
	mux.HandleFunc("GET /api/v1/plans", s.listPlans)
	s.orgRoutes(mux)
	s.teamRoutes(mux)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		writeError(w, http.StatusNotFound, "not found")
	})
}

// securityHeaders sets headers for a JSON API that is never cached and
// never rendered as a page.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Cache-Control", "no-store")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		next.ServeHTTP(w, r)
	})
}

func limitBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
		next.ServeHTTP(w, r)
	})
}

// recoverPanics turns a panic in a handler into a 500, logged with its
// stack but without request data.
func (s *Server) recoverPanics(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if v := recover(); v != nil {
				if v == http.ErrAbortHandler { //nolint:errorlint // sentinel value compared as net/http does
					panic(v)
				}
				s.log.Error("handler panicked", "method", r.Method, "path", r.URL.Path, "panic", fmt.Sprint(v), "stack", string(debug.Stack()))
				writeError(w, http.StatusInternalServerError, "internal error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// ---- JSON helpers ----------------------------------------------------------

// errorBody is the shape of every error response. Messages are written for
// the user and never include internal details.
type errorBody struct {
	Error string `json:"error"`
	// Code is a stable identifier for errors the dashboard reacts to
	// (mfa_required: show the enrolment screen; login_expired: the MFA
	// login token is gone, sign in again from the password).
	Code string `json:"code,omitempty"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v) // the client went away: nothing to do
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, errorBody{Error: msg})
}

func writeErrorCode(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, errorBody{Error: msg, Code: code})
}

// internalError logs err and answers 500 without details.
func (s *Server) internalError(w http.ResponseWriter, r *http.Request, err error) {
	s.log.Error("request failed", "method", r.Method, "path", r.URL.Path, "err", err)
	writeError(w, http.StatusInternalServerError, "internal error")
}

// decode reads exactly one JSON object into v, rejecting unknown fields:
// a typo in a field name is an error, not a silently ignored value.
func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		writeError(w, http.StatusUnsupportedMediaType, "body must be application/json")
		return false
	}
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			writeError(w, http.StatusRequestEntityTooLarge, "body too large")
		} else {
			writeError(w, http.StatusBadRequest, "invalid JSON body")
		}
		return false
	}
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		writeError(w, http.StatusBadRequest, "body must contain a single JSON object")
		return false
	}
	return true
}
