// Package web is the customer dashboard: HTML pages rendered on the server
// with html/template, served on the same origin as the JSON API.
//
// Pages work without JavaScript: navigation is links, actions are forms
// that post and redirect. The authentication rules are not here but in
// package account, shared with the API: this package only turns their
// typed errors into French messages.
//
// Protections, from the outside in:
//   - Content-Security-Policy without 'unsafe-inline': only our own
//     stylesheet, no script, forms may only post to us. Even if some text
//     escaped html/template, the browser would refuse to run it.
//   - html/template escapes every value for its context (HTML, attribute,
//     URL), so text from a scanned target or a user is never markup.
//   - http.CrossOriginProtection refuses state-changing requests from
//     other sites (CSRF), on top of SameSite session cookies.
//   - Pages are never cached (Cache-Control: no-store): they hold customer
//     data and one-time secrets.
package web

import (
	"bytes"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"net/url"
	"runtime/debug"
	"strings"

	"github.com/jordyorel/orus-shield/engine/internal/account"
	"github.com/jordyorel/orus-shield/engine/internal/store"
)

//go:embed templates static
var files embed.FS

// maxFormBytes bounds request bodies: every form here is a few fields.
const maxFormBytes = 64 << 10

// csp is the Content-Security-Policy of every page. No script-src: the
// pages have no JavaScript yet (default-src 'none' blocks all scripts).
const csp = "default-src 'none'; style-src 'self'; img-src 'self'; " +
	"form-action 'self'; base-uri 'none'; frame-ancestors 'none'"

// pageLayouts lists every page and the layout it renders in: "auth" for
// the centered sign-in card, "app" for the sidebar layout.
var pageLayouts = map[string]string{
	"login":          "auth",
	"login_mfa":      "auth",
	"setup_password": "auth",
	"mfa_setup":      "auth",
	"mfa_enrol":      "auth",
	"mfa_codes":      "auth",
	"no_org":         "auth",
	"error":          "auth",
	"overview":       "app",
}

// Server is the dashboard. Build it with New.
type Server struct {
	acct   *account.Service
	log    *slog.Logger
	pages  map[string]*template.Template
	assets map[string]asset
	urls   assetURLs
}

// asset is a static file kept in memory, with a hash of its content.
type asset struct {
	body        []byte
	contentType string
	version     string
}

// assetURLs are the URLs pages link to. The version in the query string
// changes with the content, so browsers may cache a URL forever: a new
// release links to a new URL.
type assetURLs struct {
	CSS  string
	Icon string
}

// New parses every template and loads the static files. A broken template
// fails here, at startup, not on a customer's request.
func New(acct *account.Service, log *slog.Logger) (*Server, error) {
	s := &Server{acct: acct, log: log, pages: map[string]*template.Template{}, assets: map[string]asset{}}
	funcs := template.FuncMap{
		"roleLabel": roleLabel,
		"initials":  initials,
		"groups":    groups,
	}
	for name, layout := range pageLayouts {
		t, err := template.New(name).Funcs(funcs).ParseFS(files,
			"templates/partials.html", "templates/layout_"+layout+".html", "templates/"+name+".html")
		if err != nil {
			return nil, fmt.Errorf("web: parse page %s: %w", name, err)
		}
		s.pages[name] = t
	}
	for name, ctype := range map[string]string{
		"app.css":     "text/css; charset=utf-8",
		"favicon.svg": "image/svg+xml",
	} {
		b, err := fs.ReadFile(files, "static/"+name)
		if err != nil {
			return nil, fmt.Errorf("web: static file %s: %w", name, err)
		}
		sum := sha256.Sum256(b)
		s.assets[name] = asset{body: b, contentType: ctype, version: hex.EncodeToString(sum[:6])}
	}
	s.urls = assetURLs{CSS: s.assetURL("app.css"), Icon: s.assetURL("favicon.svg")}
	return s, nil
}

func (s *Server) assetURL(name string) string {
	return "/static/" + name + "?v=" + s.assets[name].version
}

// Handler returns the dashboard's HTTP handler with every protection
// applied.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	s.routes(mux)

	csrf := http.NewCrossOriginProtection()
	csrf.SetDenyHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.errorPage(w, r, http.StatusForbidden, "Requête refusée",
			"Cette action venait d'un autre site et a été bloquée par sécurité. Recommencez depuis Orus Shield.")
	}))
	return s.recoverPanics(securityHeaders(limitBody(csrf.Handler(mux))))
}

func (s *Server) routes(mux *http.ServeMux) {
	mux.HandleFunc("GET /{$}", s.home)

	mux.HandleFunc("GET /login", s.loginPage)
	mux.HandleFunc("POST /login", s.login)
	mux.HandleFunc("POST /login/mfa", s.loginMFA)
	mux.HandleFunc("POST /logout", s.logout)
	mux.HandleFunc("GET /setup-password", s.setupPasswordPage)
	mux.HandleFunc("POST /setup-password", s.setupPassword)
	mux.HandleFunc("GET /mfa/setup", s.mfaSetupPage)
	mux.HandleFunc("POST /mfa/setup", s.mfaSetup)
	mux.HandleFunc("POST /mfa/confirm", s.mfaConfirm)
	// A reload or a bookmark of a form's target lands somewhere useful
	// instead of "405 method not allowed".
	mux.Handle("GET /login/mfa", http.RedirectHandler("/login", http.StatusSeeOther))
	mux.Handle("GET /logout", http.RedirectHandler("/", http.StatusSeeOther))
	mux.Handle("GET /mfa/confirm", http.RedirectHandler("/mfa/setup", http.StatusSeeOther))

	mux.HandleFunc("GET /orgs/{org}", s.orgPage("overview", s.overview))

	mux.HandleFunc("GET /static/{file}", s.static)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		s.notFound(w, r)
	})
}

// ---- Rendering --------------------------------------------------------------

// view is what every template receives.
type view struct {
	Assets assetURLs
	// Messages shown above the content; empty ones are not rendered.
	Error   string
	Warning string
	Notice  string
	// Wide makes the sign-in card wider (secrets, recovery codes).
	Wide bool
	// App is set for pages in the application layout.
	App *appView
	// Data is the page's own data.
	Data any
}

// appView is the context of the application layout: who is signed in and
// in which organization.
type appView struct {
	Email string
	Org   store.Membership
	Orgs  []store.Membership
	// Nav is the current section, highlighted in the sidebar.
	Nav string
}

// render writes page with status. The page is rendered into a buffer
// first: a template error gives a clean 500, never half a page.
func (s *Server) render(w http.ResponseWriter, r *http.Request, status int, page string, v view) {
	t, ok := s.pages[page]
	if !ok {
		s.internalError(w, r, fmt.Errorf("unknown page %q", page))
		return
	}
	v.Assets = s.urls
	var buf bytes.Buffer
	if err := t.ExecuteTemplate(&buf, "layout", v); err != nil {
		s.internalError(w, r, fmt.Errorf("render %s: %w", page, err))
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = buf.WriteTo(w) // the client went away: nothing to do
}

type errorData struct {
	Title   string
	Message string
}

func (s *Server) errorPage(w http.ResponseWriter, r *http.Request, status int, title, msg string) {
	s.render(w, r, status, "error", view{Data: errorData{Title: title, Message: msg}})
}

func (s *Server) notFound(w http.ResponseWriter, r *http.Request) {
	s.errorPage(w, r, http.StatusNotFound, "Page introuvable",
		"Cette page n'existe pas, ou vous n'y avez pas accès.")
}

// internalError logs err and answers 500 without details. It does not go
// through the templates: they may be what failed.
func (s *Server) internalError(w http.ResponseWriter, r *http.Request, err error) {
	s.log.Error("web request failed", "method", r.Method, "path", r.URL.Path, "err", err)
	http.Error(w, "Erreur interne. Réessayez dans quelques instants.", http.StatusInternalServerError)
}

// ---- Static files -----------------------------------------------------------

// static serves the embedded CSS and icon. A request with the current
// version may be cached for a year; any other is revalidated.
func (s *Server) static(w http.ResponseWriter, r *http.Request) {
	a, ok := s.assets[r.PathValue("file")]
	if !ok {
		s.notFound(w, r)
		return
	}
	h := w.Header()
	h.Set("Content-Type", a.contentType)
	if r.URL.Query().Get("v") == a.version {
		h.Set("Cache-Control", "public, max-age=31536000, immutable")
	} else {
		h.Set("Cache-Control", "no-cache")
	}
	_, _ = w.Write(a.body)
}

// ---- Middleware -------------------------------------------------------------

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", csp)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "same-origin")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		// Pages hold customer data and one-time secrets; static files
		// override this with their own caching.
		h.Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

func limitBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
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
				s.log.Error("web handler panicked", "method", r.Method, "path", r.URL.Path, "panic", fmt.Sprint(v), "stack", string(debug.Stack()))
				http.Error(w, "Erreur interne.", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// ---- Template functions -----------------------------------------------------

func roleLabel(role string) string {
	switch role {
	case store.RoleAdmin:
		return "Administrateur"
	case store.RoleViewer:
		return "Lecteur"
	}
	return role
}

// initials is the avatar text: the first letter of the email address.
func initials(email string) string {
	for _, r := range email {
		return strings.ToUpper(string(r))
	}
	return "?"
}

// groups splits a secret into groups of 4 characters, easier to copy by
// hand into an authenticator app.
func groups(s string) string {
	var b strings.Builder
	n := 0
	for _, r := range s {
		if n > 0 && n%4 == 0 {
			b.WriteByte(' ')
		}
		b.WriteRune(r)
		n++
	}
	return b.String()
}

// ---- Helpers ----------------------------------------------------------------

// redirect answers 303 See Other: after a form post, the browser loads the
// target with GET, so a reload never posts the form again.
func redirect(w http.ResponseWriter, r *http.Request, to string) {
	http.Redirect(w, r, to, http.StatusSeeOther)
}

// orgURL is the path of an organization's overview.
func orgURL(orgID string) string {
	return "/orgs/" + url.PathEscape(orgID)
}
