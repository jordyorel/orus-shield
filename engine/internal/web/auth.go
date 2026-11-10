package web

import (
	"errors"
	"html/template"
	"net/http"
	"strconv"
	"strings"

	"github.com/jordyorel/orus-shield/engine/internal/account"
	"github.com/jordyorel/orus-shield/engine/internal/password"
	"github.com/jordyorel/orus-shield/engine/internal/store"
	"github.com/jordyorel/orus-shield/engine/internal/totp"
)

// Messages shown to the user. Every wrong password gets the same one,
// whatever the reason: the page never tells whether an account exists.
//
//nolint:gosec // G101: user-facing messages about passwords, not credentials
const (
	msgBadCredentials = "Adresse e-mail ou mot de passe incorrect."
	msgBadPassword    = "Mot de passe incorrect."
	msgRateLimited    = "Trop de tentatives échouées. Réessayez dans 15 minutes."
	msgBadCode        = "Code incorrect. Vérifiez l'heure de votre téléphone et saisissez le code affiché maintenant."
	msgBadRecovery    = "Code incorrect, ou déjà utilisé."
	msgLoginExpired   = "La vérification a expiré. Saisissez à nouveau votre mot de passe."
	msgSetupToken     = "Ce code d'activation est invalide, expiré ou déjà utilisé. Demandez-en un nouveau à votre administrateur."
	msgPasswordShort  = "Le mot de passe doit contenir au moins 12 caractères."
	msgPasswordLong   = "Ce mot de passe est trop long."
	msgPasswordMatch  = "Les deux mots de passe ne correspondent pas."
	msgAdminNeedsMFA  = "Votre rôle d'administrateur exige la double authentification. Activez-la pour accéder à votre organisation."
)

// Notices after a redirect, keyed by the ?ok= parameter. The page shows
// one of these fixed texts, never text from the URL.
//
//nolint:gosec // G101: user-facing messages, not credentials
var notices = map[string]string{
	"password": "Votre mot de passe est enregistré. Vous pouvez vous connecter.",
	"logout":   "Vous êtes déconnecté.",
}

type loginData struct {
	Email string
}

type mfaLoginData struct {
	MFAToken string
}

type setupPasswordData struct {
	Token     string
	MinLength int
}

type enrolData struct {
	Secret string
	// URI is the otpauth:// link. html/template only lets http, https and
	// mailto URLs through; template.URL marks this one as trusted, which
	// is safe because we build it (totp.URI), never the user.
	URI template.URL
}

type codesData struct {
	Codes []string
}

type noOrgData struct {
	Email string
}

// rateLimited answers 429 on page, with the retry delay for clients.
func (s *Server) rateLimited(w http.ResponseWriter, r *http.Request, page string, data any) {
	w.Header().Set("Retry-After", strconv.Itoa(int(account.LoginWindow.Seconds())))
	s.render(w, r, http.StatusTooManyRequests, page, view{Error: msgRateLimited, Data: data})
}

func (s *Server) loginPage(w http.ResponseWriter, r *http.Request) {
	if _, _, err := s.acct.SessionFrom(r); err == nil {
		redirect(w, r, "/")
		return
	}
	s.render(w, r, http.StatusOK, "login", view{Notice: notices[r.URL.Query().Get("ok")], Data: loginData{}})
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	email := r.PostFormValue("email")
	res, err := s.acct.Login(r.Context(), email, r.PostFormValue("password"), account.ClientFrom(r))
	data := loginData{Email: email}
	switch {
	case errors.Is(err, account.ErrBadCredentials):
		s.render(w, r, http.StatusUnauthorized, "login", view{Error: msgBadCredentials, Data: data})
		return
	case errors.Is(err, account.ErrRateLimited):
		s.rateLimited(w, r, "login", data)
		return
	case err != nil:
		s.internalError(w, r, err)
		return
	}
	if res.MFAToken != "" {
		// The token travels in a hidden field of the next form, never in
		// the URL (it would land in the history and in proxy logs).
		s.render(w, r, http.StatusOK, "login_mfa", view{Data: mfaLoginData{MFAToken: res.MFAToken}})
		return
	}
	account.SetSessionCookie(w, res.Session.Token, res.Session.Expires)
	redirect(w, r, "/")
}

func (s *Server) loginMFA(w http.ResponseWriter, r *http.Request) {
	token := r.PostFormValue("mfa_token")
	code := r.PostFormValue("code")
	ns, err := s.acct.LoginMFA(r.Context(), token, code, account.ClientFrom(r))
	switch {
	case errors.Is(err, account.ErrBadCode):
		msg := msgBadCode
		if len(strings.TrimSpace(code)) != totp.Digits {
			msg = msgBadRecovery
		}
		s.render(w, r, http.StatusUnauthorized, "login_mfa", view{Error: msg, Data: mfaLoginData{MFAToken: token}})
		return
	case errors.Is(err, account.ErrChallengeExpired):
		s.render(w, r, http.StatusUnauthorized, "login", view{Error: msgLoginExpired, Data: loginData{}})
		return
	case errors.Is(err, account.ErrRateLimited):
		s.rateLimited(w, r, "login", loginData{})
		return
	case err != nil:
		s.internalError(w, r, err)
		return
	}
	account.SetSessionCookie(w, ns.Token, ns.Expires)
	redirect(w, r, "/")
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	sess, token, err := s.acct.SessionFrom(r)
	switch {
	case errors.Is(err, account.ErrNoSession):
		account.ClearSessionCookie(w)
		redirect(w, r, "/login")
		return
	case err != nil:
		s.internalError(w, r, err)
		return
	}
	if err := s.acct.Logout(r.Context(), sess, token, account.ClientFrom(r)); err != nil {
		s.internalError(w, r, err)
		return
	}
	account.ClearSessionCookie(w)
	redirect(w, r, "/login?ok=logout")
}

func (s *Server) setupPasswordPage(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, http.StatusOK, "setup_password", view{Data: setupPasswordData{MinLength: password.MinLength}})
}

func (s *Server) setupPassword(w http.ResponseWriter, r *http.Request) {
	token := r.PostFormValue("token")
	pw := r.PostFormValue("password")
	data := setupPasswordData{Token: token, MinLength: password.MinLength}
	fail := func(msg string) {
		s.render(w, r, http.StatusBadRequest, "setup_password", view{Error: msg, Data: data})
	}
	if pw != r.PostFormValue("confirm") {
		fail(msgPasswordMatch)
		return
	}
	err := s.acct.SetupPassword(r.Context(), token, pw, account.ClientFrom(r))
	switch {
	case errors.Is(err, password.ErrTooShort):
		fail(msgPasswordShort)
	case errors.Is(err, password.ErrTooLong):
		fail(msgPasswordLong)
	case errors.Is(err, account.ErrInvalidSetupToken):
		data.Token = "" // useless: make the user paste a new one
		fail(msgSetupToken)
	case err != nil:
		s.internalError(w, r, err)
	default:
		redirect(w, r, "/login?ok=password")
	}
}

// requireSession returns the caller's session, or sends them to the login
// page and returns false.
func (s *Server) requireSession(w http.ResponseWriter, r *http.Request) (store.Session, string, bool) {
	sess, token, err := s.acct.SessionFrom(r)
	switch {
	case errors.Is(err, account.ErrNoSession):
		redirect(w, r, "/login")
		return store.Session{}, "", false
	case err != nil:
		s.internalError(w, r, err)
		return store.Session{}, "", false
	}
	return sess, token, true
}

func (s *Server) mfaSetupPage(w http.ResponseWriter, r *http.Request) {
	sess, _, ok := s.requireSession(w, r)
	if !ok {
		return
	}
	if sess.MFAEnabled {
		redirect(w, r, "/")
		return
	}
	v := view{}
	if r.URL.Query().Get("reason") == "admin" {
		v.Warning = msgAdminNeedsMFA
	}
	s.render(w, r, http.StatusOK, "mfa_setup", v)
}

func (s *Server) mfaSetup(w http.ResponseWriter, r *http.Request) {
	sess, _, ok := s.requireSession(w, r)
	if !ok {
		return
	}
	en, err := s.acct.BeginMFA(r.Context(), sess, r.PostFormValue("password"), account.ClientFrom(r))
	switch {
	case errors.Is(err, account.ErrBadCredentials):
		s.render(w, r, http.StatusForbidden, "mfa_setup", view{Error: msgBadPassword})
		return
	case errors.Is(err, account.ErrRateLimited):
		s.rateLimited(w, r, "mfa_setup", nil)
		return
	case errors.Is(err, account.ErrMFAEnabled):
		redirect(w, r, "/")
		return
	case err != nil:
		s.internalError(w, r, err)
		return
	}
	// The secret is shown in this response only. A wrong first code does
	// not show it again: seeing it would need the password once more,
	// otherwise a stolen session could read a pending secret.
	s.render(w, r, http.StatusOK, "mfa_enrol", view{Wide: true, Data: enrolData{
		Secret: en.Secret, URI: template.URL(en.URI), //nolint:gosec // G203: we built this otpauth URI, see enrolData.URI
	}})
}

func (s *Server) mfaConfirm(w http.ResponseWriter, r *http.Request) {
	sess, token, ok := s.requireSession(w, r)
	if !ok {
		return
	}
	codes, err := s.acct.ConfirmMFA(r.Context(), sess, token, r.PostFormValue("code"), account.ClientFrom(r))
	switch {
	case errors.Is(err, account.ErrBadCode):
		s.render(w, r, http.StatusBadRequest, "mfa_enrol", view{Wide: true, Error: msgBadCode, Data: enrolData{}})
		return
	case errors.Is(err, account.ErrNoMFASetup):
		redirect(w, r, "/mfa/setup")
		return
	case errors.Is(err, account.ErrMFAEnabled):
		redirect(w, r, "/")
		return
	case err != nil:
		s.internalError(w, r, err)
		return
	}
	s.render(w, r, http.StatusOK, "mfa_codes", view{Wide: true, Data: codesData{Codes: codes}})
}
