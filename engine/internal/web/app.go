package web

import (
	"errors"
	"net/http"

	"github.com/jordyorel/orus-shield/engine/internal/account"
	"github.com/jordyorel/orus-shield/engine/internal/store"
)

// home sends a signed-in user to their first organization.
func (s *Server) home(w http.ResponseWriter, r *http.Request) {
	sess, _, ok := s.requireSession(w, r)
	if !ok {
		return
	}
	ms, err := s.acct.Memberships(r.Context(), sess.UserID)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if len(ms) == 0 {
		s.render(w, r, http.StatusOK, "no_org", view{Data: noOrgData{Email: sess.Email}})
		return
	}
	redirect(w, r, orgURL(ms[0].OrgID))
}

// orgRequest is what organization pages receive: the caller and the
// layout context. Pages that read customer data will also get the
// organization's *store.Org here, never the cross-organization store.
type orgRequest struct {
	sess store.Session
	app  *appView
}

type orgHandler func(w http.ResponseWriter, r *http.Request, req orgRequest)

// orgPage resolves {org} from the URL through account.Access, the same
// check as the API: a non-member gets 404, as if the organization did not
// exist; an admin without a second factor is sent to enrolment. nav is the
// sidebar entry to highlight.
func (s *Server) orgPage(nav string, h orgHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess, _, ok := s.requireSession(w, r)
		if !ok {
			return
		}
		orgID := r.PathValue("org")
		_, err := s.acct.Access(r.Context(), sess, orgID, store.RoleViewer)
		switch {
		case errors.Is(err, account.ErrNotMember):
			s.notFound(w, r)
			return
		case errors.Is(err, account.ErrMFARequired):
			redirect(w, r, "/mfa/setup?reason=admin")
			return
		case err != nil:
			s.internalError(w, r, err)
			return
		}
		ms, err := s.acct.Memberships(r.Context(), sess.UserID)
		if err != nil {
			s.internalError(w, r, err)
			return
		}
		app := &appView{Email: sess.Email, Orgs: ms, Nav: nav}
		for _, m := range ms {
			if m.OrgID == orgID {
				app.Org = m
			}
		}
		h(w, r, orgRequest{sess: sess, app: app})
	}
}

func (s *Server) overview(w http.ResponseWriter, r *http.Request, req orgRequest) {
	s.render(w, r, http.StatusOK, "overview", view{App: req.app})
}
