package api

import (
	"errors"
	"net/http"
	"time"

	"github.com/jordyorel/orus-shield/engine/internal/account"
	"github.com/jordyorel/orus-shield/engine/internal/store"
)

type updateMeRequest struct {
	Name *string `json:"name"`
}

// updateMe changes the signed-in user's profile (Profil > Modifier) and
// answers the updated user.
func (s *Server) updateMe(w http.ResponseWriter, r *http.Request, sess store.Session, _ string) {
	var req updateMeRequest
	if !decode(w, r, &req) {
		return
	}
	if req.Name != nil {
		err := s.acct.SetName(r.Context(), sess, *req.Name, account.ClientFrom(r))
		if errors.Is(err, store.ErrInvalidName) {
			writeError(w, http.StatusBadRequest, "name must be at most 100 characters, without control characters")
			return
		}
		if err != nil {
			s.internalError(w, r, err)
			return
		}
	}
	s.writeMe(w, r, sess)
}

type sessionJSON struct {
	ID         string    `json:"id"`
	CreatedAt  time.Time `json:"created_at"`
	LastSeenAt time.Time `json:"last_seen_at"`
	IP         string    `json:"ip"`
	// UserAgent as the browser sent it: the dashboard derives "iPhone,
	// Safari" from it. Untrusted text, shown escaped.
	UserAgent string `json:"user_agent"`
	Current   bool   `json:"current"`
}

// listSessions answers the user's open sessions (Profil > Appareils connectés).
func (s *Server) listSessions(w http.ResponseWriter, r *http.Request, sess store.Session, token string) {
	ds, err := s.acct.Sessions(r.Context(), sess, token)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	out := make([]sessionJSON, 0, len(ds))
	for _, d := range ds {
		out = append(out, sessionJSON{ID: d.ID, CreatedAt: d.CreatedAt, LastSeenAt: d.LastSeenAt, IP: d.IP, UserAgent: d.UserAgent, Current: d.Current})
	}
	writeJSON(w, http.StatusOK, listOf(out))
}

// endSession signs out one of the user's other devices.
func (s *Server) endSession(w http.ResponseWriter, r *http.Request, sess store.Session, _ string) {
	err := s.acct.EndSession(r.Context(), sess, r.PathValue("session"), account.ClientFrom(r))
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

type authActivityJSON struct {
	At     time.Time `json:"at"`
	Action string    `json:"action"`
	IP     string    `json:"ip"`
}

// authActivity answers the user's latest security events (the recent
// activity of Profil): logins, password and MFA changes.
func (s *Server) authActivity(w http.ResponseWriter, r *http.Request, sess store.Session, _ string) {
	es, err := s.acct.Activity(r.Context(), sess, 10)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	out := make([]authActivityJSON, 0, len(es))
	for _, e := range es {
		out = append(out, authActivityJSON{At: e.At, Action: e.Action, IP: e.IP})
	}
	writeJSON(w, http.StatusOK, listOf(out))
}
