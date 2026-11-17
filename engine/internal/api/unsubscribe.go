package api

import (
	"errors"
	"net/http"

	"github.com/jordyorel/orus-shield/engine/internal/store"
)

type unsubscribeRequest struct {
	Token string `json:"token"`
}

// unsubscribe answers POST /unsubscribe: the page of a reminder's link
// posts its token, and the address it was sent to gets no more reminders.
// A POST, not the link itself: mail scanners that open links must not
// unsubscribe anyone.
func (s *Server) unsubscribe(w http.ResponseWriter, r *http.Request) {
	var req unsubscribeRequest
	if !decode(w, r, &req) {
		return
	}
	err := s.unsub.Unsubscribe(r.Context(), req.Token)
	if errors.Is(err, store.ErrUnknownToken) {
		writeError(w, http.StatusNotFound, "unknown or invalid link")
		return
	}
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
