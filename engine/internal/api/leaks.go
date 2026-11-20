package api

import (
	"errors"
	"net/http"
	"strings"

	"github.com/jordyorel/orus-shield/engine/internal/modules/leaks"
	"github.com/jordyorel/orus-shield/engine/internal/store"
)

// Addresses declared on a domain for data leak monitoring (leaks module,
// XposedOrNot). The members of the organization on the domain are checked
// without being declared.

type leakAddressJSON struct {
	ID        string `json:"id"`
	Email     string `json:"email"`
	CreatedBy string `json:"created_by"`
	CreatedAt string `json:"created_at"`
}

func toLeakAddressJSON(a store.LeakAddress) leakAddressJSON {
	return leakAddressJSON{ID: a.ID, Email: a.Email, CreatedBy: a.CreatedBy, CreatedAt: a.CreatedAt.UTC().Format("2006-01-02T15:04:05Z")}
}

// listLeakAddresses answers GET /orgs/{org}/targets/{target}/leak-addresses.
func (s *Server) listLeakAddresses(w http.ResponseWriter, r *http.Request, req orgRequest, t store.Target) {
	list, err := req.org.LeakAddresses(r.Context(), t.ID)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	out := make([]leakAddressJSON, 0, len(list))
	for _, a := range list {
		out = append(out, toLeakAddressJSON(a))
	}
	writeJSON(w, http.StatusOK, listOf(out))
}

// addLeakAddress answers POST /orgs/{org}/targets/{target}/leak-addresses
// with {"email"}: an address on the domain or under it.
func (s *Server) addLeakAddress(w http.ResponseWriter, r *http.Request, req orgRequest, t store.Target) {
	if t.Internal {
		writeError(w, http.StatusBadRequest, "not for an internal network")
		return
	}
	var body struct {
		Email string `json:"email"`
	}
	if !decode(w, r, &body) {
		return
	}
	addrs := leaks.Addresses([]string{body.Email}, strings.ToLower(t.Domain))
	if len(addrs) != 1 {
		writeErrorCode(w, http.StatusBadRequest, "bad_email", "the address must be on "+t.Domain+" or a name under it")
		return
	}
	a, err := req.org.AddLeakAddress(r.Context(), t.ID, addrs[0], actor(req))
	switch {
	case errors.Is(err, store.ErrExists):
		writeErrorCode(w, http.StatusConflict, "exists", "this address is already declared")
		return
	case errors.Is(err, store.ErrTooManyLeakAddresses):
		writeErrorCode(w, http.StatusConflict, "too_many_addresses", "15 addresses at most per domain: remove one first")
		return
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "not found")
		return
	case err != nil:
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, toLeakAddressJSON(a))
}

// removeLeakAddress answers DELETE /orgs/{org}/targets/{target}/leak-addresses/{address}.
func (s *Server) removeLeakAddress(w http.ResponseWriter, r *http.Request, req orgRequest, t store.Target) {
	err := req.org.RemoveLeakAddress(r.Context(), t.ID, r.PathValue("address"), actor(req))
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
