package api

import (
	"errors"
	"net/http"

	"github.com/jordyorel/orus-shield/engine/internal/account"
	"github.com/jordyorel/orus-shield/engine/internal/store"
)

// Team management (organization admins) and password change (any user).

// Audit actions for the organization's log.
const (
	actionMemberInvited     = "member.invited"
	actionMemberRoleChanged = "member.role_changed"
	actionMemberRemoved     = "member.removed"
)

func (s *Server) teamRoutes(mux *http.ServeMux) {
	base := "/api/v1/orgs/{org}"
	mux.HandleFunc("GET "+base+"/members", s.withOrg(store.RoleViewer, s.listMembers))
	mux.HandleFunc("POST "+base+"/members", s.withOrg(store.RoleAdmin, s.inviteMember))
	mux.HandleFunc("PUT "+base+"/members/{user}/role", s.withOrg(store.RoleAdmin, s.setMemberRole))
	mux.HandleFunc("DELETE "+base+"/members/{user}", s.withOrg(store.RoleAdmin, s.removeMember))
	mux.HandleFunc("POST "+base+"/members/{user}/setup-token", s.withOrg(store.RoleAdmin, s.reissueSetupToken))
	mux.HandleFunc("POST /api/v1/auth/password", s.withSession(s.changePassword))
}

type memberJSON struct {
	UserID     string `json:"user_id"`
	Email      string `json:"email"`
	Role       string `json:"role"`
	Activated  bool   `json:"activated"` // password set
	MFAEnabled bool   `json:"mfa_enabled"`
}

func toMemberJSON(m store.Member) memberJSON {
	return memberJSON{UserID: m.UserID, Email: m.Email, Role: m.Role, Activated: m.Activated, MFAEnabled: m.MFAEnabled}
}

func (s *Server) listMembers(w http.ResponseWriter, r *http.Request, req orgRequest) {
	ms, err := s.acct.Members(r.Context(), req.org.ID())
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	out := make([]memberJSON, 0, len(ms))
	for _, m := range ms {
		out = append(out, toMemberJSON(m))
	}
	writeJSON(w, http.StatusOK, listOf(out))
}

type inviteRequest struct {
	Email string `json:"email"`
	Role  string `json:"role"`
}

type invitationJSON struct {
	Member memberJSON `json:"member"`
	// SetupToken is shown once to the admin. The invitee also gets it by
	// email (Emailed); without mail, the admin passes it on over a trusted
	// channel. Empty when the account was already activated.
	SetupToken string `json:"setup_token,omitempty"`
	// Emailed: an email was sent to the invitee (activation link, or a
	// note that they have access).
	Emailed bool `json:"emailed"`
}

func (s *Server) inviteMember(w http.ResponseWriter, r *http.Request, req orgRequest) {
	var body inviteRequest
	if !decode(w, r, &body) {
		return
	}
	if body.Role != store.RoleAdmin && body.Role != store.RoleViewer {
		writeError(w, http.StatusBadRequest, "role must be admin or viewer")
		return
	}
	if _, err := store.NormalizeEmail(body.Email); err != nil {
		writeError(w, http.StatusBadRequest, "invalid email address")
		return
	}
	inv, emailed, err := s.acct.Invite(r.Context(), req.org.ID(), body.Email, body.Role, req.sess)
	switch {
	case errors.Is(err, account.ErrMemberExists):
		writeError(w, http.StatusConflict, err.Error())
		return
	case err != nil:
		s.internalError(w, r, err)
		return
	}
	if !s.audit(w, r, req, actionMemberInvited, map[string]any{"user_id": inv.Member.UserID, "email": inv.Member.Email, "role": inv.Member.Role}) {
		return
	}
	writeJSON(w, http.StatusCreated, invitationJSON{Member: toMemberJSON(inv.Member), SetupToken: inv.Token, Emailed: emailed})
}

type roleRequest struct {
	Role string `json:"role"`
}

func (s *Server) setMemberRole(w http.ResponseWriter, r *http.Request, req orgRequest) {
	var body roleRequest
	if !decode(w, r, &body) {
		return
	}
	if body.Role != store.RoleAdmin && body.Role != store.RoleViewer {
		writeError(w, http.StatusBadRequest, "role must be admin or viewer")
		return
	}
	userID := r.PathValue("user")
	if !s.teamError(w, r, s.acct.SetMemberRole(r.Context(), req.org.ID(), userID, body.Role)) {
		return
	}
	if !s.audit(w, r, req, actionMemberRoleChanged, map[string]any{"user_id": userID, "role": body.Role}) {
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) removeMember(w http.ResponseWriter, r *http.Request, req orgRequest) {
	userID := r.PathValue("user")
	if !s.teamError(w, r, s.acct.RemoveMember(r.Context(), req.org.ID(), userID)) {
		return
	}
	if !s.audit(w, r, req, actionMemberRemoved, map[string]any{"user_id": userID}) {
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type setupTokenJSON struct {
	SetupToken string `json:"setup_token"`
	// Emailed: the new link was sent to the member.
	Emailed bool `json:"emailed"`
}

func (s *Server) reissueSetupToken(w http.ResponseWriter, r *http.Request, req orgRequest) {
	token, emailed, err := s.acct.ReissueSetupToken(r.Context(), req.org.ID(), r.PathValue("user"), req.sess)
	if errors.Is(err, account.ErrAlreadyActivated) {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	if !s.teamError(w, r, err) {
		return
	}
	writeJSON(w, http.StatusOK, setupTokenJSON{SetupToken: token, Emailed: emailed})
}

// teamError answers a team error; it returns true when err is nil.
func (s *Server) teamError(w http.ResponseWriter, r *http.Request, err error) bool {
	switch {
	case err == nil:
		return true
	case errors.Is(err, account.ErrNoMember):
		writeError(w, http.StatusNotFound, "not found")
	case errors.Is(err, account.ErrLastAdmin):
		writeErrorCode(w, http.StatusConflict, "last_admin", err.Error())
	default:
		s.internalError(w, r, err)
	}
	return false
}

// audit records a team change in the organization's audit log.
func (s *Server) audit(w http.ResponseWriter, r *http.Request, req orgRequest, action string, details map[string]any) bool {
	if err := req.org.AppendAudit(r.Context(), store.AuditEntry{Actor: actor(req), Action: action, Details: details}); err != nil {
		s.internalError(w, r, err)
		return false
	}
	return true
}

type changePasswordRequest struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

func (s *Server) changePassword(w http.ResponseWriter, r *http.Request, sess store.Session, token string) {
	var body changePasswordRequest
	if !decode(w, r, &body) {
		return
	}
	err := s.acct.ChangePassword(r.Context(), sess, token, body.CurrentPassword, body.NewPassword, account.ClientFrom(r))
	if err != nil {
		s.accountError(w, r, err, http.StatusForbidden)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
