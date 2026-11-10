package api

import (
	"net/http"
	"testing"

	"github.com/jordyorel/orus-shield/engine/internal/store"
)

func TestTeamManagement(t *testing.T) {
	e := newEnv(t)
	a := e.tenant("A", "example.com")
	b := e.tenant("B", "example.org")
	base := "/api/v1/orgs/" + a.orgID

	var members list[memberJSON]
	e.do("GET", base+"/members", a.viewer, nil).json(t, &members)
	if len(members.Items) != 2 {
		t.Fatalf("members = %+v", members.Items)
	}

	// An admin invites: the setup token comes back once.
	r := e.do("POST", base+"/members", a.session, inviteRequest{Email: "new@example.com", Role: store.RoleViewer})
	var inv invitationJSON
	r.json(t, &inv)
	if r.status != http.StatusCreated || inv.SetupToken == "" || inv.Member.Activated {
		t.Fatalf("invite = %d %s", r.status, r.body)
	}
	if r := e.do("POST", base+"/members", a.session, inviteRequest{Email: "new@example.com", Role: store.RoleViewer}); r.status != http.StatusConflict {
		t.Errorf("invite twice = %d, want 409", r.status)
	}
	for _, bad := range []inviteRequest{{Email: "not an email", Role: "viewer"}, {Email: "x@example.com", Role: "owner"}} {
		if r := e.do("POST", base+"/members", a.session, bad); r.status != http.StatusBadRequest {
			t.Errorf("invite %+v = %d, want 400", bad, r.status)
		}
	}
	// The invitee activates the account with the token and signs in.
	if r := e.do("POST", "/api/v1/auth/setup-password", "", setupPasswordRequest{Token: inv.SetupToken, Password: testPassword}); r.status != http.StatusNoContent {
		t.Fatalf("setup = %d %s", r.status, r.body)
	}
	e.login("new@example.com")

	// Viewers read the team but do not change it; other organizations do not see it.
	if r := e.do("POST", base+"/members", a.viewer, inviteRequest{Email: "y@example.com", Role: "viewer"}); r.status != http.StatusForbidden {
		t.Errorf("viewer invite = %d, want 403", r.status)
	}
	if r := e.do("GET", base+"/members", b.session, nil); r.status != http.StatusNotFound {
		t.Errorf("other organization's members = %d, want 404", r.status)
	}
	// B's admin cannot remove A's member through B's URL.
	if r := e.do("DELETE", "/api/v1/orgs/"+b.orgID+"/members/"+inv.Member.UserID, b.session, nil); r.status != http.StatusNotFound {
		t.Errorf("cross-organization removal = %d, want 404", r.status)
	}

	// Roles: the last admin stays.
	var adminID string
	e.do("GET", base+"/members", a.session, nil).json(t, &members)
	for _, m := range members.Items {
		if m.Role == store.RoleAdmin {
			adminID = m.UserID
		}
	}
	var body errorBody
	r = e.do("PUT", base+"/members/"+adminID+"/role", a.session, roleRequest{Role: store.RoleViewer})
	if r.json(t, &body); r.status != http.StatusConflict || body.Code != "last_admin" {
		t.Errorf("demote last admin = %d %+v", r.status, body)
	}
	if r := e.do("PUT", base+"/members/"+inv.Member.UserID+"/role", a.session, roleRequest{Role: store.RoleAdmin}); r.status != http.StatusNoContent {
		t.Errorf("promote = %d %s", r.status, r.body)
	}
	if r := e.do("POST", base+"/members/"+inv.Member.UserID+"/setup-token", a.session, nil); r.status != http.StatusConflict {
		t.Errorf("setup token for an activated account = %d, want 409", r.status)
	}
	if r := e.do("DELETE", base+"/members/"+inv.Member.UserID, a.session, nil); r.status != http.StatusNoContent {
		t.Errorf("remove = %d", r.status)
	}

	// Every change is in the organization's audit log.
	var audit list[auditEntryJSON]
	e.do("GET", base+"/audit", a.session, nil).json(t, &audit)
	seen := map[string]bool{}
	for _, entry := range audit.Items {
		seen[entry.Action] = true
	}
	for _, want := range []string{actionMemberInvited, actionMemberRoleChanged, actionMemberRemoved} {
		if !seen[want] {
			t.Errorf("audit log lacks %s: %+v", want, audit.Items)
		}
	}
}

func TestChangePasswordRoute(t *testing.T) {
	e := newEnv(t)
	orgID := e.org("Acme")
	e.user("alice@example.com", orgID, store.RoleViewer)
	session := e.login("alice@example.com")
	other := e.login("alice@example.com")

	if r := e.do("POST", "/api/v1/auth/password", session, changePasswordRequest{CurrentPassword: "wrong password!!", NewPassword: "another long passphrase"}); r.status != http.StatusForbidden {
		t.Errorf("wrong current password = %d, want 403", r.status)
	}
	if r := e.do("POST", "/api/v1/auth/password", session, changePasswordRequest{CurrentPassword: testPassword, NewPassword: "short"}); r.status != http.StatusBadRequest {
		t.Errorf("weak new password = %d, want 400", r.status)
	}
	if r := e.do("POST", "/api/v1/auth/password", session, changePasswordRequest{CurrentPassword: testPassword, NewPassword: "another long passphrase"}); r.status != http.StatusNoContent {
		t.Fatalf("change = %d %s", r.status, r.body)
	}
	if r := e.do("GET", "/api/v1/auth/me", session, nil); r.status != http.StatusOK {
		t.Errorf("current session closed: %d", r.status)
	}
	if r := e.do("GET", "/api/v1/auth/me", other, nil); r.status != http.StatusUnauthorized {
		t.Errorf("other session still open: %d", r.status)
	}
	if r := e.do("POST", "/api/v1/auth/login", "", loginRequest{Email: "alice@example.com", Password: "another long passphrase"}); r.status != http.StatusOK {
		t.Errorf("login with the new password = %d", r.status)
	}
}
