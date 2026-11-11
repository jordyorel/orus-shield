package api

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/jordyorel/orus-shield/engine/internal/store"
)

// linkToken returns the token of the setup link in an email body.
func linkToken(t *testing.T, text string) string {
	t.Helper()
	const prefix = "https://app.example/setup-password#token="
	i := strings.Index(text, prefix)
	if i < 0 {
		t.Fatalf("no setup link in:\n%s", text)
	}
	tok, err := url.QueryUnescape(strings.Fields(text[i+len(prefix):])[0])
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func TestInvitationsAreEmailed(t *testing.T) {
	e := newEnv(t)
	a := e.tenant("Acme Corp", "example.com")
	base := "/api/v1/orgs/" + a.orgID

	// A new address: an activation link, the same token the admin sees.
	r := e.do("POST", base+"/members", a.session, inviteRequest{Email: "new@example.com", Role: store.RoleAdmin})
	var inv invitationJSON
	r.json(t, &inv)
	if r.status != http.StatusCreated || !inv.Emailed || inv.SetupToken == "" {
		t.Fatalf("invite = %d %s", r.status, r.body)
	}
	m := e.nextMail()
	if m.To != "new@example.com" || m.Subject != "Invitation à rejoindre Acme Corp sur Orus Shield" {
		t.Errorf("email to %q, subject %q", m.To, m.Subject)
	}
	if !strings.Contains(m.Text, "administrateur") || linkToken(t, m.Text) != inv.SetupToken {
		t.Errorf("email body:\n%s", m.Text)
	}

	// A new link: emailed too, and the old one stops working.
	r = e.do("POST", base+"/members/"+inv.Member.UserID+"/setup-token", a.session, nil)
	var again setupTokenJSON
	r.json(t, &again)
	if r.status != http.StatusOK || !again.Emailed {
		t.Fatalf("reissue = %d %s", r.status, r.body)
	}
	if tok := linkToken(t, e.nextMail().Text); tok != again.SetupToken {
		t.Error("reissued email does not carry the new token")
	}
	if r := e.do("POST", "/api/v1/auth/setup-password", "", setupPasswordRequest{Token: inv.SetupToken, Password: "a long enough passphrase"}); r.status != http.StatusBadRequest {
		t.Errorf("old invitation link still works: %d", r.status)
	}

	// An account that already exists: no token, a note that they have access.
	e.user("existing@example.com", "", "")
	r = e.do("POST", base+"/members", a.session, inviteRequest{Email: "existing@example.com", Role: store.RoleViewer})
	var existing invitationJSON
	r.json(t, &existing)
	if r.status != http.StatusCreated || existing.SetupToken != "" || !existing.Emailed {
		t.Fatalf("invite existing = %d %s", r.status, r.body)
	}
	m = e.nextMail()
	if m.To != "existing@example.com" || !strings.Contains(m.Subject, "Vous avez accès à Acme Corp") ||
		!strings.Contains(m.Text, "https://app.example/login") || strings.Contains(m.Text, "token=") {
		t.Errorf("access email: %q\n%s", m.Subject, m.Text)
	}
}
