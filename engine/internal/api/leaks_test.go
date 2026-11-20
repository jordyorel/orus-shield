package api

import (
	"net/http"
	"testing"
)

func TestLeakAddresses(t *testing.T) {
	e := newEnv(t)
	a := e.tenant("A", "example.com")
	path := "/api/v1/orgs/" + a.orgID + "/targets/" + a.target.ID + "/leak-addresses"
	body := map[string]string{"email": "Compta@Example.com"}

	if r := e.do("POST", path, a.viewer, body); r.status != http.StatusForbidden {
		t.Errorf("viewer = %d, want 403", r.status)
	}
	var created leakAddressJSON
	r := e.do("POST", path, a.session, body)
	r.json(t, &created)
	if r.status != http.StatusCreated || created.Email != "compta@example.com" {
		t.Fatalf("add = %d %s", r.status, r.body)
	}
	if r := e.do("POST", path, a.session, body); r.status != http.StatusConflict {
		t.Errorf("again = %d, want 409", r.status)
	}
	for name, bad := range map[string]string{
		"other domain": "x@other.org",
		"look-alike":   "x@evilexample.com",
		"not an email": "compta",
		"no local":     "@example.com",
	} {
		if r := e.do("POST", path, a.session, map[string]string{"email": bad}); r.status != http.StatusBadRequest {
			t.Errorf("%s = %d %s, want 400", name, r.status, r.body)
		}
	}
	if r := e.do("POST", path, a.session, map[string]string{"email": "it@mail.example.com"}); r.status != http.StatusCreated {
		t.Errorf("subdomain = %d %s", r.status, r.body)
	}
	var got list[leakAddressJSON]
	e.do("GET", path, a.viewer, nil).json(t, &got)
	if len(got.Items) != 2 {
		t.Errorf("list = %+v", got.Items)
	}
	if r := e.do("DELETE", path+"/"+created.ID, a.session, nil); r.status != http.StatusNoContent {
		t.Errorf("remove = %d", r.status)
	}
	b := e.tenant("B", "example.org")
	other := "/api/v1/orgs/" + b.orgID + "/targets/" + a.target.ID + "/leak-addresses"
	if r := e.do("GET", other, b.session, nil); r.status != http.StatusNotFound {
		t.Errorf("cross-tenant = %d, want 404", r.status)
	}
}
