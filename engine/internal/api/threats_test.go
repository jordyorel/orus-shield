package api

import (
	"net/http"
	"testing"
)

// The list itself is tested in the store (TestThreats); here: the route,
// its access rule and the empty shape.
func TestThreatsRoute(t *testing.T) {
	e := newEnv(t)
	a := e.tenant("A", "example.com")
	b := e.tenant("B", "example.org")

	var got list[threatJSON]
	r := e.do("GET", "/api/v1/orgs/"+a.orgID+"/threats", a.viewer, nil)
	r.json(t, &got)
	if r.status != http.StatusOK || got.Items == nil || len(got.Items) != 0 {
		t.Errorf("threats = %d %s", r.status, r.body)
	}
	if r := e.do("GET", "/api/v1/orgs/"+b.orgID+"/threats", a.viewer, nil); r.status != http.StatusNotFound {
		t.Errorf("another organization's threats = %d, want 404", r.status)
	}
}
