package api

import (
	"net/http"
	"testing"
)

func TestUnsubscribeUnknownToken(t *testing.T) {
	e := newEnv(t)
	if r := e.do("POST", "/api/v1/unsubscribe", "", unsubscribeRequest{Token: "nope"}); r.status != http.StatusNotFound {
		t.Errorf("unknown token = %d %s, want 404", r.status, r.body)
	}
	if r := e.do("POST", "/api/v1/unsubscribe", "", unsubscribeRequest{}); r.status != http.StatusNotFound {
		t.Errorf("empty token = %d %s, want 404", r.status, r.body)
	}
}
