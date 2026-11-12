package paddle

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// Sign returns the Paddle-Signature header Paddle would send.
func Sign(body []byte, secret string, at time.Time) string {
	ts := fmt.Sprint(at.Unix())
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(ts + ":"))
	mac.Write(body)
	return "ts=" + ts + ";h1=" + hex.EncodeToString(mac.Sum(nil))
}

func TestVerify(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	body := []byte(`{"event_id":"evt_1"}`)
	good := Sign(body, "secret", now)
	if err := Verify(good, body, "secret", now.Add(time.Minute)); err != nil {
		t.Errorf("valid = %v", err)
	}
	for name, tc := range map[string]struct {
		header string
		body   []byte
		secret string
		at     time.Time
	}{
		"wrong secret": {good, body, "other", now},
		"changed body": {good, []byte(`{"event_id":"evt_2"}`), "secret", now},
		"too old":      {good, body, "secret", now.Add(10 * time.Minute)},
		"no signature": {"ts=1800000000", body, "secret", now},
		"garbage":      {"nonsense", body, "secret", now},
		"empty secret": {good, body, "", now},
	} {
		if err := Verify(tc.header, tc.body, tc.secret, tc.at); !errors.Is(err, ErrSignature) {
			t.Errorf("%s = %v, want ErrSignature", name, err)
		}
	}
	// Paddle may send several h1 during a secret rotation.
	if err := Verify("ts="+fmt.Sprint(now.Unix())+";h1=00;"+strings.Split(good, ";")[1], body, "secret", now); err != nil {
		t.Errorf("rotation = %v", err)
	}
}

func TestClient(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer key" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		switch r.URL.Path {
		case "/transactions":
			if body["custom_data"].(map[string]any)["org_id"] != "org-1" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			_, _ = w.Write([]byte(`{"data":{"id":"txn_1"}}`))
		case "/customers/ctm_1/portal-sessions":
			_, _ = w.Write([]byte(`{"data":{"urls":{"general":{"overview":"https://customer-portal.paddle.com/x"}}}}`))
		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error":{"code":"not_found","detail":"no"}}`))
		}
	}))
	defer srv.Close()
	c := New(Config{APIKey: "key", BaseURL: srv.URL})
	if id, err := c.CreateTransaction(context.Background(), "pri_1", "org-1", "a@b.c"); err != nil || id != "txn_1" {
		t.Errorf("transaction = %q, %v", id, err)
	}
	if u, err := c.PortalURL(context.Background(), "ctm_1", []string{"sub_1"}); err != nil || u != "https://customer-portal.paddle.com/x" {
		t.Errorf("portal = %q, %v", u, err)
	}
	if _, err := c.PortalURL(context.Background(), "ctm_x", nil); !errors.Is(err, ErrPaddle) {
		t.Errorf("unknown customer = %v", err)
	}
	if _, err := New(Config{APIKey: "bad", BaseURL: srv.URL}).CreateTransaction(context.Background(), "p", "org-1", ""); !errors.Is(err, ErrPaddle) {
		t.Errorf("bad key = %v", err)
	}
}

func TestPlanOfPrice(t *testing.T) {
	c := Config{Prices: map[string]string{"sme/monthly": "pri_a", "pro/yearly": "pri_b"}}
	if p, period, ok := c.PlanOfPrice("pri_b"); !ok || p != "pro" || period != "yearly" {
		t.Errorf("PlanOfPrice = %s %s %v", p, period, ok)
	}
	if _, _, ok := c.PlanOfPrice("pri_x"); ok {
		t.Error("unknown price matched")
	}
}
