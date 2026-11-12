package api

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jordyorel/orus-shield/engine/internal/paddle"
	"github.com/jordyorel/orus-shield/engine/internal/plan"
)

const webhookSecret = "whsec"

func signPaddle(body []byte, at time.Time) string {
	ts := fmt.Sprint(at.Unix())
	mac := hmac.New(sha256.New, []byte(webhookSecret))
	mac.Write([]byte(ts + ":"))
	mac.Write(body)
	return "ts=" + ts + ";h1=" + hex.EncodeToString(mac.Sum(nil))
}

func subscriptionEvent(id, typ, status, orgID, price string, ends time.Time, extra string) []byte {
	// Compact, as the request helper re-encodes it: the signed bytes must be
	// the bytes sent.
	var out bytes.Buffer
	_ = json.Compact(&out, []byte(fmt.Sprintf(`{"event_id":%q,"event_type":%q,"data":{"id":"sub_1","status":%q,"customer_id":"ctm_1",
	 "custom_data":{"org_id":%q},"items":[{"price":{"id":%q}}],"current_billing_period":{"ends_at":%q}%s}}`,
		id, typ, status, orgID, price, ends.UTC().Format(time.RFC3339), extra)))
	return out.Bytes()
}

func TestPaddle(t *testing.T) {
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/transactions":
			_, _ = w.Write([]byte(`{"data":{"id":"txn_42"}}`))
		case "/customers/ctm_1/portal-sessions":
			_, _ = w.Write([]byte(`{"data":{"urls":{"general":{"overview":"https://customer-portal.paddle.com/p"}}}}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer fake.Close()
	e := newEnvWith(t, func(c *Config) {
		c.Paddle = paddle.Config{Environment: paddle.Sandbox, APIKey: "key", ClientToken: "test_tok", WebhookSecret: webhookSecret, BaseURL: fake.URL,
			Prices: map[string]string{"sme/monthly": "pri_sme_m", "sme/yearly": "pri_sme_y", "pro/monthly": "pri_pro_m", "pro/yearly": "pri_pro_y"}}
	})
	a := e.tenant("A", "example.com")
	base := "/api/v1/orgs/" + a.orgID

	// Checkout: a transaction for the organization, admins only.
	var co checkoutJSON
	r := e.do("POST", base+"/checkout", a.session, checkoutRequest{Plan: "pro", Period: "yearly"})
	r.json(t, &co)
	if r.status != http.StatusOK || co.TransactionID != "txn_42" || co.ClientToken != "test_tok" || co.Environment != "sandbox" {
		t.Fatalf("checkout = %d %s", r.status, r.body)
	}
	if r := e.do("POST", base+"/checkout", a.viewer, checkoutRequest{Plan: "pro", Period: "yearly"}); r.status != http.StatusForbidden {
		t.Errorf("viewer = %d", r.status)
	}
	if r := e.do("POST", base+"/checkout", a.session, checkoutRequest{Plan: "enterprise", Period: "monthly"}); r.status != http.StatusBadRequest {
		t.Errorf("enterprise = %d, want 400", r.status)
	}
	if r := e.do("POST", base+"/billing/portal", a.session, nil); r.status != http.StatusNotFound {
		t.Errorf("portal before paying = %d, want 404", r.status)
	}

	// Paddle's webhook: the organization moves to Pro, paid until ends.
	hook := func(body []byte, sig string) int {
		return e.doHeaders("POST", "/api/v1/billing/paddle", map[string]string{"Paddle-Signature": sig}, json.RawMessage(body)).status
	}
	ends := e.now.Add(365 * 24 * time.Hour)
	created := subscriptionEvent("evt_1", "subscription.created", "active", a.orgID, "pri_pro_y", ends, "")
	if got := hook(created, "ts=1;h1=00"); got != http.StatusUnauthorized {
		t.Errorf("bad signature = %d, want 401", got)
	}
	if got := hook(created, signPaddle(created, e.now)); got != http.StatusOK {
		t.Fatalf("webhook = %d", got)
	}
	sub, err := e.st.SubscriptionOf(context.Background(), a.orgID)
	if err != nil || sub == nil || sub.Plan != plan.Pro || sub.Status != plan.Active || sub.PeriodEnd == nil || !sub.PeriodEnd.Equal(ends.Truncate(time.Second)) {
		t.Fatalf("subscription = %+v, %v", sub, err)
	}
	// The same event again applies once (it would reset a later change).
	_ = e.st.SetSubscription(context.Background(), a.orgID, plan.Subscription{Plan: plan.SME, Status: plan.Active}, "manual", "test")
	if got := hook(created, signPaddle(created, e.now)); got != http.StatusOK {
		t.Errorf("replay = %d", got)
	}
	if sub, _ := e.st.SubscriptionOf(context.Background(), a.orgID); sub.Plan != plan.SME {
		t.Errorf("a replayed event applied again: %+v", sub)
	}
	// Cancellation at the period's end.
	canceled := subscriptionEvent("evt_2", "subscription.updated", "active", a.orgID, "pri_pro_y", ends,
		fmt.Sprintf(`,"scheduled_change":{"action":"cancel","effective_at":%q}`, ends.UTC().Format(time.RFC3339)))
	if got := hook(canceled, signPaddle(canceled, e.now)); got != http.StatusOK {
		t.Fatal(got)
	}
	if sub, _ := e.st.SubscriptionOf(context.Background(), a.orgID); sub.Status != plan.Canceled || sub.PeriodEnd == nil {
		t.Errorf("after cancel = %+v", sub)
	}
	// An unknown price is acknowledged but changes nothing.
	odd := subscriptionEvent("evt_3", "subscription.updated", "active", a.orgID, "pri_unknown", ends, "")
	if got := hook(odd, signPaddle(odd, e.now)); got != http.StatusOK {
		t.Errorf("unknown price = %d", got)
	}
	if sub, _ := e.st.SubscriptionOf(context.Background(), a.orgID); sub.Status != plan.Canceled {
		t.Errorf("unknown price changed the subscription: %+v", sub)
	}

	// The portal opens once Paddle knows the customer.
	var portal map[string]string
	r = e.do("POST", base+"/billing/portal", a.session, nil)
	r.json(t, &portal)
	if r.status != http.StatusOK || portal["url"] != "https://customer-portal.paddle.com/p" {
		t.Errorf("portal = %d %s", r.status, r.body)
	}
}

func TestPaddleOff(t *testing.T) {
	e := newEnv(t)
	a := e.tenant("A", "example.com")
	if r := e.do("POST", "/api/v1/orgs/"+a.orgID+"/checkout", a.session, checkoutRequest{Plan: "pro", Period: "monthly"}); r.status != http.StatusServiceUnavailable {
		t.Errorf("checkout without Paddle = %d, want 503", r.status)
	}
	if r := e.doHeaders("POST", "/api/v1/billing/paddle", nil, json.RawMessage(`{}`)); r.status != http.StatusServiceUnavailable {
		t.Errorf("webhook without Paddle = %d, want 503", r.status)
	}
}
