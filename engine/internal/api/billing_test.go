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
	var priced []string // the price of each transaction created
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/transactions":
			var tx struct {
				Items []struct {
					PriceID string `json:"price_id"`
				} `json:"items"`
			}
			_ = json.NewDecoder(r.Body).Decode(&tx)
			if len(tx.Items) == 1 {
				priced = append(priced, tx.Items[0].PriceID)
			}
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
			Prices: map[string]string{"sme/monthly": "pri_sme_m", "sme/yearly": "pri_sme_y", "pro/monthly": "pri_pro_m", "pro/yearly": "pri_pro_y",
				"sme/monthly/trial": "pri_sme_m_t", "sme/yearly/trial": "pri_sme_y_t", "pro/monthly/trial": "pri_pro_m_t", "pro/yearly/trial": "pri_pro_y_t"}}
	})
	a := e.tenant("A", "example.com")
	base := "/api/v1/orgs/" + a.orgID

	// Checkout: a transaction for the organization, admins only. Its first
	// one starts the 14-day trial (the trial price).
	var subJS subscriptionJSON
	e.do("GET", base+"/subscription", a.session, nil).json(t, &subJS)
	if !subJS.TrialAvailable {
		t.Error("new organization: no trial available")
	}
	var co checkoutJSON
	r := e.do("POST", base+"/checkout", a.session, checkoutRequest{Plan: "pro", Period: "yearly"})
	r.json(t, &co)
	if r.status != http.StatusOK || co.TransactionID != "txn_42" || co.ClientToken != "test_tok" || co.Environment != "sandbox" || !co.Trial {
		t.Fatalf("checkout = %d %s", r.status, r.body)
	}
	if len(priced) != 1 || priced[0] != "pri_pro_y_t" {
		t.Errorf("priced %v, want the trial price", priced)
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
	// Paying now: no second checkout (it would charge twice), and no
	// second trial.
	if r := e.do("POST", base+"/checkout", a.session, checkoutRequest{Plan: "sme", Period: "monthly"}); r.status != http.StatusConflict {
		t.Errorf("checkout while subscribed = %d, want 409", r.status)
	}
	e.do("GET", base+"/subscription", a.session, nil).json(t, &subJS)
	if subJS.TrialAvailable {
		t.Error("a second trial is available")
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
	// Subscribing again after a cancellation pays from the first day.
	priced = nil
	if r := e.do("POST", base+"/checkout", a.session, checkoutRequest{Plan: "sme", Period: "monthly"}); r.status != http.StatusOK {
		t.Errorf("checkout after cancel = %d %s", r.status, r.body)
	}
	if len(priced) != 1 || priced[0] != "pri_sme_m" {
		t.Errorf("priced %v, want the price without trial", priced)
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

	// A trial started at checkout: Essentiel until the trial's end, when
	// Paddle charges (subscription.activated) or the trial is canceled.
	b := e.tenant("B", "example.org")
	trialEnds := e.now.Add(14 * 24 * time.Hour)
	trialing := subscriptionEvent("evt_10", "subscription.created", "trialing", b.orgID, "pri_sme_m_t", trialEnds, "")
	if got := hook(trialing, signPaddle(trialing, e.now)); got != http.StatusOK {
		t.Fatal(got)
	}
	tsub, _ := e.st.SubscriptionOf(context.Background(), b.orgID)
	if tsub == nil || tsub.Plan != plan.SME || tsub.Status != plan.Trialing || tsub.TrialEndsAt == nil || !tsub.TrialEndsAt.Equal(trialEnds.Truncate(time.Second)) {
		t.Errorf("trial = %+v", tsub)
	}
	if r := e.do("POST", "/api/v1/orgs/"+b.orgID+"/checkout", b.session, checkoutRequest{Plan: "pro", Period: "monthly"}); r.status != http.StatusConflict {
		t.Errorf("checkout during the trial = %d, want 409", r.status)
	}
	// The trial's end: Paddle charges the card and the subscription becomes
	// active for the first paid period.
	paidEnds := trialEnds.Add(30 * 24 * time.Hour)
	charged := subscriptionEvent("evt_11", "subscription.activated", "active", b.orgID, "pri_sme_m_t", paidEnds, "")
	if got := hook(charged, signPaddle(charged, e.now)); got != http.StatusOK {
		t.Fatal(got)
	}
	if sub, _ := e.st.SubscriptionOf(context.Background(), b.orgID); sub.Plan != plan.SME || sub.Status != plan.Active || sub.PeriodEnd == nil || !sub.PeriodEnd.Equal(paidEnds.Truncate(time.Second)) {
		t.Errorf("after the trial's charge = %+v", sub)
	}

	// A trial canceled before its end: Paddle keeps it trialing with a
	// scheduled cancel and will not charge. It ends with the trial, and the
	// dashboard must show that end.
	c := e.tenant("C", "example.net")
	cancelTrial := subscriptionEvent("evt_20", "subscription.updated", "trialing", c.orgID, "pri_sme_m_t", trialEnds,
		fmt.Sprintf(`,"scheduled_change":{"action":"cancel","effective_at":%q}`, trialEnds.UTC().Format(time.RFC3339)))
	if got := hook(cancelTrial, signPaddle(cancelTrial, e.now)); got != http.StatusOK {
		t.Fatal(got)
	}
	csub, _ := e.st.SubscriptionOf(context.Background(), c.orgID)
	if csub == nil || csub.Status != plan.Canceled || csub.PeriodEnd == nil || !csub.PeriodEnd.Equal(trialEnds.Truncate(time.Second)) {
		t.Fatalf("trial canceled = %+v", csub)
	}
	if eff := plan.Resolve(csub, e.now); eff.Plan.ID != plan.SME || eff.Until == nil {
		t.Errorf("canceled trial before its end = %+v, want Essentiel until the trial's end", eff)
	}
	if eff := plan.Resolve(csub, trialEnds.Add(time.Hour)); eff.Plan.ID != plan.Discovery || eff.InGrace {
		t.Errorf("canceled trial after its end = %+v, want Gratuit without grace", eff)
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
