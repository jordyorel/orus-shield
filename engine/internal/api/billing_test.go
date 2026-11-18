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

func TestBillingSync(t *testing.T) {
	ends := time.Date(2026, 12, 1, 20, 2, 7, 0, time.UTC)
	var orgID string // the tenant's, known once created
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tx := func(status, org string) {
			_, _ = fmt.Fprintf(w, `{"data":{"id":"txn","status":%q,"subscription_id":"sub_9","customer_id":"ctm_9","custom_data":{"org_id":%q},
				"items":[{"price":{"id":"pri_sme_y_t","trial_period":{"interval":"day","frequency":14}}}],
				"billing_period":{"starts_at":"2026-11-17T20:02:07Z","ends_at":%q}}}`, status, org, ends.Format(time.RFC3339))
		}
		switch r.URL.Path {
		case "/transactions/txn_ok":
			tx("completed", orgID)
		case "/transactions/txn_ready":
			tx("ready", orgID)
		case "/transactions/txn_other":
			tx("completed", "01a1c4c7-edc4-743c-b378-719267497786")
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer fake.Close()
	e := newEnvWith(t, func(c *Config) {
		c.Paddle = paddle.Config{Environment: paddle.Sandbox, APIKey: "key", ClientToken: "test_tok", WebhookSecret: webhookSecret, BaseURL: fake.URL,
			Prices: map[string]string{"sme/monthly": "pri_sme_m", "sme/yearly": "pri_sme_y", "sme/monthly/trial": "pri_sme_m_t", "sme/yearly/trial": "pri_sme_y_t"}}
	})
	a := e.tenant("A", "example.com")
	orgID = a.orgID
	path := "/api/v1/orgs/" + a.orgID + "/billing/sync"
	sync := func(id string) (int, billingSyncJSON) {
		var out billingSyncJSON
		r := e.do("POST", path, a.session, billingSyncRequest{TransactionID: id})
		if r.status == http.StatusOK {
			r.json(t, &out)
		}
		return r.status, out
	}

	// Not paid yet: pending, nothing recorded.
	if st, out := sync("txn_ready"); st != http.StatusOK || out.State != "pending" {
		t.Errorf("unpaid = %d %+v, want pending", st, out)
	}
	// Another organization's transaction is not found.
	if st, _ := sync("txn_other"); st != http.StatusNotFound {
		t.Errorf("other organization's transaction = %d, want 404", st)
	}
	// Paid: the yearly trial is recorded at once, without the webhook.
	if st, out := sync("txn_ok"); st != http.StatusOK || out.State != "active" {
		t.Fatalf("paid = %d %+v", st, out)
	}
	sub, err := e.st.SubscriptionOf(context.Background(), a.orgID)
	if err != nil || sub == nil || sub.Plan != plan.SME || sub.Status != plan.Trialing || sub.TrialEndsAt == nil || !sub.TrialEndsAt.Equal(ends) {
		t.Fatalf("subscription after sync = %+v, %v", sub, err)
	}
	var subJS subscriptionJSON
	e.do("GET", "/api/v1/orgs/"+a.orgID+"/subscription", a.session, nil).json(t, &subJS)
	if subJS.Period != "yearly" || subJS.Plan.ID != plan.SME {
		t.Errorf("subscription JSON = %+v, want Essentiel yearly", subJS)
	}

	// Later changes (a webhook's cancellation) are never overwritten by a
	// sync of the same subscription.
	if err := e.st.SetSubscription(context.Background(), a.orgID, plan.Subscription{Plan: plan.SME, Status: plan.Canceled, PeriodEnd: &ends}, "paddle", "test"); err != nil {
		t.Fatal(err)
	}
	if st, _ := sync("txn_ok"); st != http.StatusOK {
		t.Fatalf("sync again = %d", st)
	}
	if sub, _ := e.st.SubscriptionOf(context.Background(), a.orgID); sub.Status != plan.Canceled {
		t.Errorf("sync overwrote a later change: %+v", sub)
	}
	// Viewers cannot sync; a malformed ID never reaches Paddle.
	if r := e.do("POST", path, a.viewer, billingSyncRequest{TransactionID: "txn_ok"}); r.status != http.StatusForbidden {
		t.Errorf("viewer = %d, want 403", r.status)
	}
	if st, _ := sync("../customers"); st != http.StatusBadRequest {
		t.Errorf("malformed ID = %d, want 400", st)
	}
}

func TestPendingCheckoutSync(t *testing.T) {
	ends := time.Date(2026, 12, 2, 8, 8, 46, 0, time.UTC)
	var orgID string
	paid := false
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/transactions":
			_, _ = w.Write([]byte(`{"data":{"id":"txn_pc"}}`))
		case r.URL.Path == "/transactions/txn_pc":
			status := "ready"
			if paid {
				status = "completed"
			}
			_, _ = fmt.Fprintf(w, `{"data":{"id":"txn_pc","status":%q,"subscription_id":"sub_pc","customer_id":"ctm_pc","custom_data":{"org_id":%q},
				"items":[{"price":{"id":"pri_sme_y_t","trial_period":{"interval":"day","frequency":14}}}],
				"billing_period":{"starts_at":"2026-11-18T08:08:46Z","ends_at":%q}}}`, status, orgID, ends.Format(time.RFC3339))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer fake.Close()
	e := newEnvWith(t, func(c *Config) {
		c.Paddle = paddle.Config{Environment: paddle.Sandbox, APIKey: "key", ClientToken: "test_tok", WebhookSecret: webhookSecret, BaseURL: fake.URL,
			Prices: map[string]string{"sme/yearly": "pri_sme_y", "sme/yearly/trial": "pri_sme_y_t"}}
	})
	a := e.tenant("A", "example.com")
	orgID = a.orgID
	base := "/api/v1/orgs/" + a.orgID
	e.setPlan(a.orgID, plan.Subscription{Plan: plan.Discovery, Status: plan.Active})
	e.verifyTarget(a.session, a.orgID, a.target.ID) // the free audit is used: nothing queued

	if r := e.do("POST", base+"/checkout", a.session, checkoutRequest{Plan: "sme", Period: "yearly"}); r.status != http.StatusOK {
		t.Fatalf("checkout = %d %s", r.status, r.body)
	}
	var sub subscriptionJSON
	// Not paid yet: still Gratuit.
	e.do("GET", base+"/subscription", a.session, nil).json(t, &sub)
	if sub.Plan.ID != plan.Discovery {
		t.Errorf("before payment = %s", sub.Plan.ID)
	}
	// Paid, no webhook, no return page: reading the subscription records it.
	paid = true
	e.do("GET", base+"/subscription", a.session, nil).json(t, &sub)
	if sub.Plan.ID != plan.SME || sub.Status != "trialing" || sub.Period != "yearly" {
		t.Errorf("after payment = %+v, want Essentiel trialing yearly", sub)
	}
	// What the customer bought starts at once: a full scan of the verified
	// domain, and a weekly schedule since none was chosen.
	var scans list[scanJSON]
	e.do("GET", base+"/targets/"+a.target.ID+"/scans", a.session, nil).json(t, &scans)
	if len(scans.Items) == 0 || scans.Items[0].Status != "queued" || scans.Items[0].RequestedBy != "paddle" {
		t.Errorf("scans after the trial started = %+v, want one queued by paddle", scans.Items)
	}
	var settings orgSettingsJSON
	e.do("GET", base+"/settings", a.session, nil).json(t, &settings)
	if settings.Frequency != "weekly" || settings.Weekday != 6 || settings.Hour != 2 {
		t.Errorf("settings after the trial started = %+v, want weekly, Saturday 2:00", settings)
	}
	var tg targetJSON
	e.do("GET", base+"/targets/"+a.target.ID, a.session, nil).json(t, &tg)
	if tg.Schedule == nil {
		t.Error("the domain got no schedule")
	}
	// Applied once: the pending checkout is forgotten.
	if id, err := e.st.Org(a.orgID); err != nil {
		t.Fatal(err)
	} else if pending, err := id.LatestPendingCheckout(context.Background(), e.now); err != nil || pending != "" {
		t.Errorf("pending checkout after sync = %q, %v", pending, err)
	}
}
