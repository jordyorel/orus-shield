package api

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/jordyorel/orus-shield/engine/internal/paddle"
	"github.com/jordyorel/orus-shield/engine/internal/plan"
	"github.com/jordyorel/orus-shield/engine/internal/store"
)

type checkoutRequest struct {
	Plan   string `json:"plan"`   // sme, pro
	Period string `json:"period"` // monthly, yearly
}

type checkoutJSON struct {
	TransactionID string `json:"transaction_id"`
	ClientToken   string `json:"client_token"` // public, for Paddle.js
	Environment   string `json:"environment"`  // sandbox, production
	Email         string `json:"email"`        // prefilled in the checkout
	// Trial: the price has a 14-day trial; Paddle charges at its end.
	Trial bool `json:"trial"`
}

// cardTrial tells whether the organization may start the 14-day trial at
// checkout (one per organization: never had a Paddle customer), and
// whether it already pays Paddle for a subscription still running (a second
// checkout would charge it twice).
func (s *Server) cardTrial(r *http.Request, req orgRequest) (available, live bool, err error) {
	acct, err := req.org.BillingAccount(r.Context())
	if err != nil {
		return false, false, err
	}
	if acct == nil {
		return true, false, nil
	}
	sub, err := req.org.Subscription(r.Context())
	if err != nil {
		return false, false, err
	}
	eff := plan.Resolve(sub, s.cfg.Now())
	live = acct.Provider == "paddle" && sub != nil && sub.Status != plan.Canceled && !eff.Lapsed && eff.Plan.ID != plan.Discovery
	return false, live, nil
}

// checkout answers POST /orgs/{org}/checkout (admins): the Paddle
// transaction for an offer, which the dashboard opens in Paddle's checkout.
func (s *Server) checkout(w http.ResponseWriter, r *http.Request, req orgRequest) {
	if !s.cfg.Paddle.Enabled() {
		writeError(w, http.StatusServiceUnavailable, "online payment is not configured on this server")
		return
	}
	var body checkoutRequest
	if !decode(w, r, &body) {
		return
	}
	if (body.Plan != string(plan.SME) && body.Plan != string(plan.Pro)) || (body.Period != "monthly" && body.Period != "yearly") {
		writeError(w, http.StatusBadRequest, "plan must be sme or pro, period monthly or yearly")
		return
	}
	trial, live, err := s.cardTrial(r, req)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if live {
		// Changing the offer of a running subscription is not a new
		// checkout: it would start a second subscription.
		writeError(w, http.StatusConflict, "this organization already has a subscription; cancel it first")
		return
	}
	price, ok := s.cfg.Paddle.Prices[paddle.PriceKey(body.Plan, body.Period, trial)]
	if !ok {
		writeError(w, http.StatusServiceUnavailable, "online payment is not configured on this server")
		return
	}
	id, err := paddle.New(s.cfg.Paddle).CreateTransaction(r.Context(), price, req.org.ID(), req.sess.Email)
	if err != nil {
		s.log.Error("paddle checkout", "err", err)
		writeError(w, http.StatusBadGateway, "the payment provider did not answer, try again")
		return
	}
	// Remembered, so the subscription is recorded once paid even without
	// the webhook or the return page (syncPendingCheckout).
	if validTransactionID(id) {
		if err := req.org.AddPendingCheckout(r.Context(), id); err != nil {
			s.internalError(w, r, err)
			return
		}
	}
	writeJSON(w, http.StatusOK, checkoutJSON{TransactionID: id, ClientToken: s.cfg.Paddle.ClientToken,
		Environment: s.cfg.Paddle.Environment, Email: req.sess.Email, Trial: trial})
}

// billingPortal answers POST /orgs/{org}/billing/portal (admins): the
// address of the organization's Paddle portal (invoices, payment method,
// cancellation); 404 when it pays nothing online.
func (s *Server) billingPortal(w http.ResponseWriter, r *http.Request, req orgRequest) {
	if !s.cfg.Paddle.Enabled() {
		writeError(w, http.StatusServiceUnavailable, "online payment is not configured on this server")
		return
	}
	acct, err := req.org.BillingAccount(r.Context())
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if acct == nil || acct.Provider != "paddle" {
		writeError(w, http.StatusNotFound, "no online subscription")
		return
	}
	url, err := paddle.New(s.cfg.Paddle).PortalURL(r.Context(), acct.Customer, []string{acct.Ref})
	if err != nil {
		s.log.Error("paddle portal", "err", err)
		writeError(w, http.StatusBadGateway, "the payment provider did not answer, try again")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"url": url})
}

// maxWebhook bounds a Paddle notification.
const maxWebhook = 256 << 10

// paddleWebhook answers POST /api/v1/billing/paddle: Paddle's notifications,
// signed with the destination's secret. Subscription events update the
// organization named in the transaction's custom data (set by our server
// at checkout). Every event applies once (store.Billing).
func (s *Server) paddleWebhook(w http.ResponseWriter, r *http.Request) {
	if !s.cfg.Paddle.Enabled() {
		writeError(w, http.StatusServiceUnavailable, "online payment is not configured")
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxWebhook))
	if err != nil {
		writeError(w, http.StatusBadRequest, "unreadable body")
		return
	}
	if err := paddle.Verify(r.Header.Get("Paddle-Signature"), body, s.cfg.Paddle.WebhookSecret, s.cfg.Now()); err != nil {
		writeError(w, http.StatusUnauthorized, "invalid signature")
		return
	}
	ev, sub, ok := parseSubscriptionEvent(body)
	if !ok {
		w.WriteHeader(http.StatusOK) // not an event we act on
		return
	}
	u, why := s.providerUpdate(ev, sub)
	if why != "" {
		// Signed but unusable (unknown price, no organization): retrying
		// cannot help, so it is acknowledged and logged.
		s.log.Warn("paddle event ignored", "event_id", ev.ID, "type", ev.Type, "reason", why)
		w.WriteHeader(http.StatusOK)
		return
	}
	// The offer before the event: gaining monitoring starts it at once.
	var before plan.Plan
	org, orgErr := s.org(u.OrgID)
	if orgErr == nil {
		if eff, err := org.Plan(r.Context(), s.cfg.Now()); err == nil {
			before = eff.Plan
		}
	}
	applied, err := s.billing.Apply(r.Context(), u)
	if errors.Is(err, store.ErrNotFound) {
		s.log.Warn("paddle event for an unknown organization", "event_id", ev.ID)
		w.WriteHeader(http.StatusOK)
		return
	}
	if err != nil {
		s.internalError(w, r, err) // Paddle retries
		return
	}
	if applied && orgErr == nil {
		s.startMonitoring(r.Context(), org, before, "paddle")
	}
	s.log.Info("paddle event", "event_id", ev.ID, "type", ev.Type, "applied", applied, "plan", u.Sub.Plan, "status", u.Sub.Status)
	w.WriteHeader(http.StatusOK)
}

func parseSubscriptionEvent(body []byte) (paddle.Event, paddle.Subscription, bool) {
	ev, sub, err := paddle.ParseSubscriptionEvent(body)
	return ev, sub, err == nil
}

// providerUpdate turns a Paddle subscription into ours. why is set when it
// cannot be used.
func (s *Server) providerUpdate(ev paddle.Event, sub paddle.Subscription) (store.ProviderUpdate, string) {
	planID, period, ok := s.cfg.Paddle.PlanOfPrice(sub.PriceID())
	if !ok {
		return store.ProviderUpdate{}, "unknown price " + sub.PriceID()
	}
	if sub.CustomData.OrgID == "" {
		return store.ProviderUpdate{}, "no organization in custom_data"
	}
	now := s.cfg.Now()
	periodEnd := func() *time.Time {
		if sub.CurrentPeriod == nil {
			return nil
		}
		t := sub.CurrentPeriod.EndsAt
		return &t
	}
	var ps plan.Subscription
	ps.Plan = plan.ID(planID)
	switch sub.Status {
	case "active", "past_due":
		// past_due: a renewal failed; Paddle retries, and the grace days
		// (plan.GraceDays) run after the period's end.
		ps.Status, ps.PeriodEnd = plan.Active, periodEnd()
	case "trialing":
		ps.Status = plan.Trialing
		if ps.TrialEndsAt = periodEnd(); ps.TrialEndsAt == nil {
			return store.ProviderUpdate{}, "trial without an end"
		}
	case "paused", "canceled":
		end := now
		if sub.CanceledAt != nil {
			end = *sub.CanceledAt
		}
		ps.Status, ps.PeriodEnd = plan.Canceled, &end
	default:
		return store.ProviderUpdate{}, "unknown status " + sub.Status
	}
	// A scheduled cancel (customer canceled, paid period or trial still
	// running): Paddle will not charge again, so the offer ends then, with
	// no grace days. A trial canceled this way ends at the trial's end.
	if sc := sub.ScheduledChange; sc != nil && sc.Action == "cancel" && ps.Status != plan.Canceled {
		end := sc.EffectiveAt
		ps.Status, ps.PeriodEnd, ps.TrialEndsAt = plan.Canceled, &end, nil
	}
	return store.ProviderUpdate{EventID: ev.ID, EventType: ev.Type, OrgID: sub.CustomData.OrgID, Sub: ps,
		Provider: "paddle", Ref: sub.ID, Customer: sub.CustomerID, Period: period}, ""
}

type billingSyncRequest struct {
	TransactionID string `json:"transaction_id"`
}

type billingSyncJSON struct {
	// State: "active" (the subscription is recorded), or "pending" (Paddle
	// has not finished the payment yet: ask again in a moment).
	State string `json:"state"`
}

// billingSync answers POST /orgs/{org}/billing/sync (admins), called when
// the customer comes back from Paddle's checkout: it reads the transaction
// from Paddle and records its subscription at once, in case the webhook is
// late or lost (a tunnel down in development, a restart in production).
// It never overwrites a subscription a webhook already recorded, and a
// transaction of another organization is not found.
func (s *Server) billingSync(w http.ResponseWriter, r *http.Request, req orgRequest) {
	if !s.cfg.Paddle.Enabled() {
		writeError(w, http.StatusServiceUnavailable, "online payment is not configured on this server")
		return
	}
	var body billingSyncRequest
	if !decode(w, r, &body) {
		return
	}
	if !validTransactionID(body.TransactionID) {
		writeError(w, http.StatusBadRequest, "invalid transaction ID")
		return
	}
	state, err := s.syncTransaction(r.Context(), req.org, body.TransactionID)
	switch {
	case errors.Is(err, errForeignTransaction):
		writeError(w, http.StatusNotFound, "not found")
	case errors.Is(err, errPaddleAnswer):
		s.log.Warn("paddle sync", "err", err)
		writeError(w, http.StatusBadGateway, "the payment provider did not answer, try again")
	case err != nil:
		s.internalError(w, r, err)
	default:
		writeJSON(w, http.StatusOK, billingSyncJSON{State: state})
	}
}

func validTransactionID(id string) bool {
	return strings.HasPrefix(id, "txn_") && len(id) <= 100 && !strings.ContainsAny(id, "/?#")
}

var (
	// errForeignTransaction: the transaction is another organization's.
	errForeignTransaction = errors.New("transaction of another organization")
	// errPaddleAnswer: Paddle did not answer, or with something unusable.
	errPaddleAnswer = errors.New("unusable answer from paddle")
)

// syncTransaction reads a checkout's transaction from Paddle and, once it
// is paid, records its subscription for org: "active", or "pending" while
// Paddle has not finished the payment. It never overwrites a subscription a
// webhook already recorded, and forgets the organization's pending
// checkouts once one is applied.
func (s *Server) syncTransaction(ctx context.Context, org *store.Org, id string) (string, error) {
	tx, err := paddle.New(s.cfg.Paddle).GetTransaction(ctx, id)
	if err != nil {
		return "", fmt.Errorf("%w: %w", errPaddleAnswer, err)
	}
	if tx.CustomData.OrgID != org.ID() {
		return "", errForeignTransaction
	}
	if !tx.Paid() || tx.SubscriptionID == "" || tx.BillingPeriod == nil {
		return "pending", nil
	}
	planID, period, ok := s.cfg.Paddle.PlanOfPrice(tx.PriceID())
	if !ok {
		return "", fmt.Errorf("%w: unknown price %s", errPaddleAnswer, tx.PriceID())
	}
	// The checkout's transaction covers the first period: the trial, or
	// the first paid month or year. Webhooks take over from there.
	end := tx.BillingPeriod.EndsAt
	ps := plan.Subscription{Plan: plan.ID(planID), Status: plan.Active, PeriodEnd: &end}
	if tx.Trial() {
		ps = plan.Subscription{Plan: plan.ID(planID), Status: plan.Trialing, TrialEndsAt: &end}
	}
	eff, err := org.Plan(ctx, s.cfg.Now())
	if err != nil {
		return "", err
	}
	applied, err := s.billing.Apply(ctx, store.ProviderUpdate{
		EventID: "sync_" + tx.ID, EventType: "transaction.sync", OrgID: tx.CustomData.OrgID, Sub: ps,
		Provider: "paddle", Ref: tx.SubscriptionID, Customer: tx.CustomerID, Period: period, OnlyIfNew: true,
	})
	if err != nil {
		return "", err
	}
	if applied {
		s.startMonitoring(ctx, org, eff.Plan, "paddle")
	}
	if err := org.ClearPendingCheckouts(ctx); err != nil {
		return "", err
	}
	return "active", nil
}

// syncPendingCheckout gives a paid checkout its subscription when the
// organization has no paid offer in force: called when the subscription is
// read (the dashboard does at every load), so the trial starts even if the
// webhook is late or lost and the customer never saw the return page. Best
// effort: a failure leaves the offer as it is, and logs.
func (s *Server) syncPendingCheckout(ctx context.Context, org *store.Org) {
	id, err := org.LatestPendingCheckout(ctx, s.cfg.Now())
	if err != nil || id == "" {
		if err != nil {
			s.log.Warn("pending checkout", "err", err)
		}
		return
	}
	if _, err := s.syncTransaction(ctx, org, id); err != nil {
		s.log.Warn("pending checkout sync", "err", err)
	}
}
