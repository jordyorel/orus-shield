package api

import (
	"errors"
	"io"
	"net/http"
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
	price, ok := s.cfg.Paddle.Prices[body.Plan+"/"+body.Period]
	if !ok || (body.Plan != string(plan.SME) && body.Plan != string(plan.Pro)) {
		writeError(w, http.StatusBadRequest, "plan must be sme or pro, period monthly or yearly")
		return
	}
	id, err := paddle.New(s.cfg.Paddle).CreateTransaction(r.Context(), price, req.org.ID(), req.sess.Email)
	if err != nil {
		s.log.Error("paddle checkout", "err", err)
		writeError(w, http.StatusBadGateway, "the payment provider did not answer, try again")
		return
	}
	writeJSON(w, http.StatusOK, checkoutJSON{TransactionID: id, ClientToken: s.cfg.Paddle.ClientToken,
		Environment: s.cfg.Paddle.Environment, Email: req.sess.Email})
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
	planID, _, ok := s.cfg.Paddle.PlanOfPrice(sub.PriceID())
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
		if sc := sub.ScheduledChange; sc != nil && sc.Action == "cancel" {
			end := sc.EffectiveAt
			ps.Status, ps.PeriodEnd = plan.Canceled, &end
		}
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
	return store.ProviderUpdate{EventID: ev.ID, EventType: ev.Type, OrgID: sub.CustomData.OrgID, Sub: ps,
		Provider: "paddle", Ref: sub.ID, Customer: sub.CustomerID}, ""
}
