// Package paddle talks to Paddle Billing, the merchant of record that takes
// card (and PayPal) payments for the subscriptions: it creates the
// transaction a customer pays, opens their customer portal, and checks the
// signature of the webhooks Paddle sends. Standard library only.
//
// Card numbers never reach us: the customer types them in Paddle's
// checkout (Paddle.js overlay), opened on the transaction this package
// creates. The transaction carries the organization's ID (custom_data),
// set by our server, so a webhook can only ever change the organization
// that started the payment.
package paddle

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Environments.
const (
	Sandbox    = "sandbox"
	Production = "production"
)

// Config is the account's settings (environment variables, never in the
// repository: rule 5).
type Config struct {
	Environment   string // sandbox or production
	APIKey        string // server-side API key
	ClientToken   string // public token for Paddle.js
	WebhookSecret string // the notification destination's secret key
	// Prices maps "plan/period" ("sme/monthly", "pro/yearly") to Paddle
	// price IDs.
	Prices map[string]string
	// BaseURL overrides the API's address (tests).
	BaseURL string
}

// Enabled reports whether payments are configured.
func (c Config) Enabled() bool {
	return c.APIKey != "" && c.ClientToken != "" && c.WebhookSecret != "" && len(c.Prices) > 0
}

func (c Config) base() string {
	if c.BaseURL != "" {
		return strings.TrimRight(c.BaseURL, "/")
	}
	if c.Environment == Production {
		return "https://api.paddle.com"
	}
	return "https://sandbox-api.paddle.com"
}

// PlanOfPrice returns the plan and period of a Paddle price ID.
func (c Config) PlanOfPrice(priceID string) (plan, period string, ok bool) {
	for k, v := range c.Prices {
		if v == priceID {
			plan, period, _ = strings.Cut(k, "/")
			return plan, period, true
		}
	}
	return "", "", false
}

// Client calls Paddle's API.
type Client struct {
	cfg  Config
	http *http.Client
}

// New returns a client.
func New(cfg Config) *Client {
	return &Client{cfg: cfg, http: &http.Client{Timeout: 20 * time.Second}}
}

// maxAnswer bounds what we read from Paddle.
const maxAnswer = 1 << 20

// ErrPaddle is an error answered by Paddle.
var ErrPaddle = errors.New("paddle error")

func (c *Client) call(ctx context.Context, method, path string, body, out any) error {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.cfg.base()+path, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.cfg.APIKey)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("paddle %s: %w", path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxAnswer))
	if err != nil {
		return fmt.Errorf("paddle %s: %w", path, err)
	}
	if resp.StatusCode >= 300 {
		var e struct {
			Error struct {
				Code   string `json:"code"`
				Detail string `json:"detail"`
			} `json:"error"`
		}
		_ = json.Unmarshal(data, &e)
		return fmt.Errorf("%w: %s %d %s: %s", ErrPaddle, path, resp.StatusCode, e.Error.Code, e.Error.Detail)
	}
	if out != nil {
		if err := json.Unmarshal(data, out); err != nil {
			return fmt.Errorf("paddle %s: %w", path, err)
		}
	}
	return nil
}

// CustomData is what we attach to a transaction, and read back in its
// webhooks.
type CustomData struct {
	OrgID string `json:"org_id"`
}

// CreateTransaction creates the transaction an organization pays for one
// price, and returns its ID, which Paddle.js opens in the checkout.
func (c *Client) CreateTransaction(ctx context.Context, priceID, orgID, email string) (string, error) {
	body := map[string]any{
		"items":       []map[string]any{{"price_id": priceID, "quantity": 1}},
		"custom_data": CustomData{OrgID: orgID},
	}
	var out struct {
		Data struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := c.call(ctx, http.MethodPost, "/transactions", body, &out); err != nil {
		return "", err
	}
	if out.Data.ID == "" {
		return "", fmt.Errorf("%w: no transaction ID", ErrPaddle)
	}
	_ = email // Paddle's checkout asks for it; we prefill it in Paddle.js.
	return out.Data.ID, nil
}

// PortalURL opens a customer's portal (invoices, payment method,
// cancellation) and returns its address.
func (c *Client) PortalURL(ctx context.Context, customerID string, subscriptionIDs []string) (string, error) {
	body := map[string]any{"subscription_ids": subscriptionIDs}
	var out struct {
		Data struct {
			URLs struct {
				General struct {
					Overview string `json:"overview"`
				} `json:"general"`
			} `json:"urls"`
		} `json:"data"`
	}
	if err := c.call(ctx, http.MethodPost, "/customers/"+customerID+"/portal-sessions", body, &out); err != nil {
		return "", err
	}
	if !strings.HasPrefix(out.Data.URLs.General.Overview, "https://") {
		return "", fmt.Errorf("%w: no portal address", ErrPaddle)
	}
	return out.Data.URLs.General.Overview, nil
}

// ---- Webhooks ----------------------------------------------------------------

// Tolerance bounds the age of a webhook's signature: an old, captured
// notification cannot be replayed (the event IDs are deduplicated too).
const Tolerance = 5 * time.Minute

// ErrSignature is a webhook whose signature is missing, wrong or too old.
var ErrSignature = errors.New("invalid paddle signature")

// Verify checks the Paddle-Signature header ("ts=...;h1=...") of a webhook:
// HMAC-SHA256, keyed with the destination's secret, of "ts:body".
func Verify(header string, body []byte, secret string, now time.Time) error {
	var ts string
	var sigs []string
	for _, part := range strings.Split(header, ";") {
		k, v, _ := strings.Cut(strings.TrimSpace(part), "=")
		switch k {
		case "ts":
			ts = v
		case "h1":
			sigs = append(sigs, v)
		}
	}
	sec, err := strconv.ParseInt(ts, 10, 64)
	if err != nil || len(sigs) == 0 || secret == "" {
		return ErrSignature
	}
	if d := now.Sub(time.Unix(sec, 0)); d > Tolerance || d < -Tolerance {
		return ErrSignature
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(ts + ":"))
	mac.Write(body)
	want := mac.Sum(nil)
	for _, s := range sigs {
		got, err := hex.DecodeString(s)
		if err == nil && hmac.Equal(got, want) {
			return nil
		}
	}
	return ErrSignature
}

// Event is the part of a webhook we read.
type Event struct {
	ID   string          `json:"event_id"`
	Type string          `json:"event_type"`
	Data json.RawMessage `json:"data"`
}

// Subscription is the part of a subscription event we read.
type Subscription struct {
	ID         string     `json:"id"`
	Status     string     `json:"status"` // active, trialing, past_due, paused, canceled
	CustomerID string     `json:"customer_id"`
	CustomData CustomData `json:"custom_data"`
	Items      []struct {
		Price struct {
			ID string `json:"id"`
		} `json:"price"`
	} `json:"items"`
	CurrentPeriod *struct {
		EndsAt time.Time `json:"ends_at"`
	} `json:"current_billing_period"`
	ScheduledChange *struct {
		Action      string    `json:"action"` // cancel, pause, resume
		EffectiveAt time.Time `json:"effective_at"`
	} `json:"scheduled_change"`
	CanceledAt *time.Time `json:"canceled_at"`
}

// PriceID is the subscription's (single) price.
func (s Subscription) PriceID() string {
	if len(s.Items) == 0 {
		return ""
	}
	return s.Items[0].Price.ID
}

// ErrNotSubscription is an event that is not about a subscription.
var ErrNotSubscription = errors.New("not a subscription event")

// ParseSubscriptionEvent reads a webhook (already verified) and returns the
// subscription of a subscription.* event.
func ParseSubscriptionEvent(body []byte) (Event, Subscription, error) {
	var ev Event
	if err := json.Unmarshal(body, &ev); err != nil {
		return Event{}, Subscription{}, err
	}
	if ev.ID == "" || !strings.HasPrefix(ev.Type, "subscription.") {
		return ev, Subscription{}, ErrNotSubscription
	}
	var sub Subscription
	if err := json.Unmarshal(ev.Data, &sub); err != nil {
		return ev, Subscription{}, err
	}
	return ev, sub, nil
}
