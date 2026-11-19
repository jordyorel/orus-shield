// Package webhook delivers the outgoing webhooks that scans leave in the
// webhook_deliveries outbox (migration 0032): signed JSON POSTs to the
// HTTPS endpoints customers declared in Réglages > API.
//
// It runs in the worker process, like package notify: each pass leases due
// deliveries, sends them, and records the outcome (delivered, retried later
// with a growing delay, or abandoned).
//
// The URL is the customer's: everything about the request is bounded. Only
// public addresses are dialed (the URL's name is resolved here and every
// private, loopback or link-local answer is refused: server-side request
// forgery), only HTTPS, no redirect followed, 10 seconds at most, the
// answer read up to 64 KB and discarded.
package webhook

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/jordyorel/orus-shield/engine/internal/quicktest"
	"github.com/jordyorel/orus-shield/engine/internal/seal"
	"github.com/jordyorel/orus-shield/engine/internal/store"
)

// Store is the part of store.Store the deliverer uses.
type Store interface {
	ClaimWebhookDeliveries(ctx context.Context, now time.Time, lease time.Duration, limit int) ([]store.WebhookDelivery, error)
	FinishWebhookDelivery(ctx context.Context, d store.WebhookDelivery, o store.DeliveryOutcome, at time.Time) error
	WebhooksAllowed(ctx context.Context, orgID string, now time.Time) (bool, error)
}

const (
	lease   = 2 * time.Minute
	batch   = 20
	timeout = 10 * time.Second
	// maxAge: a delivery older than this is dropped (the endpoint was down
	// for a day; the dashboard and the API have the data anyway).
	maxAge = 24 * time.Hour
	// DefaultInterval is the wait between passes.
	DefaultInterval = 10 * time.Second
	maxAnswer       = 64 << 10
)

// retryDelays are the waits after the 1st, 2nd... failed attempt.
var retryDelays = []time.Duration{time.Minute, 5 * time.Minute, 30 * time.Minute, 2 * time.Hour}

// Sign returns the Orus-Signature header of body sent at t: the Unix time
// and the HMAC-SHA256, in hex, of "<time>.<body>" with the endpoint's
// secret. Receivers recompute it, compare in constant time, and refuse an
// old time (replay).
func Sign(secret, body []byte, t time.Time) string {
	ts := strconv.FormatInt(t.Unix(), 10)
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(ts))
	mac.Write([]byte("."))
	mac.Write(body)
	return "t=" + ts + ",v1=" + hex.EncodeToString(mac.Sum(nil))
}

// Deliverer sends the outbox.
type Deliverer struct {
	store  Store
	key    *seal.Key
	client *http.Client
	log    *slog.Logger
	now    func() time.Time
}

// New returns a deliverer. key opens endpoints' secrets
// (ORUS_CREDENTIALS_KEY).
func New(st Store, key *seal.Key, log *slog.Logger) *Deliverer {
	return &Deliverer{store: st, key: key, client: SafeClient(nil), log: log, now: time.Now}
}

// SafeClient is an HTTP client for customers' URLs: it dials public
// addresses only (allow decides; nil means quicktest.Public), never
// follows a redirect, and gives up after the timeout.
func SafeClient(allow func(netip.Addr) bool) *http.Client {
	if allow == nil {
		allow = quicktest.Public
	}
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	tr := &http.Transport{
		Proxy: nil, // never through a proxy from the environment
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
			if err != nil {
				return nil, err
			}
			for _, ip := range ips {
				if allow(ip) {
					return dialer.DialContext(ctx, network, net.JoinHostPort(ip.Unmap().String(), port))
				}
			}
			return nil, fmt.Errorf("%s has no public address", host)
		},
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: timeout,
		MaxIdleConns:          10,
		IdleConnTimeout:       30 * time.Second,
	}
	return &http.Client{
		Transport: tr,
		Timeout:   timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// Run delivers every interval until ctx ends.
func (d *Deliverer) Run(ctx context.Context, interval time.Duration) {
	for {
		if _, err := d.RunOnce(ctx); err != nil && ctx.Err() == nil {
			d.log.Error("deliver webhooks", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(interval):
		}
	}
}

// RunOnce makes one pass and returns the number of deliveries made.
func (d *Deliverer) RunOnce(ctx context.Context) (int, error) {
	now := d.now()
	due, err := d.store.ClaimWebhookDeliveries(ctx, now, lease, batch)
	if err != nil {
		return 0, err
	}
	sent := 0
	for _, del := range due {
		if ctx.Err() != nil {
			return sent, ctx.Err()
		}
		o := d.attempt(ctx, del, now)
		if err := d.store.FinishWebhookDelivery(ctx, del, o, d.now()); err != nil {
			return sent, err
		}
		if o.Delivered {
			sent++
		}
	}
	return sent, nil
}

// attempt sends one delivery and says what to record.
func (d *Deliverer) attempt(ctx context.Context, del store.WebhookDelivery, now time.Time) store.DeliveryOutcome {
	if now.Sub(del.CreatedAt) > maxAge {
		return store.DeliveryOutcome{Error: "too old to send"}
	}
	allowed, err := d.store.WebhooksAllowed(ctx, del.OrgID, now)
	if err != nil {
		return d.retry(del, 0, err.Error(), now)
	}
	if !allowed {
		return store.DeliveryOutcome{Error: "the offer no longer includes webhooks"}
	}
	secret, err := d.key.Open(del.SecretSealed, store.WebhookSealOwner(del.OrgID, del.URL))
	if err != nil {
		return store.DeliveryOutcome{Error: "the endpoint's secret cannot be opened"}
	}
	status, err := d.send(ctx, del, secret)
	if err == nil && status >= 200 && status < 300 {
		return store.DeliveryOutcome{Delivered: true, Status: status}
	}
	msg := fmt.Sprintf("HTTP %d", status)
	if err != nil {
		msg = err.Error()
	}
	return d.retry(del, status, msg, now)
}

func (d *Deliverer) retry(del store.WebhookDelivery, status int, msg string, now time.Time) store.DeliveryOutcome {
	o := store.DeliveryOutcome{Status: status, Error: msg}
	if del.Attempts <= len(retryDelays) {
		t := now.Add(retryDelays[del.Attempts-1])
		o.RetryAt = &t
	}
	return o
}

// send POSTs the delivery and returns the answer's status.
func (d *Deliverer) send(ctx context.Context, del store.WebhookDelivery, secret []byte) (int, error) {
	u, err := url.Parse(del.URL)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return 0, errors.New("the URL must be https")
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), strings.NewReader(string(del.Payload)))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "OrusShield-Webhooks/1.0")
	req.Header.Set("Orus-Event", del.EventType)
	req.Header.Set("Orus-Delivery", del.ID)
	req.Header.Set("Orus-Signature", Sign(secret, del.Payload, d.now()))
	resp, err := d.client.Do(req)
	if err != nil {
		return 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxAnswer))
	return resp.StatusCode, nil
}
