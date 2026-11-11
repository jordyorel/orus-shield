// Package notify delivers the email notifications that scans leave in the
// outbox (store table notifications): alerts about new critical and high
// findings.
//
// It runs in the worker process. Each pass claims due notifications with a
// lease, sends them, and records the outcome: sent, retried later with a
// growing delay, or abandoned after too many attempts or when too old to be
// useful. Several workers can run it together; the store's lease keeps a
// notification with one of them at a time.
package notify

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/jordyorel/orus-shield/engine/internal/mailer"
	"github.com/jordyorel/orus-shield/engine/internal/store"
)

// Store is the part of store.Store the notifier uses.
type Store interface {
	ClaimNotifications(ctx context.Context, now time.Time, lease time.Duration, limit int) ([]store.Notification, error)
	MarkNotificationSent(ctx context.Context, id string, at time.Time) error
	RetryNotification(ctx context.Context, id, reason string, retryAt time.Time) error
	AbandonNotification(ctx context.Context, id, reason string, at time.Time) error
}

const (
	// lease is how long a claimed notification is kept from other workers;
	// longer than one delivery attempt (mailer timeout 30s).
	lease = 5 * time.Minute
	// batch bounds the notifications handled per pass.
	batch = 20
	// maxAge: an alert older than this is dropped rather than sent late
	// (mail was down for a day; the dashboard shows the findings anyway).
	maxAge = 24 * time.Hour
	// DefaultInterval is the wait between passes.
	DefaultInterval = 15 * time.Second
)

// retryDelays are the waits after the 1st, 2nd... failed attempt; after the
// last one the notification is abandoned.
var retryDelays = []time.Duration{time.Minute, 5 * time.Minute, 30 * time.Minute, 2 * time.Hour}

// Notifier sends the outbox.
type Notifier struct {
	store     Store
	mail      mailer.Sender
	publicURL string
	log       *slog.Logger
	now       func() time.Time
}

// New returns a notifier. publicURL is the dashboard's address, for links.
func New(st Store, mail mailer.Sender, publicURL string, log *slog.Logger) *Notifier {
	return &Notifier{store: st, mail: mail, publicURL: publicURL, log: log, now: time.Now}
}

// Run delivers notifications every interval until ctx ends.
func (n *Notifier) Run(ctx context.Context, interval time.Duration) {
	for {
		if _, err := n.RunOnce(ctx); err != nil && ctx.Err() == nil {
			n.log.Error("deliver notifications", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(interval):
		}
	}
}

// RunOnce makes one pass and returns the number of emails sent.
func (n *Notifier) RunOnce(ctx context.Context) (int, error) {
	now := n.now()
	due, err := n.store.ClaimNotifications(ctx, now, lease, batch)
	if err != nil {
		return 0, err
	}
	sent := 0
	for _, nt := range due {
		if ctx.Err() != nil {
			return sent, ctx.Err() // the lease returns the rest to the queue
		}
		if now.Sub(nt.CreatedAt) > maxAge {
			if err := n.store.AbandonNotification(ctx, nt.ID, "too old to send", now); err != nil {
				return sent, err
			}
			continue
		}
		m, err := n.message(nt)
		if err != nil {
			// A payload we cannot read will not get better: give up.
			if err := n.store.AbandonNotification(ctx, nt.ID, err.Error(), now); err != nil {
				return sent, err
			}
			continue
		}
		if err := n.mail.Send(ctx, m); err != nil {
			if err := n.failed(ctx, nt, err, now); err != nil {
				return sent, err
			}
			continue
		}
		if err := n.store.MarkNotificationSent(ctx, nt.ID, n.now()); err != nil {
			return sent, err
		}
		sent++
	}
	if sent > 0 {
		n.log.Info("notifications sent", "count", sent)
	}
	return sent, nil
}

// failed schedules the next attempt, or abandons after the last one. The
// error is logged without the recipient (customer data stays out of logs).
func (n *Notifier) failed(ctx context.Context, nt store.Notification, sendErr error, now time.Time) error {
	n.log.Warn("notification delivery failed", "notification", nt.ID, "attempt", nt.Attempts, "err", sendErr)
	if nt.Attempts > len(retryDelays) {
		return n.store.AbandonNotification(ctx, nt.ID, "gave up: "+sendErr.Error(), now)
	}
	return n.store.RetryNotification(ctx, nt.ID, sendErr.Error(), now.Add(retryDelays[nt.Attempts-1]))
}

// message builds the email of a notification.
func (n *Notifier) message(nt store.Notification) (mailer.Message, error) {
	if nt.Kind != store.NotifyNewFindings {
		return mailer.Message{}, fmt.Errorf("unknown notification kind %q", nt.Kind)
	}
	var a store.NewFindingsAlert
	if err := json.Unmarshal(nt.Payload, &a); err != nil {
		return mailer.Message{}, fmt.Errorf("read payload: %w", err)
	}
	items := make([]mailer.AlertItem, 0, len(a.Findings))
	for _, f := range a.Findings {
		items = append(items, mailer.AlertItem{
			Severity: string(f.Severity), Title: f.Title, Asset: f.Asset, Reopened: f.Reopened,
			Link: mailer.FindingsLink(n.publicURL, a.OrgID, f.ID),
		})
	}
	return mailer.NewFindings(nt.Recipient, a.OrgName, a.Domain, items, a.Total, mailer.FindingsLink(n.publicURL, a.OrgID, "")), nil
}
