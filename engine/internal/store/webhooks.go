package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/jordyorel/orus-shield/engine/internal/plan"
)

// Outgoing webhooks (migration 0032). An endpoint receives the events it
// subscribed to, as signed JSON POSTs delivered by the worker (package
// webhook) from the webhook_deliveries outbox.

// Webhook events.
const (
	EventFindingOpened = "finding.opened" // a finding is new, or back after a fix
	EventFindingFixed  = "finding.fixed"  // a scan no longer saw it
	EventScanFinished  = "scan.finished"  // a scan's summary
	EventPing          = "ping"           // "Envoyer un test"
)

// WebhookEvents are the events an endpoint may subscribe to.
var WebhookEvents = []string{EventFindingOpened, EventFindingFixed, EventScanFinished}

// Audit actions of webhooks.
const (
	ActionWebhookCreated = "webhook.created"
	ActionWebhookDeleted = "webhook.deleted"
)

const (
	// MaxWebhooks bounds the endpoints of one organization.
	MaxWebhooks = 10
	// maxEventsPerScan bounds the per-finding events one scan queues for
	// one endpoint (a first scan may open many findings); scan.finished
	// still gives the totals.
	maxEventsPerScan = 100
)

var (
	// ErrTooManyWebhooks: the organization has MaxWebhooks endpoints.
	ErrTooManyWebhooks = errors.New("too many webhooks")
	// ErrBadWebhook: an unusable URL or event list.
	ErrBadWebhook = errors.New("a webhook needs an https URL and at least one known event")
)

// Webhook is an endpoint as the organization sees it (never its secret).
type Webhook struct {
	ID             string
	URL            string
	Events         []string
	CreatedBy      string
	CreatedAt      time.Time
	LastDeliveryAt *time.Time
	LastStatus     *int
	LastError      *string
}

// WebhookSealOwner binds a sealed secret to its organization and URL: a
// sealed value copied onto another row does not open.
func WebhookSealOwner(orgID, url string) string { return "webhook:" + orgID + ":" + url }

const webhookColumns = "id::text, url, events, created_by, created_at, last_delivery_at, last_status, last_error"

func scanWebhook(row pgx.CollectableRow) (Webhook, error) {
	var w Webhook
	err := row.Scan(&w.ID, &w.URL, &w.Events, &w.CreatedBy, &w.CreatedAt, &w.LastDeliveryAt, &w.LastStatus, &w.LastError)
	return w, err
}

// CreateWebhook records an endpoint whose secret the caller already
// sealed (WebhookSealOwner). url must be https; events known ones.
func (o *Org) CreateWebhook(ctx context.Context, url string, events []string, sealed []byte, actor string) (Webhook, error) {
	if len(url) < 9 || len(url) > 2000 || url[:8] != "https://" || len(events) == 0 {
		return Webhook{}, ErrBadWebhook
	}
	for _, e := range events {
		if !slices.Contains(WebhookEvents, e) {
			return Webhook{}, ErrBadWebhook
		}
	}
	events = slices.Compact(slices.Sorted(slices.Values(events)))
	tx, err := o.begin(ctx)
	if err != nil {
		return Webhook{}, fmt.Errorf("create webhook: %w", err)
	}
	defer tx.Rollback(ctx)
	var n int
	if err := tx.QueryRow(ctx, "SELECT count(*) FROM webhooks").Scan(&n); err != nil {
		return Webhook{}, fmt.Errorf("create webhook: %w", err)
	}
	if n >= MaxWebhooks {
		return Webhook{}, ErrTooManyWebhooks
	}
	rows, err := tx.Query(ctx, `INSERT INTO webhooks (org_id, url, events, secret_sealed, created_by)
		VALUES ($1, $2, $3, $4, $5) RETURNING `+webhookColumns, o.orgID, url, events, sealed, actor)
	if err != nil {
		return Webhook{}, fmt.Errorf("create webhook: %w", err)
	}
	w, err := pgx.CollectExactlyOneRow(rows, scanWebhook)
	if err != nil {
		return Webhook{}, fmt.Errorf("create webhook: %w", err)
	}
	if err := appendAudit(ctx, tx, AuditEntry{OrgID: o.orgID, Actor: actor, Action: ActionWebhookCreated, Target: "api",
		Details: map[string]any{"webhook_id": w.ID, "url": url, "events": events}}); err != nil {
		return Webhook{}, err
	}
	return w, tx.Commit(ctx)
}

// Webhooks lists the organization's endpoints, oldest first.
func (o *Org) Webhooks(ctx context.Context) ([]Webhook, error) {
	tx, err := o.begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("list webhooks: %w", err)
	}
	defer tx.Rollback(ctx)
	rows, err := tx.Query(ctx, "SELECT "+webhookColumns+" FROM webhooks ORDER BY created_at")
	if err != nil {
		return nil, fmt.Errorf("list webhooks: %w", err)
	}
	hooks, err := pgx.CollectRows(rows, scanWebhook)
	if err != nil {
		return nil, fmt.Errorf("list webhooks: %w", err)
	}
	return hooks, tx.Commit(ctx)
}

// DeleteWebhook removes an endpoint and its pending deliveries. Another
// organization's endpoint is ErrNotFound.
func (o *Org) DeleteWebhook(ctx context.Context, id, actor string) error {
	if !isUUID(id) {
		return ErrNotFound
	}
	tx, err := o.begin(ctx)
	if err != nil {
		return fmt.Errorf("delete webhook: %w", err)
	}
	defer tx.Rollback(ctx)
	var url string
	err = tx.QueryRow(ctx, "DELETE FROM webhooks WHERE id = $1 RETURNING url", id).Scan(&url)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("delete webhook: %w", err)
	}
	if err := appendAudit(ctx, tx, AuditEntry{OrgID: o.orgID, Actor: actor, Action: ActionWebhookDeleted, Target: "api",
		Details: map[string]any{"webhook_id": id, "url": url}}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// QueueWebhookPing queues a "ping" event to one endpoint, to check it.
func (o *Org) QueueWebhookPing(ctx context.Context, id string, at time.Time) error {
	if !isUUID(id) {
		return ErrNotFound
	}
	tx, err := o.begin(ctx)
	if err != nil {
		return fmt.Errorf("ping webhook: %w", err)
	}
	defer tx.Rollback(ctx)
	var exists bool
	if err := tx.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM webhooks WHERE id = $1)", id).Scan(&exists); err != nil {
		return fmt.Errorf("ping webhook: %w", err)
	}
	if !exists {
		return ErrNotFound
	}
	if err := insertDelivery(ctx, tx, o.orgID, id, EventPing, map[string]any{"message": "Orus Shield webhook test"}, at); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// insertDelivery queues one event to one endpoint. The payload is the
// envelope the receiver gets: id, type, created_at, data.
func insertDelivery(ctx context.Context, tx pgx.Tx, orgID, webhookID, event string, data any, at time.Time) error {
	evID, err := randomHex(12)
	if err != nil {
		return err
	}
	body, err := json.Marshal(map[string]any{"id": "evt_" + evID, "type": event, "created_at": at.UTC(), "org_id": orgID, "data": data})
	if err != nil {
		return fmt.Errorf("webhook payload: %w", err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO webhook_deliveries (org_id, webhook_id, event_type, payload) VALUES ($1, $2, $3, $4)`,
		orgID, webhookID, event, body); err != nil {
		return fmt.Errorf("queue webhook: %w", err)
	}
	return nil
}

// WebhookFinding is a finding as webhook events carry it.
type WebhookFinding struct {
	ID       string `json:"id"`
	ModuleID string `json:"module_id"`
	CheckID  string `json:"check_id"`
	Severity string `json:"severity"`
	Title    string `json:"title"`
	TitleFR  string `json:"title_fr,omitempty"`
	Asset    string `json:"asset"`
	Reopened bool   `json:"reopened,omitempty"`
}

// scanEvents is what FinishScan hands to queueWebhookEvents.
type scanEvents struct {
	orgID, targetID, scanID, domain string
	at                              time.Time
	opened, fixed                   []WebhookFinding
	score                           *int
	findings                        int
}

// queueWebhookEvents queues a scan's events to every endpoint subscribed
// to them, in FinishScan's transaction. Whether the offer still includes
// webhooks is checked at delivery (WebhooksAllowed).
func queueWebhookEvents(ctx context.Context, tx pgx.Tx, e scanEvents) (int, error) {
	rows, err := tx.Query(ctx, "SELECT id::text, events FROM webhooks WHERE org_id = $1", e.orgID)
	if err != nil {
		return 0, fmt.Errorf("list webhooks: %w", err)
	}
	type hook struct {
		id     string
		events []string
	}
	hooks, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (hook, error) {
		var h hook
		err := row.Scan(&h.id, &h.events)
		return h, err
	})
	if err != nil {
		return 0, fmt.Errorf("list webhooks: %w", err)
	}
	queued := 0
	scan := map[string]any{"scan_id": e.scanID, "target_id": e.targetID, "domain": e.domain}
	for _, h := range hooks {
		for _, kind := range []struct {
			event string
			list  []WebhookFinding
		}{{EventFindingOpened, e.opened}, {EventFindingFixed, e.fixed}} {
			if !slices.Contains(h.events, kind.event) {
				continue
			}
			for i, f := range kind.list {
				if i == maxEventsPerScan {
					break
				}
				data := map[string]any{"finding": f}
				for k, v := range scan {
					data[k] = v
				}
				if err := insertDelivery(ctx, tx, e.orgID, h.id, kind.event, data, e.at); err != nil {
					return queued, err
				}
				queued++
			}
		}
		if slices.Contains(h.events, EventScanFinished) {
			data := map[string]any{"score": e.score, "findings": e.findings, "opened": len(e.opened), "fixed": len(e.fixed)}
			for k, v := range scan {
				data[k] = v
			}
			if err := insertDelivery(ctx, tx, e.orgID, h.id, EventScanFinished, data, e.at); err != nil {
				return queued, err
			}
			queued++
		}
	}
	return queued, nil
}

// WebhookDelivery is a delivery claimed by the worker, with what it needs
// to send it.
type WebhookDelivery struct {
	ID, OrgID, WebhookID, EventType string
	Payload                         []byte
	Attempts                        int // including this one
	CreatedAt                       time.Time
	URL                             string
	SecretSealed                    []byte
}

// ClaimWebhookDeliveries leases up to limit due deliveries (worker).
func (s *Store) ClaimWebhookDeliveries(ctx context.Context, now time.Time, lease time.Duration, limit int) ([]WebhookDelivery, error) {
	rows, err := s.pool.Query(ctx, `
		WITH due AS (
			SELECT d.id FROM webhook_deliveries d
			WHERE d.delivered_at IS NULL AND d.abandoned_at IS NULL AND d.next_attempt_at <= $1
				AND (d.locked_until IS NULL OR d.locked_until < $1)
			ORDER BY d.next_attempt_at LIMIT $3
			FOR UPDATE SKIP LOCKED
		)
		UPDATE webhook_deliveries d SET attempts = d.attempts + 1, locked_until = $1::timestamptz + $2::interval
		FROM due, webhooks w
		WHERE d.id = due.id AND w.id = d.webhook_id
		RETURNING d.id::text, d.org_id::text, d.webhook_id::text, d.event_type, d.payload, d.attempts, d.created_at, w.url, w.secret_sealed`,
		now, lease.String(), limit)
	if err != nil {
		return nil, fmt.Errorf("claim webhook deliveries: %w", err)
	}
	out, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (WebhookDelivery, error) {
		var d WebhookDelivery
		err := row.Scan(&d.ID, &d.OrgID, &d.WebhookID, &d.EventType, &d.Payload, &d.Attempts, &d.CreatedAt, &d.URL, &d.SecretSealed)
		return d, err
	})
	if err != nil {
		return nil, fmt.Errorf("claim webhook deliveries: %w", err)
	}
	return out, nil
}

// DeliveryOutcome is the result of one attempt.
type DeliveryOutcome struct {
	Delivered bool
	Status    int        // HTTP status, 0 when no answer
	Error     string     // why it failed, "" when delivered
	RetryAt   *time.Time // next attempt; nil with Delivered or to abandon
}

// FinishWebhookDelivery records an attempt on the delivery and its
// endpoint's last status.
func (s *Store) FinishWebhookDelivery(ctx context.Context, d WebhookDelivery, o DeliveryOutcome, at time.Time) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("finish webhook delivery: %w", err)
	}
	defer tx.Rollback(ctx)
	status := &o.Status
	if o.Status == 0 {
		status = nil
	}
	errText := truncateRunes(o.Error, 500)
	switch {
	case o.Delivered:
		_, err = tx.Exec(ctx, `UPDATE webhook_deliveries SET delivered_at = $2, locked_until = NULL, last_status = $3, last_error = NULL WHERE id = $1`, d.ID, at, status)
	case o.RetryAt != nil:
		_, err = tx.Exec(ctx, `UPDATE webhook_deliveries SET next_attempt_at = $2, locked_until = NULL, last_status = $3, last_error = $4 WHERE id = $1`, d.ID, *o.RetryAt, status, errText)
	default:
		_, err = tx.Exec(ctx, `UPDATE webhook_deliveries SET abandoned_at = $2, locked_until = NULL, last_status = $3, last_error = $4 WHERE id = $1`, d.ID, at, status, errText)
	}
	if err != nil {
		return fmt.Errorf("finish webhook delivery: %w", err)
	}
	if _, err := tx.Exec(ctx, `UPDATE webhooks SET last_delivery_at = $2, last_status = $3, last_error = nullif($4, '') WHERE id = $1`,
		d.WebhookID, at, status, errText); err != nil {
		return fmt.Errorf("finish webhook delivery: %w", err)
	}
	return tx.Commit(ctx)
}

// WebhooksAllowed reports whether the organization's offer in force still
// includes webhooks (plan.PublicAPI): a lapsed trial's deliveries are
// dropped.
func (s *Store) WebhooksAllowed(ctx context.Context, orgID string, now time.Time) (bool, error) {
	sub, err := s.SubscriptionOf(ctx, orgID)
	if err != nil {
		return false, fmt.Errorf("webhooks allowed: %w", err)
	}
	return plan.Resolve(sub, now).Plan.PublicAPI, nil
}
