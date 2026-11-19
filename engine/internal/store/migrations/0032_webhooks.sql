-- 0032: outgoing webhooks (Réglages > API, offers with plan.PublicAPI).
--
-- An organization's admin declares HTTPS endpoints and the events each one
-- receives. Every delivery is a JSON POST signed with the endpoint's secret
-- (HMAC-SHA256, header Orus-Signature), so the receiver can check it comes
-- from us. The secret is sealed with ORUS_CREDENTIALS_KEY (package seal,
-- bound to the endpoint): the API seals it at creation and shows it once,
-- the worker opens it to sign; it is never readable back through the API.
--
-- FinishScan queues the deliveries of a scan's events in the same
-- transaction as its results (webhook_deliveries, an outbox like
-- notifications); the worker delivers them with a lease and retries.
CREATE TABLE webhooks (
    id               uuid PRIMARY KEY DEFAULT uuidv7(),
    org_id           uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    url              text NOT NULL CHECK (url LIKE 'https://%' AND length(url) <= 2000),
    events           text[] NOT NULL CHECK (cardinality(events) BETWEEN 1 AND 10),
    secret_sealed    bytea NOT NULL CHECK (length(secret_sealed) <= 200),
    created_by       text NOT NULL CHECK (length(created_by) <= 300),
    created_at       timestamptz NOT NULL DEFAULT now(),
    last_delivery_at timestamptz,
    last_status      integer,
    last_error       text CHECK (length(last_error) <= 500)
);
CREATE INDEX webhooks_org ON webhooks (org_id, created_at);

CREATE TABLE webhook_deliveries (
    id              uuid PRIMARY KEY DEFAULT uuidv7(),
    org_id          uuid NOT NULL,
    webhook_id      uuid NOT NULL REFERENCES webhooks (id) ON DELETE CASCADE,
    event_type      text NOT NULL CHECK (length(event_type) <= 50),
    payload         jsonb NOT NULL CHECK (octet_length(payload::text) <= 262144),
    created_at      timestamptz NOT NULL DEFAULT now(),
    attempts        integer NOT NULL DEFAULT 0,
    next_attempt_at timestamptz NOT NULL DEFAULT now(),
    locked_until    timestamptz,
    delivered_at    timestamptz,
    abandoned_at    timestamptz,
    last_status     integer,
    last_error      text CHECK (length(last_error) <= 500)
);
CREATE INDEX webhook_deliveries_due ON webhook_deliveries (next_attempt_at)
    WHERE delivered_at IS NULL AND abandoned_at IS NULL;
CREATE INDEX webhook_deliveries_hook ON webhook_deliveries (webhook_id, created_at DESC);

-- The API (orus_app) manages endpoints and queues test deliveries; it can
-- write the sealed secret but not read it back.
GRANT SELECT (id, org_id, url, events, created_by, created_at, last_delivery_at, last_status, last_error) ON webhooks TO orus_app;
GRANT INSERT, DELETE ON webhooks TO orus_app;
ALTER TABLE webhooks ENABLE ROW LEVEL SECURITY;
ALTER TABLE webhooks FORCE ROW LEVEL SECURITY;
CREATE POLICY org_isolation ON webhooks
    USING (org_id = nullif(current_setting('app.org_id', true), '')::uuid)
    WITH CHECK (org_id = nullif(current_setting('app.org_id', true), '')::uuid);

GRANT SELECT (id, org_id, webhook_id, event_type, created_at, attempts, delivered_at, abandoned_at, last_status, last_error) ON webhook_deliveries TO orus_app;
GRANT INSERT ON webhook_deliveries TO orus_app;
ALTER TABLE webhook_deliveries ENABLE ROW LEVEL SECURITY;
ALTER TABLE webhook_deliveries FORCE ROW LEVEL SECURITY;
CREATE POLICY org_isolation ON webhook_deliveries
    USING (org_id = nullif(current_setting('app.org_id', true), '')::uuid)
    WITH CHECK (org_id = nullif(current_setting('app.org_id', true), '')::uuid);
