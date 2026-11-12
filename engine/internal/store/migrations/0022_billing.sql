-- 0022: card payments with Paddle (step F).
--
-- Paddle's webhooks update subscriptions. The API receives them, checks
-- their signature, and writes through the orus_billing role (store.Billing):
-- subscriptions and their audit entries, nothing else. billing_events keeps
-- every event ID handled, so a webhook Paddle sends twice applies once.
ALTER TABLE subscriptions ADD COLUMN provider_customer text CHECK (length(provider_customer) <= 200);

CREATE TABLE billing_events (
    event_id    text PRIMARY KEY CHECK (length(event_id) BETWEEN 1 AND 200),
    event_type  text NOT NULL CHECK (length(event_type) <= 100),
    org_id      uuid,
    received_at timestamptz NOT NULL DEFAULT now()
);

DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'orus_billing') THEN
        CREATE ROLE orus_billing NOLOGIN NOSUPERUSER NOBYPASSRLS;
    END IF;
EXCEPTION
    WHEN duplicate_object OR unique_violation THEN NULL;
END;
$$;
GRANT orus_billing TO CURRENT_USER;
DO $$
BEGIN
    EXECUTE format('GRANT USAGE ON SCHEMA %I TO orus_billing', current_schema());
END;
$$;

GRANT SELECT, INSERT, UPDATE ON subscriptions TO orus_billing;
CREATE POLICY billing_subscriptions ON subscriptions TO orus_billing USING (true) WITH CHECK (true);
GRANT SELECT (id) ON organizations TO orus_billing;
CREATE POLICY billing_read_orgs ON organizations FOR SELECT TO orus_billing USING (true);
GRANT INSERT ON billing_events TO orus_billing;
GRANT INSERT ON audit_log TO orus_billing;
CREATE POLICY billing_audit ON audit_log FOR INSERT TO orus_billing WITH CHECK (true);
