-- 0027: checkouts waiting for their payment.
--
-- The API records each Paddle transaction it creates for a checkout. While
-- the organization has no paid offer in force, reading its subscription
-- asks Paddle about its latest checkout and records the subscription as soon
-- as it is paid: the trial starts even when the webhook is late or lost and
-- the customer never saw the return page (inline checkout, tab closed).
-- A checkout is forgotten once applied, or after two days.
CREATE TABLE pending_checkouts (
    org_id         uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    transaction_id text NOT NULL CHECK (transaction_id LIKE 'txn\_%' AND length(transaction_id) <= 100),
    created_at     timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, transaction_id)
);

GRANT SELECT, INSERT, DELETE ON pending_checkouts TO orus_app;

ALTER TABLE pending_checkouts ENABLE ROW LEVEL SECURITY;
ALTER TABLE pending_checkouts FORCE ROW LEVEL SECURITY;
CREATE POLICY org_isolation ON pending_checkouts
    USING (org_id = nullif(current_setting('app.org_id', true), '')::uuid)
    WITH CHECK (org_id = nullif(current_setting('app.org_id', true), '')::uuid);
