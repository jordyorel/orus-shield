-- 0012: email notifications (outbox).
--
-- FinishScan writes one row per recipient, in the scan's transaction, when
-- a scan opens or reopens findings worth an alert. A sender loop (in the
-- worker process) delivers them: a scan's results and its alerts are never
-- out of step, and a crash between the two loses or duplicates nothing.
-- Delivery is claimed with a lease (next_attempt_at moves forward first),
-- so several workers can share the outbox.
CREATE TABLE notifications (
    id              uuid PRIMARY KEY DEFAULT uuidv7(),
    org_id          uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    target_id       uuid NOT NULL,
    scan_id         uuid NOT NULL,
    kind            text NOT NULL CHECK (kind IN ('new_findings')),
    recipient       text NOT NULL CHECK (length(recipient) BETWEEN 3 AND 254),
    payload         jsonb NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    attempts        integer NOT NULL DEFAULT 0,
    next_attempt_at timestamptz NOT NULL DEFAULT now(),
    sent_at         timestamptz,
    -- Set when delivery is abandoned after too many attempts.
    failed_at       timestamptz,
    last_error      text CHECK (length(last_error) <= 2000),
    FOREIGN KEY (org_id, target_id) REFERENCES targets (org_id, id) ON DELETE CASCADE
);

CREATE INDEX notifications_pending ON notifications (next_attempt_at)
    WHERE sent_at IS NULL AND failed_at IS NULL;

-- Written and read by the worker only; the API has no access. Row-level
-- security as everywhere else, so a future grant cannot leak across
-- organizations.
ALTER TABLE notifications ENABLE ROW LEVEL SECURITY;
ALTER TABLE notifications FORCE ROW LEVEL SECURITY;
CREATE POLICY org_isolation ON notifications
    USING (org_id = nullif(current_setting('app.org_id', true), '')::uuid)
    WITH CHECK (org_id = nullif(current_setting('app.org_id', true), '')::uuid);
