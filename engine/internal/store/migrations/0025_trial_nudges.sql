-- 0025: trial reminders after the free audit, and unsubscribing from them.
--
-- When the single audit of the free offer finishes, FinishScan also queues
-- two reminders per activated admin (kind trial_nudge), due 3 and 10 days
-- later: their created_at is the day they are due, so the notifier's age
-- limit counts from then. At delivery the notifier checks they still make
-- sense (still on the free offer, never a paid offer or trial, not
-- unsubscribed); otherwise they are dropped.
--
-- Reminders are commercial email: each carries a one-click unsubscribe
-- link. Its token is random; only its SHA-256 is stored here. Unsubscribing
-- is per address and stops every future reminder; alerts and summaries,
-- which follow the Réglages email switch, are not affected.
ALTER TABLE notifications DROP CONSTRAINT notifications_kind_check;
ALTER TABLE notifications ADD CONSTRAINT notifications_kind_check
    CHECK (kind IN ('new_findings', 'emerging_threat', 'first_scan', 'trial_nudge'));

CREATE TABLE unsubscribe_tokens (
    token_hash bytea PRIMARY KEY,
    email      text NOT NULL CHECK (length(email) BETWEEN 3 AND 254),
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE marketing_optouts (
    email text PRIMARY KEY CHECK (length(email) BETWEEN 3 AND 254),
    at    timestamptz NOT NULL DEFAULT now()
);

-- The public unsubscribe endpoint runs as orus_auth: it reads a token's
-- address and records the opt-out, nothing else.
GRANT SELECT ON unsubscribe_tokens TO orus_auth;
GRANT SELECT, INSERT ON marketing_optouts TO orus_auth;
