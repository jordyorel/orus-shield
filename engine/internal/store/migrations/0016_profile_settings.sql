-- 0016: what the new dashboard (2026-11-12) needs from accounts and
-- organizations.
--
-- users.name: the name the dashboard greets ("Bonjour Jordy"), set by the
-- user in Profil. Empty until then.
ALTER TABLE users ADD COLUMN name text NOT NULL DEFAULT ''
    CHECK (length(name) <= 100 AND name = btrim(name));
GRANT UPDATE (name) ON users TO orus_auth;

-- sessions.id: a public identifier, so Profil > Appareils connectés can
-- end one session. The token hash stays private: it is what a stolen
-- database dump would be matched against.
ALTER TABLE sessions ADD COLUMN id uuid NOT NULL DEFAULT uuidv7();
CREATE UNIQUE INDEX sessions_by_id ON sessions (id);

-- Profil > Activité récente reads the user's own auth log.
CREATE INDEX auth_log_by_user ON auth_log (user_id, at) WHERE user_id IS NOT NULL;

-- org_settings: the organization-wide choices of Réglages. No row means
-- the defaults below. Schedules and rates still live on each target (the
-- worker reads them there); saving these settings rewrites every target's
-- schedule and rate, and new targets start from them.
CREATE TABLE org_settings (
    org_id      uuid PRIMARY KEY REFERENCES organizations (id) ON DELETE CASCADE,
    -- Lowest severity that sends an alert: critical, high, or all
    -- (medium and low too).
    alert_level text NOT NULL DEFAULT 'high' CHECK (alert_level IN ('critical', 'high', 'all')),
    email_alerts boolean NOT NULL DEFAULT true,
    -- quick: passive checks and ports, without the long known-vulnerability
    -- pass; standard: everything.
    profile     text NOT NULL DEFAULT 'standard' CHECK (profile IN ('quick', 'standard')),
    -- Modules the customer switched off (module IDs).
    disabled_modules text[] NOT NULL DEFAULT '{}' CHECK (cardinality(disabled_modules) <= 20),
    -- The schedule applied to every target; NULL frequency: none chosen yet.
    frequency   text CHECK (frequency IN ('daily', 'weekly', 'monthly')),
    weekday     smallint NOT NULL DEFAULT 6 CHECK (weekday BETWEEN 0 AND 6),
    hour        smallint NOT NULL DEFAULT 2 CHECK (hour BETWEEN 0 AND 23),
    timezone    text NOT NULL DEFAULT 'UTC' CHECK (length(timezone) BETWEEN 1 AND 64),
    rate_per_sec integer NOT NULL DEFAULT 0 CHECK (rate_per_sec BETWEEN 0 AND 200),
    updated_at  timestamptz NOT NULL DEFAULT now()
);

GRANT SELECT, INSERT, UPDATE ON org_settings TO orus_app;

ALTER TABLE org_settings ENABLE ROW LEVEL SECURITY;
ALTER TABLE org_settings FORCE ROW LEVEL SECURITY;
CREATE POLICY org_isolation ON org_settings
    USING (org_id = nullif(current_setting('app.org_id', true), '')::uuid)
    WITH CHECK (org_id = nullif(current_setting('app.org_id', true), '')::uuid);
