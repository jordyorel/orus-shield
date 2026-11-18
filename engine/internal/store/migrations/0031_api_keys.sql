-- 0031: API keys (Réglages > API, offers with plan.PublicAPI).
--
-- An organization's admin creates a key for the organization's own tools.
-- The key itself is shown once and never stored: only its SHA-256, like
-- agent tokens. prefix (its first characters) lets the customer recognize
-- it. scope "read" reads the organization's results; "write" also starts
-- scans and marks findings. Managing members, billing, test accounts or
-- keys is never possible with a key, only with a signed-in admin.
--
-- The organization manages its keys through orus_app (row-level security);
-- the API looks a presented key up through orus_auth (it does not know the
-- organization yet), which may read only what the check needs and record
-- the last use.
CREATE TABLE api_keys (
    id           uuid PRIMARY KEY DEFAULT uuidv7(),
    org_id       uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    name         text NOT NULL CHECK (length(name) BETWEEN 1 AND 80),
    prefix       text NOT NULL CHECK (length(prefix) BETWEEN 8 AND 20),
    token_hash   bytea NOT NULL UNIQUE CHECK (length(token_hash) = 32),
    scope        text NOT NULL CHECK (scope IN ('read', 'write')),
    created_by   text NOT NULL CHECK (length(created_by) <= 300),
    created_at   timestamptz NOT NULL DEFAULT now(),
    expires_at   timestamptz,
    last_used_at timestamptz,
    revoked_at   timestamptz
);
CREATE INDEX api_keys_org ON api_keys (org_id, created_at DESC);

GRANT SELECT (id, org_id, name, prefix, scope, created_by, created_at, expires_at, last_used_at, revoked_at) ON api_keys TO orus_app;
GRANT INSERT ON api_keys TO orus_app;
GRANT UPDATE (revoked_at) ON api_keys TO orus_app;
ALTER TABLE api_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE api_keys FORCE ROW LEVEL SECURITY;
CREATE POLICY org_isolation ON api_keys
    USING (org_id = nullif(current_setting('app.org_id', true), '')::uuid)
    WITH CHECK (org_id = nullif(current_setting('app.org_id', true), '')::uuid);

GRANT SELECT (id, org_id, name, scope, token_hash, expires_at, revoked_at, last_used_at) ON api_keys TO orus_auth;
GRANT UPDATE (last_used_at) ON api_keys TO orus_auth;
CREATE POLICY auth_lookup ON api_keys FOR SELECT TO orus_auth USING (true);
CREATE POLICY auth_touch ON api_keys FOR UPDATE TO orus_auth USING (true) WITH CHECK (true);
