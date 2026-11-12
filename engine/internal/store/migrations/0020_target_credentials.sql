-- 0020: the test account a customer gives for authenticated scans (step I).
--
-- One per target: a header (a bearer token, an API key, a session cookie)
-- or a login form (username and password of a test account). The secret
-- (header value or password) is sealed with AES-256-GCM under
-- ORUS_CREDENTIALS_KEY, bound to the target (package seal): a database
-- dump alone gives nothing, and a sealed value copied onto another target
-- does not open.
--
-- The API's role may write the secret but never read it back (column
-- privileges): only the worker, which runs the scans, opens it.
CREATE TABLE target_credentials (
    target_id      uuid PRIMARY KEY,
    org_id         uuid NOT NULL,
    kind           text NOT NULL CHECK (kind IN ('header', 'form')),
    -- header: header_name; form: login_url, username and the field names.
    header_name    text CHECK (length(header_name) <= 100),
    login_url      text CHECK (length(login_url) <= 2000),
    username       text CHECK (length(username) <= 200),
    username_field text CHECK (length(username_field) <= 100),
    password_field text CHECK (length(password_field) <= 100),
    sealed_secret  bytea NOT NULL CHECK (length(sealed_secret) <= 8192),
    created_at     timestamptz NOT NULL DEFAULT now(),
    created_by     text NOT NULL,
    CHECK (kind <> 'header' OR header_name IS NOT NULL),
    CHECK (kind <> 'form' OR (login_url IS NOT NULL AND username IS NOT NULL)),
    FOREIGN KEY (org_id, target_id) REFERENCES targets (org_id, id) ON DELETE CASCADE
);

GRANT SELECT (target_id, org_id, kind, header_name, login_url, username, username_field, password_field, created_at, created_by)
    ON target_credentials TO orus_app;
GRANT INSERT, UPDATE, DELETE ON target_credentials TO orus_app;

ALTER TABLE target_credentials ENABLE ROW LEVEL SECURITY;
ALTER TABLE target_credentials FORCE ROW LEVEL SECURITY;
CREATE POLICY org_isolation ON target_credentials
    USING (org_id = nullif(current_setting('app.org_id', true), '')::uuid)
    WITH CHECK (org_id = nullif(current_setting('app.org_id', true), '')::uuid);
