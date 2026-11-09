-- User accounts, memberships and sessions (roadmap step 7.6).
--
-- Accounts are created by invitation only (orusctl user add): there is no
-- public sign-up until we can send verification emails. A new user gets a
-- one-time setup token to choose their password through the API.

CREATE TABLE users (
    id                  uuid PRIMARY KEY DEFAULT uuidv7(),
    -- Stored lowercased, so "Alice@Example.com" and "alice@example.com"
    -- are one account.
    email               text NOT NULL UNIQUE
                        CHECK (email = lower(email) AND length(email) BETWEEN 3 AND 254 AND position('@' IN email) > 1),
    -- argon2id in PHC format (package password). NULL until the user sets it.
    password_hash       text,
    password_changed_at timestamptz,
    created_at          timestamptz NOT NULL DEFAULT now(),
    -- A disabled user cannot log in and their sessions stop working.
    disabled_at         timestamptz
);

-- admin: manage targets, verify, scan, accept risks. viewer: read only.
CREATE TABLE memberships (
    user_id    uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    org_id     uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    role       text NOT NULL CHECK (role IN ('admin', 'viewer')),
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, org_id)
);

CREATE INDEX memberships_by_org ON memberships (org_id);

-- Only the SHA-256 of each token is stored: a copy of this table gives no
-- usable session.
CREATE TABLE sessions (
    token_hash   bytea PRIMARY KEY CHECK (length(token_hash) = 32),
    user_id      uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    created_at   timestamptz NOT NULL DEFAULT now(),
    last_seen_at timestamptz NOT NULL DEFAULT now(),
    -- Absolute limit; the idle limit is checked against last_seen_at.
    expires_at   timestamptz NOT NULL,
    ip           text NOT NULL,
    user_agent   text NOT NULL CHECK (length(user_agent) <= 512)
);

CREATE INDEX sessions_by_user ON sessions (user_id);

CREATE TABLE setup_tokens (
    token_hash bytea PRIMARY KEY CHECK (length(token_hash) = 32),
    user_id    uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    used_at    timestamptz
);

-- Logins, failures, logouts, password changes. Append-only like audit_log.
-- No foreign key: entries outlive the user, and failed logins may name an
-- email that has no account. Login rate limits are computed from it.
CREATE TABLE auth_log (
    id      bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    at      timestamptz NOT NULL DEFAULT now(),
    user_id uuid,
    email   text NOT NULL,
    action  text NOT NULL,
    ip      text NOT NULL,
    details jsonb NOT NULL DEFAULT '{}'
);

CREATE INDEX auth_log_by_email ON auth_log (email, at) WHERE action = 'login.failed';
CREATE INDEX auth_log_by_ip ON auth_log (ip, at) WHERE action = 'login.failed';

CREATE FUNCTION auth_log_append_only() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'auth_log is append-only';
END;
$$;

CREATE TRIGGER auth_log_no_update_delete
    BEFORE UPDATE OR DELETE ON auth_log
    FOR EACH ROW EXECUTE FUNCTION auth_log_append_only();

CREATE TRIGGER auth_log_no_truncate
    BEFORE TRUNCATE ON auth_log
    FOR EACH STATEMENT EXECUTE FUNCTION auth_log_append_only();

-- The role of the API's authentication code (store.Auth). It sees accounts
-- and sessions, and none of the customers' data: the login code cannot
-- read a single finding, even through a bug.
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'orus_auth') THEN
        CREATE ROLE orus_auth NOLOGIN NOSUPERUSER NOBYPASSRLS;
    END IF;
EXCEPTION
    WHEN duplicate_object OR unique_violation THEN NULL;
END;
$$;
GRANT orus_auth TO CURRENT_USER;

DO $$
BEGIN
    EXECUTE format('GRANT USAGE ON SCHEMA %I TO orus_auth', current_schema());
END;
$$;
GRANT SELECT, UPDATE (password_hash, password_changed_at) ON users TO orus_auth;
GRANT SELECT                         ON memberships  TO orus_auth;
GRANT SELECT, INSERT, UPDATE, DELETE ON sessions     TO orus_auth;
GRANT SELECT, UPDATE (used_at)       ON setup_tokens TO orus_auth;
GRANT SELECT, INSERT                 ON auth_log     TO orus_auth;
-- Organization names, to list the user's organizations. organizations has
-- FORCE'd row-level security, so the role needs its own policy.
GRANT SELECT (id, name)              ON organizations TO orus_auth;
CREATE POLICY auth_read_names ON organizations FOR SELECT TO orus_auth USING (true);
