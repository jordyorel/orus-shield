-- 0013: self-service signup.
--
-- A signup request stores the email and the organization name with a
-- one-time token (only its SHA-256 here). Nothing else exists until the
-- link is used: then the account, the organization and the admin
-- membership are created in one transaction. Bots filling the form create
-- no accounts and no organizations.
CREATE TABLE signup_requests (
    token_hash bytea PRIMARY KEY,
    email      text NOT NULL CHECK (email = lower(email) AND length(email) BETWEEN 3 AND 254),
    org_name   text NOT NULL CHECK (length(btrim(org_name)) BETWEEN 1 AND 200),
    ip         text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    used_at    timestamptz,
    -- The organization created from this request (at most one).
    org_id     uuid REFERENCES organizations (id) ON DELETE SET NULL
);
CREATE INDEX signup_requests_email ON signup_requests (email) WHERE used_at IS NULL;

-- The API's authentication role reads and consumes requests.
GRANT SELECT, INSERT, UPDATE (used_at) ON signup_requests TO orus_auth;

-- It still cannot create organizations (auth_test checks it). The only way
-- is this function, and only for a signup request the same transaction has
-- just consumed: used_at = now() is the transaction's start time, so a
-- request consumed earlier, or never, is refused. One organization per
-- request. SECURITY DEFINER runs it with its owner's rights; search_path is
-- fixed so a caller cannot slip in their own tables.
CREATE FUNCTION signup_create_organization(p_token_hash bytea) RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path FROM CURRENT AS $$
DECLARE
    r   signup_requests%ROWTYPE;
    org uuid := uuidv7();
BEGIN
    SELECT * INTO r FROM signup_requests WHERE token_hash = p_token_hash FOR UPDATE;
    IF NOT FOUND OR r.used_at IS DISTINCT FROM now() OR r.org_id IS NOT NULL THEN
        RAISE EXCEPTION 'signup_create_organization: no signup request consumed in this transaction';
    END IF;
    -- organizations has FORCE ROW LEVEL SECURITY: the insert must match
    -- the organization in scope, even for the owner.
    PERFORM set_config('app.org_id', org::text, true);
    INSERT INTO organizations (id, name) VALUES (org, r.org_name);
    PERFORM set_config('app.org_id', '', true);
    UPDATE signup_requests SET org_id = org WHERE token_hash = p_token_hash;
    RETURN org;
END
$$;
REVOKE ALL ON FUNCTION signup_create_organization(bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION signup_create_organization(bytea) TO orus_auth;

-- Rate limit of signup requests, like failed logins and password resets.
CREATE INDEX auth_log_signup_by_email ON auth_log (email, at) WHERE action = 'signup.requested';
CREATE INDEX auth_log_signup_by_ip    ON auth_log (ip, at)    WHERE action = 'signup.requested';
