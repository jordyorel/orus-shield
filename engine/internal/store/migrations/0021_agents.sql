-- 0021: internal scanning by agents (step J).
--
-- An agent is a small program a customer installs on one machine of their
-- network. It only calls out (HTTPS to the API) and scans only the private
-- ranges an admin declared. Its results belong to its "internal network":
-- a target of its own (targets.internal), so scans, findings, assets,
-- checks, scores and the audit log work exactly as for a domain.
--
-- Rule 1 for internal networks: the admin of the organization created the
-- agent, the agent was installed inside the customer's network (it
-- enrolled with a one-time code), and it scans private addresses only. The
-- internal target is created verified on that basis.
ALTER TABLE targets ADD COLUMN internal boolean NOT NULL DEFAULT false;
-- A domain is verified with its DNS token; an internal network by its
-- agent's enrolment (above), never by a token.
ALTER TABLE targets DROP CONSTRAINT verified_needs_token;
ALTER TABLE targets ADD CONSTRAINT verified_needs_token CHECK (verified_at IS NULL OR verify_token IS NOT NULL OR internal);

CREATE TABLE agents (
    id                uuid PRIMARY KEY DEFAULT uuidv7(),
    org_id            uuid NOT NULL,
    target_id         uuid NOT NULL UNIQUE,
    name              text NOT NULL CHECK (length(name) BETWEEN 1 AND 100),
    -- Private CIDRs only (checked by the API, the worker and the agent).
    ranges            text[] NOT NULL CHECK (cardinality(ranges) BETWEEN 1 AND 32),
    -- One-time enrolment code (SHA-256), valid until enroll_expires_at.
    enroll_hash       bytea CHECK (length(enroll_hash) = 32),
    enroll_expires_at timestamptz,
    -- The agent's token (SHA-256), set at enrolment.
    token_hash        bytea UNIQUE CHECK (length(token_hash) = 32),
    enrolled_at       timestamptz,
    last_seen_at      timestamptz,
    hostname          text CHECK (length(hostname) <= 255),
    os                text CHECK (length(os) <= 50),
    version           text CHECK (length(version) <= 50),
    revoked_at        timestamptz,
    created_at        timestamptz NOT NULL DEFAULT now(),
    created_by        text NOT NULL,
    FOREIGN KEY (org_id, target_id) REFERENCES targets (org_id, id) ON DELETE CASCADE
);

-- What an agent sent back for a scan, kept until the worker validates it
-- and records it (FinishScan). The API never records results itself.
CREATE TABLE agent_results (
    id           uuid PRIMARY KEY DEFAULT uuidv7(),
    org_id       uuid NOT NULL,
    agent_id     uuid NOT NULL REFERENCES agents (id) ON DELETE CASCADE,
    scan_id      uuid NOT NULL,
    attempt      integer NOT NULL,
    payload      jsonb NOT NULL CHECK (octet_length(payload::text) <= 8388608),
    created_at   timestamptz NOT NULL DEFAULT now(),
    processed_at timestamptz,
    UNIQUE (scan_id, attempt)
);
CREATE INDEX agent_results_pending ON agent_results (created_at) WHERE processed_at IS NULL;

-- The dashboard (orus_app, row-level security by organization).
GRANT SELECT (id, org_id, target_id, name, ranges, enroll_expires_at, enrolled_at, last_seen_at, hostname, os, version,
              revoked_at, created_at, created_by) ON agents TO orus_app;
GRANT INSERT ON agents TO orus_app;
GRANT UPDATE (name, ranges, enroll_hash, enroll_expires_at, revoked_at) ON agents TO orus_app;
ALTER TABLE agents ENABLE ROW LEVEL SECURITY;
ALTER TABLE agents FORCE ROW LEVEL SECURITY;
CREATE POLICY org_isolation ON agents
    USING (org_id = nullif(current_setting('app.org_id', true), '')::uuid)
    WITH CHECK (org_id = nullif(current_setting('app.org_id', true), '')::uuid);

ALTER TABLE agent_results ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_results FORCE ROW LEVEL SECURITY;
CREATE POLICY org_isolation ON agent_results
    USING (org_id = nullif(current_setting('app.org_id', true), '')::uuid)
    WITH CHECK (org_id = nullif(current_setting('app.org_id', true), '')::uuid);

-- The role of the API's agent endpoints (store.Agents). An agent proves
-- itself with its token; the code always filters by its hash. The role
-- reaches agents, their internal targets and their scans, and nothing of
-- the customers' domains.
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'orus_agent') THEN
        CREATE ROLE orus_agent NOLOGIN NOSUPERUSER NOBYPASSRLS;
    END IF;
EXCEPTION
    WHEN duplicate_object OR unique_violation THEN NULL;
END;
$$;
GRANT orus_agent TO CURRENT_USER;
DO $$
BEGIN
    EXECUTE format('GRANT USAGE ON SCHEMA %I TO orus_agent', current_schema());
END;
$$;

GRANT SELECT (id, org_id, target_id, ranges, enroll_hash, enroll_expires_at, token_hash, revoked_at, hostname, os, version) ON agents TO orus_agent;
GRANT UPDATE (enroll_hash, enroll_expires_at, token_hash, enrolled_at, last_seen_at, hostname, os, version) ON agents TO orus_agent;
CREATE POLICY agent_access ON agents TO orus_agent USING (true) WITH CHECK (true);

GRANT SELECT (id, org_id, domain, exclusions, rate_per_sec, internal) ON targets TO orus_agent;
CREATE POLICY agent_internal_targets ON targets FOR SELECT TO orus_agent
    USING (internal AND id IN (SELECT target_id FROM agents));

GRANT SELECT ON scans TO orus_agent;
GRANT UPDATE (status, attempts, locked_until, started_at) ON scans TO orus_agent;
CREATE POLICY agent_internal_scans ON scans TO orus_agent
    USING (target_id IN (SELECT target_id FROM agents))
    WITH CHECK (target_id IN (SELECT target_id FROM agents));

GRANT INSERT ON agent_results TO orus_agent;
CREATE POLICY agent_results_insert ON agent_results FOR INSERT TO orus_agent
    WITH CHECK (agent_id IN (SELECT id FROM agents WHERE revoked_at IS NULL));

GRANT INSERT ON audit_log TO orus_agent;
CREATE POLICY agent_audit ON audit_log FOR INSERT TO orus_agent
    WITH CHECK (org_id IN (SELECT org_id FROM agents));
