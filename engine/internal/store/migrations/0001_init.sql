-- Initial schema: targets, scan queue, findings, audit log.
-- IDs use uuidv7() (PostgreSQL 18): unique without coordination, roughly
-- time-ordered for index locality, and not sequential, so they can be shown
-- to customers later without revealing how many scans or targets exist.

CREATE TABLE targets (
    id           uuid PRIMARY KEY DEFAULT uuidv7(),
    domain       text NOT NULL UNIQUE,
    -- Set by ownership verification (roadmap step 5). NULL: not verified,
    -- so no active module may run (security rule 1).
    verified_at  timestamptz,
    -- Customer exclusions: {"ips": [...], "ports": [...], "paths": [...], "hosts": [...]}
    exclusions   jsonb NOT NULL DEFAULT '{}',
    -- Outbound request rate for this target (security rule 3).
    rate_per_sec double precision NOT NULL DEFAULT 5
                 CHECK (rate_per_sec > 0 AND rate_per_sec <= 100),
    created_at   timestamptz NOT NULL DEFAULT now()
);

-- The scan queue. Workers claim rows with FOR UPDATE SKIP LOCKED.
CREATE TABLE scans (
    id           uuid PRIMARY KEY DEFAULT uuidv7(),
    target_id    uuid NOT NULL REFERENCES targets (id) ON DELETE CASCADE,
    modules      text[] NOT NULL CHECK (cardinality(modules) > 0),
    requested_by text NOT NULL,
    status       text NOT NULL DEFAULT 'queued'
                 CHECK (status IN ('queued', 'running', 'done', 'failed')),
    -- Incremented on every claim. Also the fencing token: a worker whose
    -- lease expired cannot overwrite the result of the worker that took over.
    attempts     integer NOT NULL DEFAULT 0,
    -- While running: the claim is valid until then. A crashed worker's scan
    -- becomes claimable again once its lease expires.
    locked_until timestamptz,
    error        text,
    created_at   timestamptz NOT NULL DEFAULT now(),
    started_at   timestamptz,
    finished_at  timestamptz
);

CREATE INDEX scans_claimable ON scans (created_at) WHERE status IN ('queued', 'running');

CREATE TABLE findings (
    target_id  uuid NOT NULL REFERENCES targets (id) ON DELETE CASCADE,
    -- Deterministic finding ID (finding.NewID). It depends on the domain, so
    -- it is unique per target, not globally: hence the composite key.
    id         text NOT NULL,
    module_id  text NOT NULL,
    check_id   text NOT NULL,
    severity   text NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
    status     text NOT NULL CHECK (status IN ('open', 'fixed', 'accepted_risk')),
    first_seen timestamptz NOT NULL,
    last_seen  timestamptz NOT NULL,
    -- The complete finding in the standard JSON schema. The columns above
    -- duplicate a few fields for filtering and sorting.
    data       jsonb NOT NULL,
    PRIMARY KEY (target_id, id)
);

CREATE INDEX findings_by_status ON findings (target_id, status, severity);

-- Security rule 4: who started which scan, on which target, with which
-- modules, when. Append-only: the triggers below reject UPDATE, DELETE and
-- TRUNCATE, even for the application's own database user.
CREATE TABLE audit_log (
    id      bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    at      timestamptz NOT NULL DEFAULT now(),
    actor   text NOT NULL,
    action  text NOT NULL,
    target  text NOT NULL,
    details jsonb NOT NULL DEFAULT '{}'
);

CREATE INDEX audit_log_by_target ON audit_log (target, at);

CREATE FUNCTION audit_log_append_only() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'audit_log is append-only';
END;
$$;

CREATE TRIGGER audit_log_no_update_delete
    BEFORE UPDATE OR DELETE ON audit_log
    FOR EACH ROW EXECUTE FUNCTION audit_log_append_only();

CREATE TRIGGER audit_log_no_truncate
    BEFORE TRUNCATE ON audit_log
    FOR EACH STATEMENT EXECUTE FUNCTION audit_log_append_only();
