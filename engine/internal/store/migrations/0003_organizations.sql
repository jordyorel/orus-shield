-- Organizations: every target, scan, finding and audit entry belongs to one
-- customer organization (roadmap step 7.1).
--
-- A leak between customers is the worst failure for a security product, so
-- isolation has two independent layers:
--   1. Go: API code only gets a store.Org handle, whose queries all filter
--      on org_id.
--   2. PostgreSQL row-level security (below): an Org handle's transactions
--      run as the orus_app role with app.org_id set, and the policies hide
--      every row of another organization, even from a query that forgot its
--      filter.
-- The worker processes every organization: it connects as the schema owner
-- (dev) or, in production, as a role with BYPASSRLS. A role without either
-- sees no rows at all: the failure mode is "nothing", never "everything".

CREATE TABLE organizations (
    id         uuid PRIMARY KEY DEFAULT uuidv7(),
    -- Not unique: two customers can have the same name.
    name       text NOT NULL CHECK (length(btrim(name)) BETWEEN 1 AND 200),
    created_at timestamptz NOT NULL DEFAULT now()
);

-- Everything that existed before organizations belongs to this one. It also
-- gives orusctl a default organization on a fresh database.
INSERT INTO organizations (name) VALUES ('Default');

-- 1. Add org_id everywhere and fill it. Only one organization exists at this
--    point, so every existing row belongs to it.
ALTER TABLE targets   ADD COLUMN org_id uuid REFERENCES organizations (id);
ALTER TABLE scans     ADD COLUMN org_id uuid;
ALTER TABLE findings  ADD COLUMN org_id uuid;
ALTER TABLE audit_log ADD COLUMN org_id uuid REFERENCES organizations (id);

UPDATE targets SET org_id = (SELECT id FROM organizations);
UPDATE scans   SET org_id = (SELECT id FROM organizations);
UPDATE findings SET org_id = (SELECT id FROM organizations);

-- audit_log is append-only: its triggers reject every UPDATE, on purpose.
-- They are disabled for this one backfill, inside the migration transaction,
-- and enabled again right after. Nothing else can run in between.
ALTER TABLE audit_log DISABLE TRIGGER audit_log_no_update_delete;
UPDATE audit_log SET org_id = (SELECT id FROM organizations);
ALTER TABLE audit_log ENABLE TRIGGER audit_log_no_update_delete;

ALTER TABLE targets   ALTER COLUMN org_id SET NOT NULL;
ALTER TABLE scans     ALTER COLUMN org_id SET NOT NULL;
ALTER TABLE findings  ALTER COLUMN org_id SET NOT NULL;
ALTER TABLE audit_log ALTER COLUMN org_id SET NOT NULL;

-- 2. A domain is unique per organization, not globally: two organizations
--    may both add (and each verify, with its own token) the same domain.
ALTER TABLE targets DROP CONSTRAINT targets_domain_key;
ALTER TABLE targets ADD CONSTRAINT targets_org_domain_key UNIQUE (org_id, domain);

-- 3. A scan or finding is in the same organization as its target. Composite
--    foreign keys make the database enforce it, so a bug cannot attach a
--    scan to another customer's target.
ALTER TABLE targets ADD CONSTRAINT targets_org_id_id_key UNIQUE (org_id, id);

ALTER TABLE scans DROP CONSTRAINT scans_target_id_fkey;
ALTER TABLE scans ADD CONSTRAINT scans_target_fkey
    FOREIGN KEY (org_id, target_id) REFERENCES targets (org_id, id) ON DELETE CASCADE;

ALTER TABLE findings DROP CONSTRAINT findings_target_id_fkey;
ALTER TABLE findings ADD CONSTRAINT findings_target_fkey
    FOREIGN KEY (org_id, target_id) REFERENCES targets (org_id, id) ON DELETE CASCADE;

DROP INDEX audit_log_by_target;
CREATE INDEX audit_log_by_target ON audit_log (org_id, target, at);

-- 4. The role API transactions switch to (SET LOCAL ROLE orus_app). NOLOGIN:
--    nobody connects as it directly, so it has no password (rule 5). Roles
--    are global to the PostgreSQL server, not to a database or schema: create
--    it only once, and tolerate another migration creating it concurrently.
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'orus_app') THEN
        CREATE ROLE orus_app NOLOGIN NOSUPERUSER NOBYPASSRLS;
    END IF;
EXCEPTION
    WHEN duplicate_object OR unique_violation THEN NULL;
END;
$$;

-- The user running migrations must be allowed to SET ROLE orus_app. Implicit
-- for a superuser; needed for a non-superuser owner in production.
GRANT orus_app TO CURRENT_USER;

-- Least privilege: only what the API needs. Recording scan results (findings
-- INSERT) and deleting anything are left to the worker.
DO $$
BEGIN
    EXECUTE format('GRANT USAGE ON SCHEMA %I TO orus_app', current_schema());
END;
$$;
GRANT SELECT                 ON organizations TO orus_app;
GRANT SELECT, INSERT, UPDATE ON targets       TO orus_app;
GRANT SELECT, INSERT         ON scans         TO orus_app;
GRANT SELECT, UPDATE         ON findings      TO orus_app;
GRANT SELECT, INSERT         ON audit_log     TO orus_app;

-- 5. Row-level security. app.org_id is set per transaction by the Org
--    handle (set_config(..., true)). Unset, current_setting(..., true)
--    returns NULL; once set in a session it returns '' after the
--    transaction ends, hence nullif. Either way the comparison is NULL and
--    the policy matches no row.
--
--    FORCE applies the policies to the table owner too; only superusers and
--    BYPASSRLS roles skip them.
ALTER TABLE organizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE organizations FORCE ROW LEVEL SECURITY;
CREATE POLICY org_isolation ON organizations
    USING (id = nullif(current_setting('app.org_id', true), '')::uuid);

ALTER TABLE targets ENABLE ROW LEVEL SECURITY;
ALTER TABLE targets FORCE ROW LEVEL SECURITY;
CREATE POLICY org_isolation ON targets
    USING (org_id = nullif(current_setting('app.org_id', true), '')::uuid)
    WITH CHECK (org_id = nullif(current_setting('app.org_id', true), '')::uuid);

ALTER TABLE scans ENABLE ROW LEVEL SECURITY;
ALTER TABLE scans FORCE ROW LEVEL SECURITY;
CREATE POLICY org_isolation ON scans
    USING (org_id = nullif(current_setting('app.org_id', true), '')::uuid)
    WITH CHECK (org_id = nullif(current_setting('app.org_id', true), '')::uuid);

ALTER TABLE findings ENABLE ROW LEVEL SECURITY;
ALTER TABLE findings FORCE ROW LEVEL SECURITY;
CREATE POLICY org_isolation ON findings
    USING (org_id = nullif(current_setting('app.org_id', true), '')::uuid)
    WITH CHECK (org_id = nullif(current_setting('app.org_id', true), '')::uuid);

ALTER TABLE audit_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_log FORCE ROW LEVEL SECURITY;
CREATE POLICY org_isolation ON audit_log
    USING (org_id = nullif(current_setting('app.org_id', true), '')::uuid)
    WITH CHECK (org_id = nullif(current_setting('app.org_id', true), '')::uuid);
