-- 0014: emerging threats (package threats).
--
-- threat_templates is the set of critical and high CVE detection templates
-- the platform has seen, across releases of nuclei-templates. It is public
-- data (the templates are open source), not customer data: no org_id. The
-- first sync is the baseline: only the templates the release lists as new
-- are "emerging"; on later syncs every template not seen before is.
CREATE TABLE threat_templates (
    id           text PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 200),
    cve          text NOT NULL DEFAULT '' CHECK (length(cve) <= 40),
    name         text NOT NULL CHECK (length(name) <= 500),
    severity     text NOT NULL CHECK (severity IN ('critical', 'high')),
    products     text[] NOT NULL,
    kev          boolean NOT NULL DEFAULT false,
    epss         double precision NOT NULL DEFAULT 0 CHECK (epss >= 0 AND epss <= 1),
    emerging     boolean NOT NULL,
    first_seen   timestamptz NOT NULL,
    -- Set once the template was matched against every customer.
    processed_at timestamptz
);

CREATE INDEX threat_templates_pending ON threat_templates (first_seen) WHERE emerging AND processed_at IS NULL;

-- The dashboard shows each threat's name and CVE.
GRANT SELECT ON threat_templates TO orus_app;

-- threat_matches: an emerging threat that may concern a target (its
-- detected technologies match), and the rescan it triggered. scan_id is
-- NULL when the target already had a scan queued or running: that scan
-- runs the new templates anyway.
CREATE TABLE threat_matches (
    id          uuid PRIMARY KEY DEFAULT uuidv7(),
    org_id      uuid NOT NULL,
    target_id   uuid NOT NULL,
    template_id text NOT NULL REFERENCES threat_templates (id) ON DELETE CASCADE,
    products    text[] NOT NULL, -- the technologies that matched
    scan_id     uuid,
    created_at  timestamptz NOT NULL,
    UNIQUE (target_id, template_id),
    FOREIGN KEY (org_id, target_id) REFERENCES targets (org_id, id) ON DELETE CASCADE
);

CREATE INDEX threat_matches_org ON threat_matches (org_id, created_at DESC);

-- Written by the worker only; the API reads them.
GRANT SELECT ON threat_matches TO orus_app;

ALTER TABLE threat_matches ENABLE ROW LEVEL SECURITY;
ALTER TABLE threat_matches FORCE ROW LEVEL SECURITY;
CREATE POLICY org_isolation ON threat_matches
    USING (org_id = nullif(current_setting('app.org_id', true), '')::uuid)
    WITH CHECK (org_id = nullif(current_setting('app.org_id', true), '')::uuid);

-- The admins of a matched organization get an email.
ALTER TABLE notifications DROP CONSTRAINT notifications_kind_check;
ALTER TABLE notifications ADD CONSTRAINT notifications_kind_check
    CHECK (kind IN ('new_findings', 'emerging_threat'));
