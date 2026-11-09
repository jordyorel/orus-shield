-- Asset inventory (roadmap step 7.3): what each target exposes, problem or
-- not. Modules report the assets they observe (module.Result.Assets).
--
-- An asset can be seen by several modules (an IP is seen by both tls and
-- ports). sources lists the modules that saw it in their last successful
-- run. When a module succeeds without reporting an asset, it is removed from
-- sources; when no module sees the asset any more, it is gone (gone_at set).
-- A module that failed changes nothing: like findings, a failure tells us
-- nothing about what exists.
CREATE TABLE assets (
    id         uuid PRIMARY KEY DEFAULT uuidv7(),
    org_id     uuid NOT NULL,
    target_id  uuid NOT NULL,
    kind       text NOT NULL CHECK (kind IN ('hostname', 'ip', 'service', 'certificate')),
    -- Canonical form, validated by package asset: "www.example.com",
    -- "192.0.2.10", "192.0.2.10:443/tcp", a hex SHA-256.
    value      text NOT NULL CHECK (length(value) BETWEEN 1 AND 300),
    -- Descriptive and bounded (package asset): a certificate's subject and
    -- expiry, a service's expected name and banner. Merged across modules.
    details    jsonb NOT NULL DEFAULT '{}',
    sources    text[] NOT NULL,
    first_seen timestamptz NOT NULL,
    last_seen  timestamptz NOT NULL,
    gone_at    timestamptz,
    CHECK ((cardinality(sources) = 0) = (gone_at IS NOT NULL)),
    UNIQUE (target_id, kind, value),
    FOREIGN KEY (org_id, target_id) REFERENCES targets (org_id, id) ON DELETE CASCADE
);

-- Assets are written by the worker only; the API reads them.
GRANT SELECT ON assets TO orus_app;

ALTER TABLE assets ENABLE ROW LEVEL SECURITY;
ALTER TABLE assets FORCE ROW LEVEL SECURITY;
CREATE POLICY org_isolation ON assets
    USING (org_id = nullif(current_setting('app.org_id', true), '')::uuid)
    WITH CHECK (org_id = nullif(current_setting('app.org_id', true), '')::uuid);
