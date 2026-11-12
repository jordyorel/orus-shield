-- 0019: APIs a customer declares on a verified domain (step H, API security).
--
-- An API has a base URL under its target's domain and a description the
-- scan imports: an OpenAPI (Swagger) document, by URL under the same
-- domain or uploaded, or a GraphQL endpoint (introspected). The api module
-- scans what is declared here, through gateproxy like every external tool.
CREATE TABLE apis (
    id         uuid PRIMARY KEY DEFAULT uuidv7(),
    org_id     uuid NOT NULL,
    target_id  uuid NOT NULL,
    name       text NOT NULL CHECK (length(name) BETWEEN 1 AND 100),
    kind       text NOT NULL CHECK (kind IN ('openapi', 'graphql')),
    base_url   text NOT NULL CHECK (length(base_url) BETWEEN 8 AND 2000),
    -- OpenAPI: spec_url or spec (uploaded document); GraphQL: optional
    -- spec_url of a schema, else the endpoint is introspected.
    spec_url   text CHECK (length(spec_url) <= 2000),
    spec       text CHECK (octet_length(spec) <= 2097152),
    created_at timestamptz NOT NULL DEFAULT now(),
    created_by text NOT NULL,
    CHECK (kind <> 'openapi' OR spec_url IS NOT NULL OR spec IS NOT NULL),
    UNIQUE (target_id, base_url),
    FOREIGN KEY (org_id, target_id) REFERENCES targets (org_id, id) ON DELETE CASCADE
);

CREATE INDEX apis_by_target ON apis (org_id, target_id);

GRANT SELECT, INSERT, DELETE ON apis TO orus_app;

ALTER TABLE apis ENABLE ROW LEVEL SECURITY;
ALTER TABLE apis FORCE ROW LEVEL SECURITY;
CREATE POLICY org_isolation ON apis
    USING (org_id = nullif(current_setting('app.org_id', true), '')::uuid)
    WITH CHECK (org_id = nullif(current_setting('app.org_id', true), '')::uuid);
