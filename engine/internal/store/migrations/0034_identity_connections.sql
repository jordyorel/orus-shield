-- 0034: identity providers connected to a domain (step K, Microsoft 365).
--
-- A connection holds no secret: our multi-tenant app reaches the tenant
-- with its own credentials (worker and API environment), in the tenant
-- whose admin consented. Only the tenant's ID and what the connection
-- check saw are kept. The API records it after checking that the tenant
-- manages the target's verified domain and granted exactly the read-only
-- permissions; the module checks both again at every scan.
--
-- One tenant per organization is connected to one domain only: two
-- domains of the same tenant would audit it twice.
CREATE TABLE identity_connections (
    org_id       uuid NOT NULL,
    target_id    uuid NOT NULL,
    provider     text NOT NULL CHECK (provider IN ('m365')),
    tenant_id    text NOT NULL CHECK (tenant_id ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'),
    tenant_name  text NOT NULL CHECK (length(tenant_name) BETWEEN 1 AND 253),
    permissions  text[] NOT NULL,
    connected_at timestamptz NOT NULL DEFAULT now(),
    connected_by text NOT NULL,
    PRIMARY KEY (target_id, provider),
    UNIQUE (org_id, provider, tenant_id),
    FOREIGN KEY (org_id, target_id) REFERENCES targets (org_id, id) ON DELETE CASCADE
);

GRANT SELECT, INSERT, UPDATE, DELETE ON identity_connections TO orus_app;

ALTER TABLE identity_connections ENABLE ROW LEVEL SECURITY;
ALTER TABLE identity_connections FORCE ROW LEVEL SECURITY;
CREATE POLICY org_isolation ON identity_connections
    USING (org_id = nullif(current_setting('app.org_id', true), '')::uuid)
    WITH CHECK (org_id = nullif(current_setting('app.org_id', true), '')::uuid);
