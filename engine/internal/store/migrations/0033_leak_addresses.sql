-- 0033: email addresses an admin declares on a domain for data leak
-- monitoring (leaks module, XposedOrNot). The members of the organization
-- whose address is on the domain are checked too, without being declared.
--
-- Only addresses on the target's domain or under it are accepted (checked
-- by the API); the module checks them only once the domain is verified.
CREATE TABLE leak_addresses (
    id         uuid PRIMARY KEY DEFAULT uuidv7(),
    org_id     uuid NOT NULL,
    target_id  uuid NOT NULL,
    email      text NOT NULL CHECK (email = lower(email) AND length(email) BETWEEN 3 AND 254 AND position('@' IN email) > 1),
    created_at timestamptz NOT NULL DEFAULT now(),
    created_by text NOT NULL,
    UNIQUE (target_id, email),
    FOREIGN KEY (org_id, target_id) REFERENCES targets (org_id, id) ON DELETE CASCADE
);

CREATE INDEX leak_addresses_by_target ON leak_addresses (org_id, target_id);

GRANT SELECT, INSERT, DELETE ON leak_addresses TO orus_app;

ALTER TABLE leak_addresses ENABLE ROW LEVEL SECURITY;
ALTER TABLE leak_addresses FORCE ROW LEVEL SECURITY;
CREATE POLICY org_isolation ON leak_addresses
    USING (org_id = nullif(current_setting('app.org_id', true), '')::uuid)
    WITH CHECK (org_id = nullif(current_setting('app.org_id', true), '')::uuid);
