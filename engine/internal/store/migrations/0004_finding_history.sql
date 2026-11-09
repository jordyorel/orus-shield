-- Findings lifecycle history (roadmap step 7.2).
--
-- findings keeps the current state only. Remediation metrics need more:
--   - fixed_at: when a scan stopped seeing the finding. The real fix happened
--     between last_seen and fixed_at; fixed_at is when we could prove it.
--     Mean time to remediate = fixed_at - first_seen.
--   - finding_events: every status change (opened, fixed, reopened, risk
--     accepted or withdrawn), so a finding fixed then reopened then fixed
--     again counts as two remediations, and "opened vs fixed per month" can
--     be computed for any past month.

ALTER TABLE findings ADD COLUMN fixed_at timestamptz;

-- Backfill: rows already fixed get the observation time of the first
-- finished scan of their target after they were last seen, which is when
-- that scan stopped seeing them. If there is none (should not happen),
-- last_seen is the best lower bound.
UPDATE findings f SET fixed_at = coalesce(
    (SELECT min(s.finished_at) FROM scans s
      WHERE s.target_id = f.target_id AND s.status = 'done' AND s.finished_at > f.last_seen),
    f.last_seen)
WHERE f.status = 'fixed';
UPDATE findings SET data = data || jsonb_build_object('fixed_at', fixed_at) WHERE status = 'fixed';

-- fixed_at is set exactly when the finding is fixed.
ALTER TABLE findings ADD CONSTRAINT fixed_at_iff_fixed
    CHECK ((status = 'fixed') = (fixed_at IS NOT NULL));

-- Needed by the composite foreign key below.
ALTER TABLE findings ADD CONSTRAINT findings_org_target_id_key UNIQUE (org_id, target_id, id);

CREATE TABLE finding_events (
    id         bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    org_id     uuid NOT NULL,
    target_id  uuid NOT NULL,
    finding_id text NOT NULL,
    -- When the change was observed: the scan's observation time for scan
    -- events, the request time for manual ones.
    at         timestamptz NOT NULL,
    -- NULL when the finding was first seen.
    from_status text CHECK (from_status IN ('open', 'fixed', 'accepted_risk')),
    to_status   text NOT NULL CHECK (to_status IN ('open', 'fixed', 'accepted_risk')),
    CHECK (from_status IS DISTINCT FROM to_status),
    -- A worker ID for scan events, the customer for manual ones.
    actor      text NOT NULL,
    -- The scan that observed the change; NULL for manual changes. No foreign
    -- key: history must survive if old scans are ever pruned.
    scan_id    uuid,
    -- Same organization and target as the finding, enforced by the database.
    -- History is part of the finding: deleting the finding (with its
    -- target) deletes it.
    FOREIGN KEY (org_id, target_id, finding_id)
        REFERENCES findings (org_id, target_id, id) ON DELETE CASCADE
);

CREATE INDEX finding_events_by_finding ON finding_events (target_id, finding_id, id);
CREATE INDEX finding_events_by_org_time ON finding_events (org_id, at);

-- History for existing findings, reconstructed from their current state:
-- one "opened" event at first_seen, and a "fixed" event for fixed ones.
-- Intermediate changes (an earlier fix and regression) were not recorded
-- before this migration and cannot be recovered. The actor says so.
INSERT INTO finding_events (org_id, target_id, finding_id, at, from_status, to_status, actor)
SELECT org_id, target_id, id, first_seen, NULL, 'open', 'migration:0004' FROM findings;
INSERT INTO finding_events (org_id, target_id, finding_id, at, from_status, to_status, actor)
SELECT org_id, target_id, id, fixed_at, 'open', 'fixed', 'migration:0004' FROM findings WHERE status = 'fixed';
INSERT INTO finding_events (org_id, target_id, finding_id, at, from_status, to_status, actor)
SELECT org_id, target_id, id, last_seen, 'open', 'accepted_risk', 'migration:0004' FROM findings WHERE status = 'accepted_risk';

-- The API reads history and records manual decisions; it never edits or
-- deletes events.
GRANT SELECT, INSERT ON finding_events TO orus_app;

ALTER TABLE finding_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE finding_events FORCE ROW LEVEL SECURITY;
CREATE POLICY org_isolation ON finding_events
    USING (org_id = nullif(current_setting('app.org_id', true), '')::uuid)
    WITH CHECK (org_id = nullif(current_setting('app.org_id', true), '')::uuid);
