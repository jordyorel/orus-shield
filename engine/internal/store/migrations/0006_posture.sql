-- Evaluated checks and posture score (roadmap step 7.4).
--
-- Until now only failures were stored (findings), so "31 failed out of
-- 212" and a score could not be computed honestly. Each scan now records
-- the status of every catalog check of the modules that succeeded.

-- Latest status of each check on each target. A module that failed leaves
-- its checks as they were (evaluated_at tells how old they are).
CREATE TABLE check_status (
    org_id       uuid NOT NULL,
    target_id    uuid NOT NULL,
    check_id     text NOT NULL,
    module_id    text NOT NULL,
    -- Copied from the catalog at evaluation time, so a score can be
    -- recomputed from this table alone.
    category     text NOT NULL,
    severity     text NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
    status       text NOT NULL CHECK (status IN ('passed', 'failed', 'not_applicable')),
    findings     integer NOT NULL CHECK (findings >= 0),
    CHECK ((status = 'failed') = (findings > 0)),
    evaluated_at timestamptz NOT NULL,
    scan_id      uuid NOT NULL,
    PRIMARY KEY (target_id, check_id),
    FOREIGN KEY (org_id, target_id) REFERENCES targets (org_id, id) ON DELETE CASCADE
);

-- The posture after each scan, for trends ("+16 points"). details holds the
-- breakdown that explains the score (package posture, Snapshot).
CREATE TABLE posture_snapshots (
    id             bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    org_id         uuid NOT NULL,
    target_id      uuid NOT NULL,
    scan_id        uuid NOT NULL,
    at             timestamptz NOT NULL,
    -- NULL when nothing with a weight was evaluated: no data is not a score.
    score          integer CHECK (score BETWEEN 0 AND 100),
    passed         integer NOT NULL,
    failed         integer NOT NULL,
    not_applicable integer NOT NULL,
    details        jsonb NOT NULL,
    FOREIGN KEY (org_id, target_id) REFERENCES targets (org_id, id) ON DELETE CASCADE
);

CREATE INDEX posture_snapshots_by_target ON posture_snapshots (target_id, at);

-- Written by the worker only; the API reads.
GRANT SELECT ON check_status, posture_snapshots TO orus_app;

ALTER TABLE check_status ENABLE ROW LEVEL SECURITY;
ALTER TABLE check_status FORCE ROW LEVEL SECURITY;
CREATE POLICY org_isolation ON check_status
    USING (org_id = nullif(current_setting('app.org_id', true), '')::uuid)
    WITH CHECK (org_id = nullif(current_setting('app.org_id', true), '')::uuid);

ALTER TABLE posture_snapshots ENABLE ROW LEVEL SECURITY;
ALTER TABLE posture_snapshots FORCE ROW LEVEL SECURITY;
CREATE POLICY org_isolation ON posture_snapshots
    USING (org_id = nullif(current_setting('app.org_id', true), '')::uuid)
    WITH CHECK (org_id = nullif(current_setting('app.org_id', true), '')::uuid);
