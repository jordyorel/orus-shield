-- 0018: deep scans per month (plan.Plan.DeepScansPerMonth).
--
-- The worker marks the scans it runs with the deep profile, so the month's
-- count is a count of rows. A scan over the quota runs as a standard one
-- and stays unmarked.
ALTER TABLE scans ADD COLUMN deep boolean NOT NULL DEFAULT false;
CREATE INDEX scans_deep_by_org ON scans (org_id, started_at) WHERE deep;
