-- 0010: scheduled scans.
--
-- A target may have a schedule: frequency, weekday, hour and time zone
-- (wall-clock time of the customer, see package schedule) and the modules
-- to run. next_scan_at is when the scheduler queues the next scan; the
-- worker's scheduler moves it forward each time. All schedule columns are
-- set together or all NULL (no schedule).
ALTER TABLE targets
    ADD COLUMN schedule_frequency text
        CHECK (schedule_frequency IN ('daily', 'weekly', 'monthly')),
    ADD COLUMN schedule_weekday   smallint CHECK (schedule_weekday BETWEEN 0 AND 6),
    ADD COLUMN schedule_hour      smallint CHECK (schedule_hour BETWEEN 0 AND 23),
    ADD COLUMN schedule_timezone  text CHECK (length(schedule_timezone) BETWEEN 1 AND 64),
    ADD COLUMN schedule_modules   text[] CHECK (cardinality(schedule_modules) BETWEEN 1 AND 50),
    ADD COLUMN next_scan_at       timestamptz,
    ADD CONSTRAINT targets_schedule_complete CHECK (
        (schedule_frequency IS NULL AND schedule_weekday IS NULL AND schedule_hour IS NULL
            AND schedule_timezone IS NULL AND schedule_modules IS NULL AND next_scan_at IS NULL)
        OR
        (schedule_frequency IS NOT NULL AND schedule_weekday IS NOT NULL AND schedule_hour IS NOT NULL
            AND schedule_timezone IS NOT NULL AND schedule_modules IS NOT NULL AND next_scan_at IS NOT NULL));

-- The scheduler looks for due targets across every organization.
CREATE INDEX targets_next_scan_at ON targets (next_scan_at) WHERE next_scan_at IS NOT NULL;
