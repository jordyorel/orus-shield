-- 0036: our own email before a paid trial ends (kind trial_ending).
--
-- Paddle, the merchant of record, sends the legal reminder before it
-- charges the card. Ours is about the product: what the trial found and
-- fixed, what continues, and how to cancel before the date. The worker
-- queues it three days before the end of a trial a payment provider runs
-- (store.QueueTrialEndings, one per activated admin and trial end); the
-- notifier checks at delivery that the trial still runs and still ends then.
--
-- It belongs to the organization, not to a domain or a scan: target_id and
-- scan_id become optional. The composite foreign key to targets accepts a
-- NULL target (MATCH SIMPLE).
ALTER TABLE notifications ALTER COLUMN target_id DROP NOT NULL;
ALTER TABLE notifications ALTER COLUMN scan_id DROP NOT NULL;

ALTER TABLE notifications DROP CONSTRAINT notifications_kind_check;
ALTER TABLE notifications ADD CONSTRAINT notifications_kind_check
    CHECK (kind IN ('new_findings', 'emerging_threat', 'first_scan', 'trial_nudge', 'trial_ending'));

-- The scheduled lookup for trials near their end.
CREATE INDEX subscriptions_trial_ends ON subscriptions (trial_ends_at) WHERE status = 'trialing';
