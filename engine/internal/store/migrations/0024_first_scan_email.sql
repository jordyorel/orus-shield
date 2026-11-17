-- 0024: the first scan's summary email.
--
-- When a domain's first scan finishes, its admins get one email that sums
-- it up (score, open findings by severity, names found) and links to the
-- dashboard. It is a welcome, not an alert: every offer gets it, the email
-- switch of Réglages still applies. FinishScan queues it in its transaction.
ALTER TABLE notifications DROP CONSTRAINT notifications_kind_check;
ALTER TABLE notifications ADD CONSTRAINT notifications_kind_check
    CHECK (kind IN ('new_findings', 'emerging_threat', 'first_scan'));
