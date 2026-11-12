-- 0017: the deep scan profile ("Approfondi").
--
-- It scans more than 1 000 ports, identifies versions and runs the deep
-- web scan: more load on the customer's servers, traffic a host may take
-- for an attack. The customer chooses it with an explicit consent, kept
-- here: who confirmed being allowed to have these servers tested, and
-- when. The worker runs deep scans only with a consent on record.
ALTER TABLE org_settings DROP CONSTRAINT org_settings_profile_check;
ALTER TABLE org_settings ADD CONSTRAINT org_settings_profile_check
    CHECK (profile IN ('quick', 'standard', 'deep'));
ALTER TABLE org_settings ADD COLUMN deep_consent_at timestamptz;
ALTER TABLE org_settings ADD COLUMN deep_consent_by text CHECK (length(deep_consent_by) <= 300);
ALTER TABLE org_settings ADD CONSTRAINT org_settings_deep_needs_consent
    CHECK (profile <> 'deep' OR deep_consent_at IS NOT NULL);
