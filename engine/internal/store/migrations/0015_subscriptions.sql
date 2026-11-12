-- 0015: subscriptions (package plan).
--
-- One row per organization: its offer and the state of its subscription.
-- No row, or a lapsed one, means the free offer (plan.Resolve fails towards
-- the free offer). Payment providers will update these rows; until one is
-- connected, orusctl does (contracts, bank transfers).
CREATE TABLE subscriptions (
    org_id        uuid PRIMARY KEY REFERENCES organizations (id) ON DELETE CASCADE,
    plan          text NOT NULL CHECK (plan IN ('discovery', 'sme', 'pro', 'enterprise')),
    status        text NOT NULL CHECK (status IN ('trialing', 'active', 'canceled')),
    trial_ends_at timestamptz,
    -- End of the paid period; NULL for an active subscription without end
    -- (a contract or a manual grant).
    period_end    timestamptz,
    -- Which provider manages it ("manual" for orusctl), and its reference
    -- there, for the webhooks to come.
    provider      text NOT NULL DEFAULT 'manual' CHECK (length(provider) BETWEEN 1 AND 40),
    provider_ref  text CHECK (length(provider_ref) <= 200),
    updated_at    timestamptz NOT NULL DEFAULT now(),
    CHECK (status <> 'trialing' OR trial_ends_at IS NOT NULL)
);

-- The API reads its organization's subscription; writes are the worker's
-- and orusctl's (and later the payment webhooks').
GRANT SELECT ON subscriptions TO orus_app;

ALTER TABLE subscriptions ENABLE ROW LEVEL SECURITY;
ALTER TABLE subscriptions FORCE ROW LEVEL SECURITY;
CREATE POLICY org_isolation ON subscriptions
    USING (org_id = nullif(current_setting('app.org_id', true), '')::uuid)
    WITH CHECK (org_id = nullif(current_setting('app.org_id', true), '')::uuid);

-- Every new organization starts a 14-day trial of the Essentiel offer
-- (plan.TrialDays), whoever creates it: signup, orusctl, tests. The trigger
-- runs as the table owner (SECURITY DEFINER) so the auth role, which creates
-- organizations at signup, needs no right on subscriptions; FORCE ROW LEVEL
-- SECURITY applies to the owner too, hence the scoped app.org_id, restored
-- afterwards for the caller's transaction.
CREATE FUNCTION start_trial() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path FROM CURRENT AS $$
DECLARE
    prev text := current_setting('app.org_id', true);
BEGIN
    PERFORM set_config('app.org_id', NEW.id::text, true);
    INSERT INTO subscriptions (org_id, plan, status, trial_ends_at)
    VALUES (NEW.id, 'sme', 'trialing', now() + interval '14 days');
    PERFORM set_config('app.org_id', coalesce(prev, ''), true);
    RETURN NEW;
END
$$;

CREATE TRIGGER organizations_start_trial AFTER INSERT ON organizations
    FOR EACH ROW EXECUTE FUNCTION start_trial();

-- Organizations that exist before this migration (development and test
-- ones: nothing is sold yet) keep everything they had: Pro, without end.
-- Change them with orusctl org plan.
DO $$
DECLARE
    o uuid;
BEGIN
    FOR o IN SELECT id FROM organizations LOOP
        PERFORM set_config('app.org_id', o::text, true);
        INSERT INTO subscriptions (org_id, plan, status) VALUES (o, 'pro', 'active');
    END LOOP;
    PERFORM set_config('app.org_id', '', true);
END
$$;
