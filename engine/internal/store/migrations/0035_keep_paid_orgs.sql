-- 0035: an organization whose payment provider subscription still runs
-- cannot be deleted.
--
-- Paddle is the merchant of record: it charges the customer's card, not us.
-- Deleting the organization here would leave its subscription running at
-- Paddle, which would keep sending trial reminders and charging the card for
-- an account that no longer exists (this happened in the sandbox: three
-- organizations deleted by hand left three trials running). The subscription
-- must be canceled at the provider first; its webhook then records it as
-- canceled and the deletion goes through.
--
-- A trigger rather than a check in Go: it holds for every path, a future
-- account deletion, orusctl, or a statement typed by hand. A subscription
-- scheduled for cancellation is already 'canceled' here (Paddle charges
-- nothing more), so it does not block. DROP SCHEMA and TRUNCATE, which tests
-- use, fire no row trigger.
CREATE FUNCTION keep_paid_org() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path FROM CURRENT AS $$
DECLARE
    prev text := current_setting('app.org_id', true);
    ref  text;
    prov text;
BEGIN
    -- FORCE ROW LEVEL SECURITY applies to the owner too: scope the lookup
    -- to this organization, then restore the caller's setting.
    PERFORM set_config('app.org_id', OLD.id::text, true);
    SELECT provider, coalesce(provider_ref, '?') INTO prov, ref
        FROM subscriptions
        WHERE org_id = OLD.id AND provider <> 'manual' AND status IN ('trialing', 'active');
    PERFORM set_config('app.org_id', coalesce(prev, ''), true);
    -- Not FOUND: PERFORM above resets it. ref is never NULL for a row.
    IF ref IS NOT NULL THEN
        RAISE EXCEPTION 'organization % has a running % subscription (%): cancel it there first', OLD.id, prov, ref
            USING ERRCODE = 'restrict_violation';
    END IF;
    RETURN OLD;
END
$$;

CREATE TRIGGER organizations_keep_paid BEFORE DELETE ON organizations
    FOR EACH ROW EXECUTE FUNCTION keep_paid_org();
