-- 0023: the 14-day trial needs a card (decided 2026-11-13).
--
-- A new organization now starts on the free offer. Its trial of Essentiel
-- or Pro starts at checkout: the customer gives a card or PayPal to Paddle,
-- which charges at the end of the 14 days unless the trial is canceled
-- (Paddle's trial prices, ORUS_PADDLE_TRIAL_PRICE_*). One trial per
-- organization: an organization that ever had a Paddle customer pays from
-- the first day (see api.checkout).
--
-- Organizations created before keep the subscription they have.
CREATE OR REPLACE FUNCTION start_trial() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path FROM CURRENT AS $$
DECLARE
    prev text := current_setting('app.org_id', true);
BEGIN
    PERFORM set_config('app.org_id', NEW.id::text, true);
    INSERT INTO subscriptions (org_id, plan, status)
    VALUES (NEW.id, 'discovery', 'active');
    PERFORM set_config('app.org_id', coalesce(prev, ''), true);
    RETURN NEW;
END
$$;

COMMENT ON FUNCTION start_trial() IS
    'Every new organization starts on the free offer; trials start at checkout, with a card (0023).';
