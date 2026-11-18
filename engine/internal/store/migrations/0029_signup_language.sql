-- 0029: the language of a signup, so its emails and the new account
-- speak the language the person signed up in (the page's language).
--
-- NULL for requests made before this migration: French, as before.
ALTER TABLE signup_requests ADD COLUMN lang text CHECK (lang IN ('fr', 'en'));
