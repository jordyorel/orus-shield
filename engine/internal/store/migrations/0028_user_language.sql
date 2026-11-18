-- 0028: each user's language (the product is French and English).
--
-- NULL until the user chooses one in Profil: the dashboard then follows
-- the language chosen on the public site, or the browser's. Emails will
-- follow it too.
ALTER TABLE users ADD COLUMN lang text CHECK (lang IN ('fr', 'en'));
GRANT UPDATE (lang) ON users TO orus_auth;
