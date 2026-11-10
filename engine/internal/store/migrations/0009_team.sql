-- 0009: organization admins manage their team from the dashboard.
--
-- Until now only orusctl (the schema owner) could create accounts and
-- memberships. The API's authentication role gets the smallest rights for
-- inviting, changing a role and removing a member; which organization an
-- admin may touch is checked by the API (store.Auth team methods take the
-- organization the caller is an admin of, with a second factor).
--
-- users: insert the email only (no password, no flags); the password is
-- set later by the invitee with the one-time setup token.
GRANT INSERT (email)                ON users        TO orus_auth;
-- memberships: add, change the role, remove.
GRANT INSERT, UPDATE (role), DELETE ON memberships  TO orus_auth;
-- setup_tokens: issue the invitee's one-time token.
GRANT INSERT                        ON setup_tokens TO orus_auth;
