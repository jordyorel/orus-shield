-- 0011: forgotten-password requests.
--
-- They are written to auth_log (action password_reset.requested) and
-- counted per email and per IP for their rate limit, like failed logins.
CREATE INDEX auth_log_reset_by_email ON auth_log (email, at) WHERE action = 'password_reset.requested';
CREATE INDEX auth_log_reset_by_ip    ON auth_log (ip, at)    WHERE action = 'password_reset.requested';
