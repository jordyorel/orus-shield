-- Two-factor authentication with TOTP codes (roadmap step 7.6, MFA).
--
-- MFA is mandatory for admins: the API refuses an admin's organization
-- routes unless their session was opened with a second factor.

-- One row per user who started enrolment. enabled_at is NULL until the
-- user confirms with a first valid code.
CREATE TABLE user_mfa (
    user_id       uuid PRIMARY KEY REFERENCES users (id) ON DELETE CASCADE,
    -- The TOTP secret, encrypted with AES-256-GCM under ORUS_MFA_KEY
    -- (package seal): a copy of this table generates no code.
    secret_sealed bytea NOT NULL CHECK (length(secret_sealed) BETWEEN 29 AND 256),
    created_at    timestamptz NOT NULL DEFAULT now(),
    enabled_at    timestamptz,
    -- The last time step whose code was accepted. A code is only accepted
    -- for a later step: an intercepted code cannot be replayed.
    last_step     bigint NOT NULL DEFAULT 0 CHECK (last_step >= 0)
);

-- One-time codes for a lost phone, shown once at enrolment. Only their
-- SHA-256 is kept: they are random (80 bits), so a fast hash is enough.
CREATE TABLE recovery_codes (
    user_id    uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    code_hash  bytea NOT NULL CHECK (length(code_hash) = 32),
    created_at timestamptz NOT NULL DEFAULT now(),
    used_at    timestamptz,
    PRIMARY KEY (user_id, code_hash)
);

-- The step between a correct password and the code: a short-lived,
-- single-use token (hashed) that names the user without opening a session.
CREATE TABLE mfa_challenges (
    token_hash bytea PRIMARY KEY CHECK (length(token_hash) = 32),
    user_id    uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    ip         text NOT NULL
);

CREATE INDEX mfa_challenges_by_user ON mfa_challenges (user_id);

-- Whether the session was opened (or upgraded) with a second factor.
ALTER TABLE sessions ADD COLUMN mfa boolean NOT NULL DEFAULT false;

GRANT SELECT, INSERT, UPDATE, DELETE ON user_mfa       TO orus_auth;
GRANT SELECT, INSERT, UPDATE, DELETE ON recovery_codes TO orus_auth;
GRANT SELECT, INSERT, DELETE         ON mfa_challenges TO orus_auth;
