-- Ownership verification (roadmap step 5, security rule 1).
--
-- A target gets a random token; the customer publishes it as
--   _orus-verify.<domain> TXT "orus-verify=<token>"
-- Once seen, verified_at is set and the token is kept: workers re-check that
-- the record is still there before active scans.

ALTER TABLE targets
    ADD COLUMN verify_token            text,
    -- Deadline to publish the record. NULL once verified: the token then
    -- stays valid for as long as the record is published.
    ADD COLUMN verify_token_expires_at timestamptz,
    -- Last time the record was checked successfully.
    ADD COLUMN verify_checked_at       timestamptz,
    -- A target can never be verified without a token.
    ADD CONSTRAINT verified_needs_token CHECK (verified_at IS NULL OR verify_token IS NOT NULL);
