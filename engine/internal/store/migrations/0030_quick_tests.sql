-- 0030: the public domain test of the home page (package quicktest).
--
-- quick_tests keeps each test asked: the domain, the asking address (rate
-- limits, and the record of who tested what, rule 4) and the result. A
-- domain tested in the last hour reuses its result (cached), so testing it
-- in a loop does not reach it again. Results are deleted after 30 days.
--
-- quick_test_leads are the visitors who left an email to get the full
-- report. marketing records their separate, optional consent to receive
-- our messages; the report itself is sent either way. Leads stay when
-- their test is deleted (test_id becomes NULL).
--
-- The API reaches both only through the orus_public role (store.Public).
CREATE TABLE quick_tests (
    id         uuid PRIMARY KEY DEFAULT uuidv7(),
    domain     text NOT NULL CHECK (length(domain) BETWEEN 1 AND 253),
    ip         text NOT NULL CHECK (length(ip) <= 64),
    result     jsonb NOT NULL,
    cached     boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX quick_tests_domain ON quick_tests (domain, created_at DESC);
CREATE INDEX quick_tests_ip ON quick_tests (ip, created_at DESC);
CREATE INDEX quick_tests_created ON quick_tests (created_at);

CREATE TABLE quick_test_leads (
    id         uuid PRIMARY KEY DEFAULT uuidv7(),
    test_id    uuid REFERENCES quick_tests (id) ON DELETE SET NULL,
    email      text NOT NULL CHECK (length(email) BETWEEN 3 AND 254),
    domain     text NOT NULL CHECK (length(domain) BETWEEN 1 AND 253),
    lang       text CHECK (lang IN ('fr', 'en')),
    marketing  boolean NOT NULL,
    ip         text NOT NULL CHECK (length(ip) <= 64),
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX quick_test_leads_email ON quick_test_leads (email, created_at DESC);
CREATE INDEX quick_test_leads_ip ON quick_test_leads (ip, created_at DESC);

DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'orus_public') THEN
        CREATE ROLE orus_public NOLOGIN NOSUPERUSER NOBYPASSRLS;
    END IF;
EXCEPTION
    WHEN duplicate_object OR unique_violation THEN NULL;
END;
$$;
GRANT orus_public TO CURRENT_USER;
DO $$
BEGIN
    EXECUTE format('GRANT USAGE ON SCHEMA %I TO orus_public', current_schema());
END;
$$;
GRANT SELECT, INSERT, DELETE ON quick_tests TO orus_public;
GRANT SELECT, INSERT ON quick_test_leads TO orus_public;
