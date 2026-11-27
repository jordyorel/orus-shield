-- PostgreSQL roles of a production server. Run by setup.sh as the postgres
-- superuser, before the first migration; idempotent, so it runs again on
-- every setup.sh.
--
-- Two login roles, each the name of an operating system user (peer
-- authentication over the Unix socket, see setup.sh): no database password
-- exists anywhere.
--
--   orus      the schema owner. The worker (and orusctl) connect as it and
--             apply the migrations. BYPASSRLS: the worker processes every
--             organization, and some tables FORCE row-level security even
--             for their owner. Not a superuser, cannot create databases or
--             roles.
--   orus_api  the API. It owns nothing and holds no privilege of its own:
--             every transaction switches to one of the roles below (SET
--             LOCAL ROLE), so a query that forgot to switch fails instead of
--             seeing every organization. It may only read schema_migrations
--             (granted by activate.sh once the table exists), to check at
--             start that the schema is up to date.
--
-- The NOLOGIN roles are those the migrations grant privileges to. A
-- migration creates them when they are missing, which needs a right the
-- owner does not have here: they are created now, and given to the owner
-- WITH ADMIN OPTION so its migrations can grant them. A new migration that
-- creates a role must add it to both lists below (TestProdRolesListEveryRole
-- in engine/internal/store checks it).
--
-- INHERIT FALSE: membership only allows SET ROLE, it does not add the
-- role's privileges to the login role's own.

DO $$
DECLARE
    r text;
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'orus') THEN
        CREATE ROLE orus LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE BYPASSRLS;
    END IF;
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'orus_api') THEN
        CREATE ROLE orus_api LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
    END IF;
    FOREACH r IN ARRAY ARRAY['orus_app', 'orus_auth', 'orus_agent', 'orus_billing', 'orus_public'] LOOP
        IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = r) THEN
            EXECUTE format('CREATE ROLE %I NOLOGIN NOSUPERUSER NOBYPASSRLS', r);
        END IF;
        EXECUTE format('GRANT %I TO orus WITH ADMIN OPTION, INHERIT FALSE, SET TRUE', r);
        EXECUTE format('GRANT %I TO orus_api WITH INHERIT FALSE, SET TRUE', r);
    END LOOP;
END;
$$;

SELECT 'CREATE DATABASE orus OWNER orus'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'orus')
\gexec

-- Nobody else may connect to it.
REVOKE ALL ON DATABASE orus FROM PUBLIC;
GRANT CONNECT ON DATABASE orus TO orus, orus_api;
