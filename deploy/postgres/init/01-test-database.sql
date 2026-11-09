-- Runs once, when the PostgreSQL volume is first created.
-- Integration tests use this separate database so they never touch dev data.
CREATE DATABASE orus_test OWNER orus;
