-- Bootstrap a separate database for Langfuse on the same Postgres instance.
-- Idempotent: only runs on first volume init.
SELECT 'CREATE DATABASE langfuse OWNER ztuser'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'langfuse')\gexec
