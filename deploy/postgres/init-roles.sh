#!/bin/sh
# Runs once, when the PostgreSQL volume is first initialised (docker-entrypoint-initdb.d). Least privilege:
#   POSTGRES_USER  owns the schema: only the one-shot platform-migrate service signs in with it (init-db)
#   soc_app        the running platform (API, scheduler): read / write, append-only audit_log (granted by init-db
#                  through SOC_DB_RUNTIME_ROLE), no schema changes
#   soc_engine     the phishing ML engine (only when SOC_ENGINE_DB_PASSWORD is set): its own database, nothing else
# and network connections must use TLS (hostssl).
set -eu
: "${SOC_APP_DB_PASSWORD:?set SOC_APP_DB_PASSWORD}"
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" -v app_pw="$SOC_APP_DB_PASSWORD" <<'SQL'
CREATE ROLE soc_app LOGIN PASSWORD :'app_pw';
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
GRANT CONNECT ON DATABASE :"DBNAME" TO soc_app;
SQL
if [ -n "${SOC_ENGINE_DB_PASSWORD:-}" ]; then
  psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" -v engine_pw="$SOC_ENGINE_DB_PASSWORD" <<'SQL'
CREATE ROLE soc_engine LOGIN PASSWORD :'engine_pw';
CREATE DATABASE soc_engine OWNER soc_engine;
REVOKE ALL ON DATABASE soc_engine FROM PUBLIC;
SQL
fi
# TLS for every connection that is not the local socket
sed -i 's/^host\([[:space:]]\)/hostssl\1/' "$PGDATA/pg_hba.conf"
