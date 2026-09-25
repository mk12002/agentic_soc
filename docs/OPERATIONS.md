# Operations runbook

## Run

| Task | Command |
|---|---|
| API + console | `python -m soc_platform serve` (or the `api` container) |
| Scheduled jobs | `python -m soc_platform scheduler` (or the `scheduler` container; several replicas are safe) |
| Run every job once | `python -m soc_platform scheduler --once` |
| Create schema | `python -m soc_platform init-db` |
| Demo on fixtures | `python -m soc_platform demo` |

Environment: see `.env.example`. Secrets are read from `<NAME>_FILE` (vault mount) or `<NAME>`.

## Jobs

| Job | Default interval | Does |
|---|---|---|
| incident | 5 min | ingest alerts, cluster, investigate |
| phishing | 2 min | pull reported mail, analyse |
| vulnerability | 6 h | ingest, consolidate, enrich, prioritise, Wiz misconfigurations |
| follow_up | 24 h | ITSM ticket sync (+ closure validation), follow-ups, exception expiry |
| intelligence | 10 min | risk + correlation + drift, insight narration |
| daily_report | 24 h | daily exposure report |
| retention | 24 h | prune raw payloads / emails / prompts / access log per policy |

Intervals: `SOC_JOB_<NAME>_SECONDS`. Every run is recorded (`GET /api/v1/jobs`, Integrations screen). A job
failing 3 runs in a row is marked **dead_letter** and raises a high insight; fix the cause and use
*Run now* / `POST /api/v1/jobs/{name}/run`. Jobs are idempotent, so replays never duplicate incidents or actions.

## Monitoring

* `/health` - DB, audit-chain verification, kill switch.
* `/metrics` - Prometheus: open cases, actions by status, insights, unresolved entities, per-stream sync age,
  kill switch. Scrape with an **auditor service-account key** (`X-API-Key`).
* Integrations screen - connector state (healthy / stale / error / misconfigured), freshness per stream against
  its expected cadence, reconciliation, job runs.
* Overview - enrichment latency (median/p95 per domain and per tool) and verdict-quality drift.

Alert on: `soc_connector_last_success_age_seconds` above the stream's cadence, any `dead_letter` job,
`soc_kill_switch == 1`, `/health` audit chain false.

## Access management

* Roles come from Entra app roles `SOC.<Role>` or `SOC.<Role>.<Domain>` (Domain = Phishing | Incident |
  Vulnerability) plus platform grants (Access screen / `/api/v1/admin/roles`), which are time-bound and audited.
  Nobody can grant or revoke their own access.
* Step-up MFA: with `SOC_REQUIRE_MFA=1` (default in prod) approvals, policy, kill switch and access management
  need a token whose `amr` contains `mfa` (or the Conditional Access auth context `SOC_MFA_AUTH_CONTEXT`).
* Service accounts: API keys (Access screen) - hashed, expiring (≤ 365 days), roles limited to analyst / auditor
  / automation_admin, and never able to approve, change policy or manage access. Shown once.
* Suspected compromise of an operator: `POST /api/v1/admin/revoke-sessions` (all their tokens become invalid);
  a single token: `POST /api/v1/auth/logout`.

## Break-glass

For Entra outages only. Generate a long random secret, store it sealed (two custodians), and configure only its
hash: `SOC_BREAKGLASS_SHA256=$(printf %s "$SECRET" | sha256sum | cut -d' ' -f1)`. Use it with the header
`X-Break-Glass: <secret>`. Every use and every failed attempt is audited and raises a critical insight. After use:
review the access log, rotate the secret, record the incident.

## Kill switch

Console *Policy* → kill switch, or `POST /api/v1/kill-switch?on=true` (lead / admin / automation admin, MFA).
It is stored in the database, so every API replica and the scheduler stop executing actions immediately and it
survives restarts. `SOC_KILL_SWITCH=1` forces it on from configuration.

## Data protection

* `SOC_DATA_KEY` (Fernet; comma-separated for rotation, first encrypts) encrypts raw payloads and reported
  emails at rest; mandatory in prod. Rotate: prepend a new key, keep the old one until retention has cycled.
* Retention: `SOC_RAW_RETENTION_DAYS` (180), `SOC_LLM_LOG_RETENTION_DAYS` (180), `SOC_ACCESS_LOG_RETENTION_DAYS`
  (400). Emails of open cases are kept (legal hold). The audit log is never pruned by the platform.
* Audit export for archiving/SIEM: `GET /api/v1/audit/export` (JSON Lines with chain verification).
* Compliance evidence pack: *Reports* → compliance (`POST /api/v1/reports/compliance`, auditor / lead / admin).

## Backups

Back up the database (point-in-time), the raw payload volume and the report volume. The audit chain can be
verified after restore with `GET /api/v1/audit/verify`.

## Connector changes

See [CONNECTORS.md](CONNECTORS.md). Changing a tool = enabling another connector in `config/connectors.yaml`.
