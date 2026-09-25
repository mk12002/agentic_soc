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

## LLM (optional)

Everything works without an LLM. To enable narratives, deep analysis and prompt-planned reports with Azure AI
Foundry (verified live):

```
SOC_LLM_PROVIDER=azure_foundry
SOC_LLM_ENDPOINT=https://<resource>.services.ai.azure.com/openai/v1
SOC_LLM_API_KEY=<key>                      # or SOC_LLM_API_KEY_FILE=/run/secrets/llm_key
SOC_LLM_DEPLOYMENT=gpt-4.1-mini            # SOC_LLM_DEPLOYMENT_SMALL for a cheaper routine tier
SOC_LLM_APPROVED_ENDPOINTS=https://<resource>.services.ai.azure.com/openai/v1   # anything else is refused
SOC_LLM_MODEL_VERSION=gpt-4.1-mini         # responses from another model are logged as a mismatch
SOC_LLM_MONTHLY_TOKEN_BUDGET=50000000      # finding at 80 % and 100 %; deterministic fallback when exhausted
```

Check: `GET /api/v1/llm/status`; live test: `SOC_LIVE_LLM=1 pytest soc_platform/tests/test_live_llm.py` (costs
tokens; a full demo run is about 50k). Prompts (redacted) and responses are kept for `SOC_LLM_LOG_RETENTION_DAYS`.

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

## Resilience settings

| Setting | Default | Purpose |
|---|---|---|
| `SOC_LLM_TIMEOUT_SECONDS` / `SOC_LLM_TIMEOUT_LARGE_SECONDS` / `SOC_LLM_CONNECT_TIMEOUT_SECONDS` | 30 / 120 / 10 | Read timeout for small-tier (short) and large-tier (long answers, ~2,000 tokens) calls; connect timeout. One retry on 429 / 5xx |
| `SOC_LLM_BREAKER_FAILURES` / `SOC_LLM_BREAKER_SECONDS` | 3 / 60 | Circuit breaker: skip the model after repeated failures, answer from the deterministic path |
| `SOC_BRIEF_CACHE_SECONDS` | 900 | Reuse an unchanged situation brief |
| `SOC_LLM_EXPLAIN_AUTO_CLOSED` | 0 | 1 = the model also explains reports that auto-close |
| `SOC_SCHEDULER_STALE_SECONDS` | 1800 | `/health` reports the scheduler as stopped (banner on every screen) |
| `SOC_SELF_CHECK_CONFIRM_SECONDS` | 2 | The self-check re-runs a failing check before alerting |

Failure behaviour for each dependency: [FAILURE_MODES.md](FAILURE_MODES.md). Cost and budget sizing:
[LLM_TOKENS_AND_COST.md](LLM_TOKENS_AND_COST.md).

## Sample estates

`scripts/build_estate_variant.py OUT --seed N [--scale X]` generates a different organisation (names, machines, IP
plan, suppliers, volumes) with its own tenant connector settings (`fixtures/settings.json`). Run the platform on it
with `SOC_FIXTURES_DIR=OUT/fixtures SOC_SUPPLIERS_FILE=OUT/suppliers.yaml SOC_ORG_DOMAINS=<org>`, and the browser tour
with `SOC_TOUR_ESTATE=OUT/estate.json`.

## Platform self-check

`self_check` runs hourly (`SOC_JOB_SELF_CHECK_SECONDS`). It recomputes each shared figure through every code path,
resolves every stored reference, looks for duplicates re-runs must never create, and verifies the audit chain. A
failure raises a high-severity *Platform self-check* finding (resolved automatically when consistent again). On
demand: `GET /api/v1/admin/self-check` (auditor / admin, all-domain scope) or the card on the Integrations screen.

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

## Where data is stored

| Data | Store | Protection |
|---|---|---|
| Cases, entities and relations, actions, findings, insights, jobs, policies, grants, saved report templates | Database (`SOC_DATABASE_URL`; PostgreSQL in prod) | DB access control; audit and access log append-only |
| Audit chain, access log, LLM call log (redacted prompts + responses) | Database | Hash chain (audit); retention jobs for access / LLM logs |
| Raw vendor payloads and reported emails | `SOC_RAW_PAYLOAD_DIR` | Encrypted (Fernet), retention with legal hold |
| Generated reports, post-incident reports, compliance packs | `SOC_REPORT_OUTPUT_DIR` | Encrypted; decrypted only on an authorised, scope-checked download |
| Attack stories | Not stored - rebuilt from records on request; only the deep-analysis result is cached on the case | - |
| Phishing ML engine stores (optional) | As configured in the engine deployment | See engine docs |

## Data protection

* `SOC_DATA_KEY` (Fernet; comma-separated for rotation, first encrypts) encrypts raw payloads and reported
  emails, generated reports and evidence packs at rest; mandatory in prod. Rotate: prepend a new key, keep the old one until retention has cycled.
* Retention: `SOC_RAW_RETENTION_DAYS` (180), `SOC_LLM_LOG_RETENTION_DAYS` (180), `SOC_ACCESS_LOG_RETENTION_DAYS`
  (400). Emails of open cases are kept (legal hold). The audit log is never pruned by the platform.
* Audit export for archiving/SIEM: `GET /api/v1/audit/export` (JSON Lines with chain verification).
* Compliance evidence pack: *Reports* → compliance (`POST /api/v1/reports/compliance`, auditor / lead / admin).

## Backups

Back up the database (point-in-time), the raw payload volume and the report volume. The audit chain can be
verified after restore with `GET /api/v1/audit/verify`.

## Connector changes

See [CONNECTORS.md](CONNECTORS.md). Changing a tool = enabling another connector in `config/connectors.yaml`.
