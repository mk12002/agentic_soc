# Operations runbook

## Run

| Task | Command |
|---|---|
| API + console | `python -m soc_platform serve` (or the `api` container) |
| Scheduled jobs | Built into `serve` (on by default). For a dedicated service set `SOC_EMBEDDED_SCHEDULER=0` on the API and run `python -m soc_platform scheduler` (the `platform-scheduler` container). Any number of schedulers is safe. |
| Run every job once | `python -m soc_platform scheduler --once` |
| Create schema | `python -m soc_platform init-db` |
| Demo on fixtures | `python -m soc_platform demo` |
| Start a demo again from nothing | `python -m soc_platform reset-demo [--yes]` (server stopped; refuses in prod; demo databases only - the audit log goes too) |

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

**An organisation's own LLM gateway** (one internal endpoint in front of Claude, Gemini and OpenAI models) is a
configuration change, not a code change - full walkthrough in `docs/CLIENT_DEPLOYMENT_GUIDE.md` section 5:

| Setting | Default | Meaning |
|---|---|---|
| `SOC_LLM_PROVIDER` | `none` | `openai_compatible` for a gateway exposing `/v1/chat/completions`; `anthropic` for one exposing the Claude Messages API |
| `SOC_LLM_AUTH_HEADER` / `SOC_LLM_AUTH_PREFIX` | `Authorization` / `Bearer ` | header and prefix carrying `SOC_LLM_API_KEY` (openai_compatible) |
| `SOC_LLM_EXTRA_HEADERS` | empty | JSON object of fixed, non-secret headers the gateway requires |
| `SOC_LLM_CA_BUNDLE` | empty | CA file for an internally issued gateway certificate |
| `SOC_LLM_JSON_MODE` | `1` | `0` when the gateway or model rejects `response_format`; JSON is then requested in the instructions |
| `SOC_LLM_SERVER_FALLBACK` | `1` | `anthropic` only: `0` if the gateway does not pass the Claude API's beta refusal fallback through |
| `SSL_CERT_FILE` | empty | CA bundle for every outbound TLS connection (connectors to internal consoles too) |

Check: `GET /api/v1/llm/status`; live test: `SOC_LIVE_LLM=1 pytest soc_platform/tests/test_live_llm.py` (costs
tokens; a full demo run is about 50k). Prompts (redacted) and responses are kept for `SOC_LLM_LOG_RETENTION_DAYS`.

## Jobs

| Job | Default interval | Does |
|---|---|---|
| vulnerability | 6 h | ingest, consolidate, enrich, prioritise, Wiz misconfigurations; keep the risk register current (new P1 CVEs proposed, entries updated / marked remediated) |
| incident | 5 min | ingest alerts, cluster, investigate; reassess open incidents when KEV-listed exposure appeared on their hosts since they were scored; commit the cases, then add the model's explanations in parallel |
| phishing | 2 min | pull reported mail, analyse; commit the verdicts, then add the model's explanations in parallel |
| follow_up | 24 h | ITSM ticket sync (+ closure validation), weekly follow-up per remediation plan (`SOC_VM_FOLLOWUP_DAYS`, default 7), exception expiry |
| intelligence | 10 min | risk + correlation + drift, insight narration |
| daily_report | 24 h | daily exposure report |
| weekly_reports | 7 days | weekly VM report (Word) and weekly management deck (PowerPoint), in Reports |
| retention | 24 h | prune raw payloads / emails / prompts / access log per policy |
| self_check | 1 h | platform consistency checks (see below) |
| notify | 1 min | send new findings at or above the threshold to the configured Teams / Slack / webhook channels; retry failures |

When several jobs are due at once (first start) they run in this order, vulnerability first, so incidents are
scored knowing which hosts are exposed. Intervals: `SOC_JOB_<NAME>_SECONDS` (`SOC_JOB_NOTIFY_SECONDS` for notify). Every run is recorded (`GET /api/v1/jobs`, Integrations screen). A job
failing 3 runs in a row is marked **dead_letter** and raises a high insight; fix the cause and use
*Run now* / `POST /api/v1/jobs/{name}/run`. Jobs are idempotent, so replays never duplicate incidents or actions.

**Deferred explanations.** The incident and phishing jobs decide verdict, severity, evidence and recommendations
without the model, commit, and only then ask the model for the written explanations, all of a run's cases at once
(`SOC_LLM_CONCURRENCY`). A case is usable seconds earlier; its page says "the written explanation is being prepared"
until the model's text arrives. If a run stops between the two steps, the next run finishes the explanations
(cases created in the last 7 days).

## Notifications

Findings at or above a severity are pushed to where people already are.

```
SOC_NOTIFY_WEBHOOKS=teams|https://<tenant>.webhook.office.com/...,slack|https://hooks.slack.com/services/...,json|https://siem.example/hook
SOC_NOTIFY_MIN_SEVERITY=high          # informational | low | medium | high | critical
SOC_PUBLIC_URL=https://soc.example    # optional: messages link to the console
```

* Destinations come only from this setting and must be `https://` (`http://` only to localhost for testing).
* Each finding is sent once per channel; an escalation to a higher severity is sent again.
* Operational alerts are findings too, so a dead-lettered job, break-glass use, a failing self-check and the LLM
  budget reach the channel as well.
* A failed delivery is retried every run, up to 5 attempts, then left recorded as failed. The `notifications`
  table stores the channel as `kind:host` only - the webhook URL (which contains its secret) is never stored or
  shown.
* Check: Integrations → *Notifications* card, or `GET /api/v1/admin/notifications` (auditor / admin, all-domain scope).
* Prove a channel: **Send test message** on that card, or `POST /api/v1/admin/notifications/test` (`manage_connectors`:
  admin or automation admin). One marked test message per channel, a result per channel; audited as `notify.test`
  and not counted as a delivery.
  The webhook URLs carry their own credentials: keep them in the vault and mount them as `SOC_NOTIFY_WEBHOOKS_FILE`.

## Resilience settings

| Setting | Default | Purpose |
|---|---|---|
| `SOC_LLM_TIMEOUT_SECONDS` / `SOC_LLM_TIMEOUT_LARGE_SECONDS` / `SOC_LLM_CONNECT_TIMEOUT_SECONDS` | 30 / 120 / 10 | Read timeout for small-tier (short) and large-tier (long answers, ~2,000 tokens) calls; connect timeout. One retry on 429 / 5xx |
| `SOC_LLM_BREAKER_FAILURES` / `SOC_LLM_BREAKER_SECONDS` | 3 / 60 | Circuit breaker: skip the model after repeated failures, answer from the deterministic path |
| `SOC_LLM_CONCURRENCY` | 4 | Model calls in flight at once for batches (finding narratives, report sections); keep under the provider's rate limit |
| `SOC_BRIEF_CACHE_SECONDS` | 900 | Reuse an unchanged situation brief |
| `SOC_LLM_EXPLAIN_AUTO_CLOSED` | 0 | 1 = the model also explains reports that auto-close |
| `SOC_PHISHING_ENGINE` | auto | The trained ML engine analyses reported e-mail with the heuristic analyser: `auto` = when the engine's libraries are installed (`requirements/phishing.txt`: scikit-learn, XGBoost, LangGraph; no PyTorch), `1` = on, `0` = heuristic only |
| `SOC_PHISHING_SANDBOX` | 0 | 1 = also run the engine's sandbox agent (only with an isolated detonation host configured; without one its static fallback measured no better than chance) |
| `SOC_PHISHING_ENGINE_LOG_LEVEL` | WARNING | Log level of the in-process engine (it logs every decision step at INFO) |
| `SOC_VM_FOLLOWUP_DAYS` | 7 | At most one follow-up per remediation plan per this many days |
| `SOC_EMBEDDED_SCHEDULER` | 1 | The API server runs the scheduler itself; 0 when a separate scheduler service runs the jobs |
| `SOC_SCHEDULER_START_DELAY` | 5 | Seconds after start-up before the built-in scheduler begins |
| `SOC_SCHEDULER_STALE_SECONDS` | 180 | No scheduler heartbeat for this long: `/health` reports `stale` and every screen shows "Scheduler stopped" (a job running past its 30-minute lease shows "Scheduler stuck") |
| `SOC_SELF_CHECK_CONFIRM_SECONDS` | 2 | The self-check re-runs a failing check before alerting |

Failure behaviour for each dependency: [FAILURE_MODES.md](FAILURE_MODES.md). Cost and budget sizing:
[LLM_TOKENS_AND_COST.md](LLM_TOKENS_AND_COST.md).

## Sample estates

`scripts/build_estate_variant.py OUT --seed N [--scale X]` generates a different organisation (names, machines, IP
plan, suppliers, volumes) with its own tenant connector settings (`fixtures/settings.json`). Run the platform on it
with `SOC_FIXTURES_DIR=OUT/fixtures SOC_SUPPLIERS_FILE=OUT/suppliers.yaml SOC_ORG_DOMAINS=<org>`, and the browser tour
with `SOC_TOUR_ESTATE=OUT/estate.json`.

## Testing on PostgreSQL and across time

- **PostgreSQL (the production engine):** `SOC_TEST_POSTGRES=postgresql://user:pw@host:port/postgres pytest
  soc_platform/tests` runs the whole suite on PostgreSQL. Each test database becomes a fresh PostgreSQL database.
  Without a server, `pip install pgserver` gives an embedded one. The normal SQLite run already enforces
  PostgreSQL's rules: text wider than its column, 32-bit integer overflow and NUL characters fail the test. So bugs
  that only production would show are caught on every run.
- **Time travel (tests only):** `SOC_CLOCK_OFFSET_SECONDS` moves the platform clock forward. It is ignored when
  `SOC_ENVIRONMENT=prod`. `test_time.py` uses it to check:
  - SLAs falling due, with every screen agreeing at each point in time
  - the token budget rolling over at the month boundary
  - retention pruning old mail while keeping mail of open cases
  - risk decay
- **Schema upgrades:** start-up creates new tables and adds new *optional* (nullable) columns to existing tables,
  on SQLite and PostgreSQL. On PostgreSQL it also widens any text column that the model defines wider than the
  table. All of this is safe and loses no data. Columns are never narrowed, renamed or dropped automatically; a new
  required column is logged as needing a scripted migration. `test_schema.py` checks it on both engines.
- **Accessibility:** the browser tour runs axe-core (WCAG 2.1 A/AA) on every screen in both themes. Serious and
  critical findings fail the tour.

## Platform self-check

`self_check` runs hourly (`SOC_JOB_SELF_CHECK_SECONDS`). It recomputes each shared figure through every code path,
resolves every stored reference, looks for duplicates re-runs must never create, and verifies the audit chain. A
failure raises a high-severity *Platform self-check* finding (resolved automatically when consistent again). On
demand: `GET /api/v1/admin/self-check` (auditor / admin, all-domain scope) or the card on the Integrations screen.

## Network edge (reverse proxy, rate limit)

| Setting | Default | Meaning |
|---|---|---|
| `SOC_TRUSTED_PROXIES` | empty | Comma-separated addresses of your reverse proxies / gateways. Only a request whose direct peer is listed has its `X-Forwarded-For` read, and then the client is the **right-most** hop that is not itself a listed proxy (proxies append to the header, so its left-most entries are whatever the caller sent). The same peers' `X-Forwarded-Proto: https` turns on HSTS. List only real proxies. |
| `SOC_RATE_LIMIT_RPS` / `SOC_RATE_LIMIT_BURST` | 20 / 120 | Per-client token bucket, in process. Put a gateway / WAF limit in front for several replicas. |

## Monitoring

* `/health` - DB, audit-chain verification, kill switch.
* `/metrics` - Prometheus: open cases, actions by status, insights, unresolved entities, per-stream sync age,
  kill switch. Scrape with an **all-domain auditor service-account key** (`X-API-Key`). It carries every domain's
  counts, so a domain-scoped key gets 403.
* Integrations screen - connector state (healthy / stale / error / misconfigured), freshness per stream against
  its expected cadence, reconciliation, job runs.
* Overview - enrichment latency (median/p95 per domain and per tool) and verdict-quality drift.

Alert on: `soc_connector_last_success_age_seconds` above the stream's cadence, any `dead_letter` job,
`soc_kill_switch == 1`, `/health` audit chain false.

## Access management

* **Console sign-in (production):** `SOC_AUTH_MODE=entra` with `SOC_ENTRA_TENANT_ID` and `SOC_ENTRA_AUDIENCE`
  (`api://<app-id>`). The console runs the Entra ID authorization-code flow with PKCE itself (SPA redirect URI =
  the console's origin + `/`); `SOC_ENTRA_SPA_CLIENT_ID` / `SOC_ENTRA_SCOPE` override the client id and scope when
  the console has its own app registration. The API must issue v2.0 access tokens
  (`requestedAccessTokenVersion: 2` in its manifest). Step-by-step: `docs/CLIENT_DEPLOYMENT_GUIDE.md` section 3.
* Roles come from Entra app roles `SOC.<Role>` or `SOC.<Role>.<Domain>` (Domain = Phishing | Incident |
  Vulnerability) plus platform grants (Access screen / `/api/v1/admin/roles`), which are time-bound and audited.
  Nobody can grant or revoke their own access, and a domain-scoped administrator can grant only their own domains.
* **Each role keeps its own scope.** A user *sees* every domain any of their roles covers, but a permission counts
  only where the role that grants it applies. For example, `SOC.Lead.Phishing` plus `SOC.Auditor` reads all domains
  but approves phishing actions only, and a platform grant of auditor on all domains never widens a scoped lead.
  Decisions that span domains (the autonomy policy, compliance evidence export, correlated findings) need an
  all-domain role. `GET /api/v1/me` shows `role_scopes`.
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
