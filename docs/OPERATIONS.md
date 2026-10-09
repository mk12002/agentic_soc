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
| Check the settings and the connector configuration | `python -m soc_platform config check [FILE] [--no-env]` - every problem in the `SOC_*` settings and in the connector configuration, each with how to fix it; exit 1 on errors |
| Check a tool before it goes live | `python -m soc_platform preflight NAME ... \| --all` (also the *Preflight* button on Integrations) |
| Export / compare / import the configuration | `python -m soc_platform config export [--out F]`, `config diff F`, `config import F --by EMAIL` (import = a proposal approved in the console) |
| Add a tool | `python -m soc_platform connector new NAME --category CAT --tool "Vendor Product"`, then `connector check NAME` |

`serve` and `scheduler` refuse to start when `config/connectors.yaml` has errors (a misspelled tool, key or stage,
broken YAML): those used to be ignored silently. A live tool whose secret is missing does *not* stop a start - it is
isolated and shown on Integrations, and every other tool works.

They also refuse to start when a `SOC_*` setting cannot be read - a word where a number belongs (`SOC_API_WORKERS=four`),
a value out of range, an unknown choice (`SOC_ENVIRONMENT=production`), a malformed URL, JSON, CIDR, domain or key -
and in production when sign-in is not Entra, step-up MFA is off or there is no encryption key. The message lists every
problem with its fix; before, the first bad value stopped the start with a bare conversion error, and some were read
only later, mid-request. A setting name the platform does not know is reported with the nearest real one
(`SOC_RAW_RETENTON_DAYS` - did you mean `SOC_RAW_RETENTION_DAYS`?) instead of being ignored silently.

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
SOC_LLM_MONTHLY_TOKEN_BUDGET=50000000      # the starting monthly budget; administrators change it on the AI usage screen
```

**Budgets and limits are set by administrators on the AI usage screen** (*Govern -> AI usage*): the monthly and daily
token budgets, per-person hourly / daily limits (with role and person overrides; 0 = no model text for that person),
and per feature the model tier, the longest answer and on/off. Each change is versioned and audited and applies to
the next model call. Over a limit the platform answers without the model and tells the person why. The same screen
shows use and cost per feature and per person and advises small or large per feature from measured quality figures.
Details and sizing: [LLM_TOKENS_AND_COST.md](LLM_TOKENS_AND_COST.md) sections 4 and 4b.

**An organisation's own LLM gateway** (one internal endpoint in front of Claude, Gemini and OpenAI models) is a
configuration change, not a code change - full walkthrough in `docs/CLIENT_DEPLOYMENT_GUIDE.md` section 5:

| Setting | Default | Meaning |
|---|---|---|
| `SOC_LLM_PROVIDER` | `none` | `openai_compatible` for a gateway exposing `/v1/chat/completions`; `anthropic` for one exposing the Claude Messages API |
| `SOC_LLM_AUTH_HEADER` / `SOC_LLM_AUTH_PREFIX` | `Authorization` / `Bearer ` | header and prefix carrying `SOC_LLM_API_KEY` (openai_compatible) |
| `SOC_LLM_EXTRA_HEADERS` | empty | JSON object of fixed, non-secret headers the gateway requires |
| `SOC_LLM_MAX_TOKENS_FIELD` | `max_tokens` | request field carrying the answer cap; `max_completion_tokens` for gateways / models that need it |
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
| retention | 24 h | prune raw payloads / emails / prompts / access log / old telemetry events per policy |
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

`scripts/build_estate_variant.py OUT --seed N [--scale X] [--messy]` generates a different organisation (names,
machines, IP plan, suppliers, volumes) with its own tenant connector settings (`fixtures/settings.json`). `--messy`
adds what a real tenant has and a demo does not: event volume (sign-ins, DNS, low-severity EDR alerts, more findings),
accented and non-Latin names, renamed users, leavers with live devices, re-imaged and stale machines, hostname case
and FQDN differences between tools, missing and null optional fields, epoch-millisecond times, ServiceNow custom
fields and a CVE no feed knows. Run the platform on it
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

## Server and database under load

Measured with `scripts/load_test.py` (a real server on the demo organisation, analysts clicking every 0.05-0.4 s,
the incident job replayed meanwhile): one server process reached 43 requests/s with every request queueing (median
276 ms even for `/health`); four processes served 128 requests/s to 40 analysts with medians of 5-56 ms and no error,
and 150 requests/s to 100 analysts with no error or timeout (laptop, SQLite; PostgreSQL 127 requests/s, also no error).
On its own each screen takes 6-50 ms. Real analysts click every few seconds, so this is several times a real SOC's
load. SQLite allows one writer at a time: under that load note and search writes waited up to seconds (p99), so use
PostgreSQL in production.

| Setting | Default | Meaning |
|---|---|---|
| `SOC_API_WORKERS` | 1 (`serve`), 4 (container image) | Server processes on the port. One process uses one CPU core; give one per core. Jobs stay safe with any number (database leases). |
| `SOC_API_THREADS` | 40 | Request threads per process |
| `SOC_DB_POOL_SIZE` / `SOC_DB_MAX_OVERFLOW` | 20 / 20 | Database connections per process (request threads, scheduler, access-log writer). PostgreSQL: keep `workers x (size + overflow)` under its `max_connections` |
| `SOC_DB_POOL_TIMEOUT` | 10 | Seconds a request waits for a connection; then it answers **503** with `Retry-After` (not a hang, not a 500). A locked SQLite database or an unreachable database also answers 503 |
| `SOC_DB_POOL_RECYCLE` | 1800 | Seconds before a connection is replaced. Connections are also checked before use, so a database restart or failover, or a firewall dropping idle connections, does not surface as errors |
| `SOC_DB_STATEMENT_TIMEOUT_SECONDS` | 0 (no limit) | PostgreSQL: the longest one SQL statement may run before the database cancels it, so a runaway query releases its connection and locks instead of holding them. 120 is a sensible production value; keep 0 for a first backfill of a very large tenant |
| `SOC_SHUTDOWN_GRACE_SECONDS` | 20 | On SIGTERM (a deploy, `docker stop`) requests in flight get this long to finish; the scheduler service finishes the job in hand. The server then writes its last access-log rows and stops. Keep it below the orchestrator's grace period (compose: `stop_grace_period: 30s`) |
| `SOC_RISK_CACHE_SECONDS` | 300 | The user / host risk ranking (brief, Intelligence screen) is reused while the data it reads is unchanged - exact within a process, and this is the age limit for changes made by other processes. Ranking 22,000 entities took 9.4 s per request before; now 4.7 s once, then 20 ms |

## Connector sync and volume

| Setting | Default | Meaning |
|---|---|---|
| `SOC_WATERMARK_OVERLAP_MINUTES` (or a connector's `watermark_overlap_minutes` setting) | 30 | Event streams (sign-ins, audits, alerts, DNS, Sentinel incidents) resume from the newest change time seen, minus this overlap: logs are indexed minutes late, and asking exactly from the mark would lose them. Re-read records are de-duplicated. A time more than an hour in the future (a device with a wrong clock) never moves the mark |
| `SOC_SYNC_MAX_PAGES` | 1000 | Pages one stream reads per sync. A larger backlog is not dropped: the stream keeps its place and the next sync continues (the sync report says `truncated`) |
| `SOC_RESOLUTION_AUTO_THRESHOLD` | 0.85 | Score at which a weak-hint host match merges without analyst review. 0.75 lets "same unique hostname and OS, nothing else" merge: on the 400-host stress estate the unresolved share fell from 5.4 % to 2.2 % with no false merge. Decide on the client's shadow-mode review queue; 0.6 is the floor |
| `SOC_CONNECTOR_RATE_SHARE` | 1 (5 in the compose file) | How many processes call the tools at once (API workers + a separate scheduler service). Each process holds its own request budget per tool, so each takes 1/N of it and together they stay within the rate the vendor allows |
| Umbrella `dns_sync` | security | `security`: only DNS queries in Umbrella's security categories (allowed or blocked) are stored - the only DNS events any analysis uses; a tenant makes tens of millions of queries a day. `all`: every query (small tenants). "Did anyone reach this site?" and shadow IT always ask Umbrella live |

Each page of a sync is committed as it is stored: an interrupted backfill resumes after its last page, and a long
sync never holds one database transaction open (on PostgreSQL a sync of tens of thousands of records once ran the lock
table out; on SQLite it blocked every other writer). One page is one savepoint; if it fails, the page is stored record
by record so one bad record is isolated, and 20 identical failures in a row stop the retries (a systematic fault).

**Records that do not match the vendor's documented shape** - a field as an object where text belongs, a single
object where a list belongs, a number as text, `"N/A"` for a list - are brought to that shape before they are parsed
(the shape is learned from the connector's own fixtures). The record is kept; only the unreadable field is emptied.
Each sync then logs one `connector.data_quality` warning naming the fields and how often (never their values), so a
vendor API change shows up instead of being absorbed. A record whose identifier is unusable is still refused with
the reason. Vendor times are read in every form vendors send (ISO 8601 with any fraction, offsets with or without a
colon, epoch seconds or milliseconds as a number or text); placeholder dates (`0001-01-01`, epoch 0) count as no
time, and a time more than 24 hours in the future (a device with a wrong clock, `9999-12-31`) is stored as seen now
with the vendor's value kept as `reported_time` - it would otherwise become the "latest observation" that every
risk figure decays from.

`scripts/measure_scale.py --scales 1,20,40 [--db postgresql://...]` builds messy estates of growing size (see Sample
estates) and reports, per stage, time and SQL statements, statements per synced record and the open review queue.
Measured (laptop, SQLite): 40x = 250 people, 192 laptops, 21,675 records - sync 149 s (about 146 records/s, flat
from 20x), 29 statements per record at every size, vulnerability refresh 56 s, incident pipeline 48 s (time mostly
spent waiting on each tool's request budget, about 1.5 s per new incident), intelligence refresh 24 s, overview
30 ms, self-check 0.3 s. PostgreSQL: sync about 75 records/s (one network round trip per statement).

## Recording the client's real responses (record-and-sanitise)

The demo fixtures are built from vendor documentation. To test against the shapes of the client's real tenants, put a
tool in the **Recording** stage (Integrations -> Configure; it reads live and records, and offers no actions), or set
`SOC_RECORD_FIXTURES_DIR=<folder>` to record every live tool. Recordings go to `SOC_RECORD_FIXTURES_DIR`, else to
`recordings/` next to the raw payload folder. The pseudonyms are keyed with `SOC_RECORD_SALT` (random, at least 16
characters, never stored with the recording) or, when that is unset, with a key derived from `SOC_DATA_KEY` - so the
Recording stage needs no extra secret in production. Each recorded connector writes `<folder>/<connector>.json` in
the fixture format, sanitised as it is written: request headers and any token / secret / password / key field are
never recorded; people, accounts and machines become stable pseudonyms (keyed with the salt - not reversible); the
client's own domains and the host names under them are pseudonymised wherever they appear; internal IPs map into
10.250.0.0/16 and public ones into 198.18.0.0/15; ids keep their shape; free text becomes `[text, N chars]`. Vendor
vocabulary (severities, categories, states), timestamps, counts, file hashes and external (attacker) domains are
kept: they are what tests need. `_scan.json` lists anything still looking like an e-mail address or IP - review it,
and the files, before a recording leaves the client. `SOC_RECORD_MAX_CALLS` (default 200) caps each file. Unset the
folder when done.

## Logs, traces and diagnostics

**What is recorded, and where**

| Record | Where | What it holds | Kept |
|---|---|---|---|
| Audit log | database, hash-chained | every change and decision: actions, approvals, policy and configuration changes, access grants, case work, agent recommendations, model use, exports. **Every successful write request leaves at least one event** - where a route's own code wrote none, a generic `api.<method>` event (who, which route, which ids) is added in the same transaction. | never pruned by the platform |
| Access log | database | every API request: who, method, path, status, latency, client address | `SOC_ACCESS_LOG_RETENTION_DAYS` (400) |
| Model calls | database (`llm_calls`) | every model call or refusal: feature, tier, who asked (or scheduled), prompt as sent (identities pseudonymised), answer, tokens, time, status, answer cap, statements the evidence check kept and removed **with the reason for each removal** | text `SOC_LLM_LOG_RETENTION_DAYS` (180), figures kept |
| Job runs | database | every scheduled or replayed run: outcome, attempts, error, summary | |
| Application log | stdout (and `SOC_LOG_FILE`) | one structured line per request, audit event, model call, outbound call to a tool (host and path - never the query string, headers or body), job start and end, CLI command, warning and error | your log collector's retention |

**One trace id ties them together.** Every API request gets one - the caller's `X-Request-ID` if it is a safe value
(8-64 letters, digits, `._:-`), else a new `req-...` - and every job run gets `job-<name>-...`, every CLI command
`cli-<command>-...`. It is returned in the `X-Request-ID` response header and stored on the access-log row, every
audit event, every model call and the job run, and printed on every log line.

**Diagnosing**: *Audit log* -> a row's *Trace* link, or `GET /api/v1/admin/trace/{id}`, shows everything that request
or job did in order: the request, its audit events, each model call with the prompt, the answer and what the evidence
check removed and why, and the job run. *AI usage -> Recent model calls* lists calls by feature and outcome
(`GET /api/v1/admin/llm/calls`, detail `/calls/{id}`). Both need `read_audit` with all-domain access. A user can quote
the `X-Request-ID` of a failing screen (browser developer tools) and the support engineer opens that trace.

| Setting | Default | Meaning |
|---|---|---|
| `SOC_LOG_LEVEL` | INFO | DEBUG, INFO, WARNING, ERROR |
| `SOC_LOG_FORMAT` | `json` in prod, `text` otherwise | JSON lines for a collector / SIEM; text for a console |
| `SOC_LOG_FILE` | unset | also write to this file, rotated at `SOC_LOG_FILE_MAX_MB` (50) keeping `SOC_LOG_FILE_BACKUPS` (10) |
| `SOC_LOG_CONFIGURE` | 1 | 0 = leave Python logging to the host (the test suite sets it) |

Log lines never carry secrets: values under keys that look like one (token, secret, password, key, authorization,
cookie, credential) are masked, long values are cut, and outbound calls are logged without their query string.
Forward stdout to the SIEM; alert on `level` WARNING / ERROR, `job.end` with status other than ok, `llm.call` with
status `error`, `connector.http` errors, `connector.data_quality` (a tool sent fields in an unexpected shape) and
`ingest.rejected` (alerts pushed by a SIEM were refused - the reasons are in the line and in the push response).
`server.start` / `server.stop` mark each process's life; `server.stop` reports `access_log_dropped` if any access-log
rows could not be written.

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
  (400), `SOC_EVENT_RETENTION_DAYS` (400; 0 keeps everything). Emails of open cases are kept (legal hold). The audit
  log is never pruned by the platform.
* Event retention keeps the context store bounded at client volume: sign-ins, DNS, mail events, secret accesses and
  elevations last seen longer ago than the setting are deleted with their keys, hints, relations and source records,
  in batches of 500. An event a case, evidence, an insight or a resolution override refers to is kept; alerts,
  findings, assets, people and indicators are never pruned. The retention run's report (`events`) and audit entry
  say how many went; `dry_run` counts without deleting.
* Audit export for archiving/SIEM: `GET /api/v1/audit/export` (JSON Lines with chain verification).
* Compliance evidence pack: *Reports* → compliance (`POST /api/v1/reports/compliance`, auditor / lead / admin).

## Backups

Back up the database (point-in-time), the raw payload volume and the report volume. The audit chain can be
verified after restore with `GET /api/v1/audit/verify`.

## Connecting and changing tools

The configuration in force is `config/connectors.yaml` (deployed with the platform) **plus** the approved console
changes layered on top. Admins change tools on **Integrations**, without editing files or restarting:

| Step | Who | What happens |
|---|---|---|
| 1. Secrets | platform engineer | Put the tool's secrets in the vault (`<NAME>_FILE`) or environment under the names *Configure* shows (convention `<CONNECTOR>_<SETTING>`, e.g. `CROWDSTRIKE_CLIENT_SECRET`). The console never asks for, stores or shows a secret: it shows *set / not set* and when the vault file last changed. |
| 2. Configure | `automation_admin` or `admin` (manage_connectors) | Non-secret settings (URLs, tenant ids, mailbox, field mappings...), the **stage**, on/off, and a note for the approver. Every value is checked (URL, true/false, number, one of a list, JSON mapping); a misspelled setting gets "did you mean ...?". |
| 3. Preflight | automatic | Proposing a live stage, switching a live tool on, or changing a live tool's settings runs the preflight on the *proposed* configuration: configuration, start-up, sign-in, every stream (the permission it needs, parsing, how fresh the newest record is, expected volume) and the write permissions actions will need. Errors refuse the proposal and show what to fix; warnings go to the approver. |
| 4. Approve | `lead` (approve_policy, MFA), never the proposer | The approval re-checks the configuration and that the preflight still matches it (same settings, same secrets present, less than 7 days old). A proposal made before another change was approved must be proposed again. |
| 5. In force | - | The approving process applies it at once; every other API process and the scheduler within `SOC_CONFIG_RELOAD_SECONDS` (default 5). No restart. |

**Stages** (a tool moves forward one at a time; each step is a proposal):

| Stage | Reads | Actions |
|---|---|---|
| Fixtures (`fake`) | vendor-shaped sample data | under the automation policy (demo) |
| Recording (`record`) | live; responses also saved, sanitised, as fixtures | none (recommendations appear as manual steps) |
| Read-only (`read`) | live | none (manual steps) |
| Recommend (`recommend`) | live | offered, **never above L2**: a person approves every one, whatever the policy says |
| Automate (`automate`) | live | follow the approved autonomy policy (default still L2) |

The older `mode: fake | live` in the file still works (`live` = Automate).

**Pause** (manage_connectors or kill_switch) switches one tool off **at once**, with a reason, audited - for a tool that
misbehaves. Switching it back on is a normal proposal. Everything a paused, misconfigured or read-only tool would have
done becomes a manual recommendation; approving an action whose tool is no longer able to act is refused with that
reason.

**Organisation lists**: the key **suppliers** (vendor e-mail compromise) and the **sanctioned services** (shadow
IT) are edited on the same screen (*Suppliers & sanctioned services*) and approved the same way; an approved list
replaces `config/suppliers.yaml` / `config/sanctioned_services.yaml` everywhere (phishing, supplier risk, shadow IT,
reports), and proposing it empty-handed (`null` through the API) gives the file's list back. Domains are checked.

**History**: every version is kept (who proposed, who approved, what changed). *Restore* proposes an earlier version
(approved like any change). **Export** gives the configuration in force as one YAML file (secrets only as `${VAR}`
references) for review, a staging copy or disaster recovery; **Import** proposes such a file as one change (tools
absent from it are switched off).

**One broken tool never stops the others**: a connector with a missing secret, an invalid entry, a constructor that
fails or a module that does not import is left out of every workflow, with the reason on Integrations; the rest keep
working.

| Setting | Default | Meaning |
|---|---|---|
| `SOC_CONNECTORS_CONFIG` | `config/connectors.yaml` | The file layer |
| `SOC_CONFIG_RELOAD_SECONDS` | 5 | How often each process re-reads which console version is in force |
| `SOC_CONNECTOR_MODE` | fake | Mode of a tool listed without `stage` / `mode` |

See [CONNECTORS.md](CONNECTORS.md) for each tool's settings and permissions, and ENGINEERING.md §5.5 for adding one.
