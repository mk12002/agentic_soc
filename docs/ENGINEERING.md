# Engineering reference - architecture, design and every technical decision

This document explains how the Agentic SOC platform is built and why. It covers:
- architecture, runtime and deployment
- every subsystem, its data model and algorithms
- security, reliability, performance and testing
- a log of the engineering decisions, with the alternatives considered

Every statement was checked against the code at the time of writing. File references are relative to the repository
root.

Companion documents: [ARCHITECTURE.md](ARCHITECTURE.md) (diagram-level overview), [SECURITY.md](SECURITY.md),
[FAILURE_MODES.md](FAILURE_MODES.md), [OPERATIONS.md](OPERATIONS.md), [RUN_GUIDE.md](RUN_GUIDE.md),
[TEST_REPORT.md](TEST_REPORT.md), [LLM_TOKENS_AND_COST.md](LLM_TOKENS_AND_COST.md).

---

## Contents

1. [What the system is, and the constraints that shaped it](#1-what-the-system-is-and-the-constraints-that-shaped-it)
2. [Architecture](#2-architecture)
3. [Technology stack and why](#3-technology-stack-and-why)
4. [Code organisation](#4-code-organisation)
5. [Connector SDK](#5-connector-sdk)
6. [Canonical schema and the context store](#6-canonical-schema-and-the-context-store)
7. [Entity resolution](#7-entity-resolution)
8. [Data model and persistence](#8-data-model-and-persistence)
9. [The three workflow domains](#9-the-three-workflow-domains)
10. [Intelligence layer](#10-intelligence-layer)
11. [Action layer and autonomy policy](#11-action-layer-and-autonomy-policy)
12. [LLM gateway](#12-llm-gateway)
13. [Security architecture](#13-security-architecture)
14. [Reliability: jobs, scheduler, idempotency, self-check](#14-reliability)
15. [Consistency and correctness mechanisms](#15-consistency-and-correctness-mechanisms)
16. [Performance and scale](#16-performance-and-scale)
17. [API design](#17-api-design)
18. [Frontend](#18-frontend)
19. [Reporting](#19-reporting)
20. [Configuration and secrets](#20-configuration-and-secrets)
21. [The phishing ML engine](#21-the-phishing-ml-engine-trained-models-per-e-mail-component)
22. [Testing strategy](#22-testing-strategy)
23. [Code quality tooling](#23-code-quality-tooling)
24. [Deployment and operations](#24-deployment-and-operations)
25. [Decision log](#25-decision-log)
26. [Known limitations and trade-offs](#26-known-limitations-and-trade-offs)
27. [Glossary](#27-glossary)

---

## 1. What the system is, and the constraints that shaped it

**Purpose.** One investigation and automation layer over the security tools an organisation already runs. It pulls
from 20 tools through their APIs and resolves every host and person to a single identity across them. On that
shared picture it runs three SOC workflows:
- reported phishing
- incident management
- vulnerability management

A cross-domain intelligence layer correlates across the workflows.

**Scale of the code base:**

| Part | Lines |
|---|---|
| Platform (`soc_platform/`, excluding tests and the ML engine) | ~16,800 Python |
| Platform tests (`soc_platform/tests/`) | ~5,600 |
| Web console (`soc_platform/api/static/*.js`) | ~920 JavaScript, plus CSS |
| Optional phishing ML engine (`soc_platform/domains/phishing/engine/`) | ~24,100 Python, with its own tests |

**The constraints that drove the design** (from the requirements, the sections referenced in docstrings as NFR-xx, R-xx):

| Constraint | Design consequence |
|---|---|
| The AI must not decide; analysts approve (NFR-01, R04) | Every figure, verdict, score and priority is computed in code. The LLM only writes narrative, from evidence it is given. Every change to a tool is an action request, gated by a versioned autonomy policy that defaults to *recommend*. |
| Every conclusion must be explainable and auditable (NFR-04) | Evidence rows with ids; citations validated; an append-only, hash-chained audit log; per-factor risk explanations. |
| Works with the client's existing tools, which may change (NFR-14, R06, R15) | A connector SDK with a uniform interface; a canonical schema; a plug-in registry (modules or Python entry points). |
| Personal data protection (NFR-08, NFR-10, R10) | Encryption at rest of raw payloads; pseudonymisation before any LLM call; retention with legal hold; approved LLM endpoints only. |
| Least privilege and separation of duties (NFR-09) | Roles, domain scoping, step-up MFA, human-only permissions, four-eyes, no self-approval. |
| Must degrade, not fail (NFR-05, NFR-13) | Per-source timeouts; partial results reported by name; circuit breaker for the LLM; retries and dead letters for jobs; a platform self-check. |
| Demonstrable before any tenant access | Every connector has a *fake* mode that feeds vendor-shaped fixtures through the same parsing code as *live* mode. |

---

## 2. Architecture

### 2.1 Layers

```text
                +--------------------------------------------------------------+
  Browser  ---> |  API (FastAPI) + web console (static SPA, strict CSP)        |
                |   auth, RBAC + domain scope, rate limit, access log          |
                +--------------------------------------------------------------+
                |  Intelligence: risk engine, 12 correlation rules, attack     |
                |  story, deep analysis, analyst Q&A, brief, coverage,         |
                |  shadow IT, drift, report builder                            |
                +--------------------------------------------------------------+
                |  Domains: phishing | incident | vulnerability (+ cloud)      |
                +--------------------------------------------------------------+
                |  Core: context store + entity resolution, cases & evidence,  |
                |  enrichment orchestrator, action layer + autonomy policy,    |
                |  audit chain, access mgmt, crypto, retention, self-check,    |
                |  jobs + scheduler                                            |
                +--------------------------------------------------------------+
                |  Connector SDK: 20 connectors, live (HTTP) or fake (fixtures)|
                +--------------------------------------------------------------+
                |  LLM gateway (optional): providers, redaction, grounding,    |
                |  guardrails, breaker, budget, call log                       |
                +--------------------------------------------------------------+
                |  PostgreSQL (prod) / SQLite (dev)  +  encrypted file store   |
                +--------------------------------------------------------------+
```

The dependency direction is strictly downward:
- Connectors know nothing about domains.
- Domains use the core and connectors.
- Intelligence reads everything.
- The API composes services.
- The LLM gateway is a leaf dependency that any layer may call, and every layer works without it.

### 2.2 Processes

| Process | What it runs | Scaling |
|---|---|---|
| `platform-api` (`python -m soc_platform serve` or `uvicorn soc_platform.api.app:app`) | HTTP API, the console, and by default the embedded scheduler | Stateless. Scale horizontally; every replica may also run a scheduler safely. |
| `platform-scheduler` (`python -m soc_platform scheduler`), optional | The same scheduler code as a separate service | Any number (the database coordinates). |
| PostgreSQL | All records | Managed service in production. |
| File/blob store (`SOC_RAW_PAYLOAD_DIR`, `SOC_REPORT_OUTPUT_DIR`) | Encrypted raw payloads, reported e-mails, generated reports | A volume or blob mount. |
| Optional: phishing ML engine (RabbitMQ, Redis, agent workers) and an isolated detonation host | §21 | Separate compose profile. |

### 2.3 Data flow

1. **Ingest.** A connector pulls a page, normalises each raw record into a `NormalizedRecord`, and the context store
   ingests it: raw payload kept (encrypted), entities resolved, events linked.
2. **Investigate.** A domain service builds a case, fans out enrichment lookups in parallel, and stores evidence
   rows. It then computes the verdict, severity or priority deterministically. If an LLM is configured, it writes a
   cited narrative.
3. **Recommend.** The domain proposes action requests. The policy engine decides each one's effective level; nothing
   executes without approval unless policy promotes that action type.
4. **Correlate.** The intelligence layer recomputes risk and the correlation rules across domains, and builds the
   situation brief.
5. **Prove.** Every state change is appended to the audit chain. Reports and compliance packs are generated from the
   same records.

### 2.4 Request lifecycle (API)

```text
request
 -> BodyLimitMiddleware (byte-stream cap, 30 MB)
 -> SecurityMiddleware: reject NUL in path/query (400) -> Content-Length cap (413) -> per-client token bucket (429)
 -> route dependency: current_user (Bearer / X-API-Key / X-Break-Glass) -> revocation check -> need(permission, domain)
 -> handler: service calls inside one DB session (commit on success, rollback on error)
 -> response: security headers added; access-log row queued (written in batches by a background thread)
exceptions: DataError -> 400; KeyError from services -> 404; PermissionError -> 403
```

---

## 3. Technology stack and why

| Component | Choice | Why | Alternatives considered |
|---|---|---|---|
| Language | Python 3.11 | The security-tooling ecosystem (vendor SDKs, email parsing, ML) is Python-first. The ML engine is Python. 3.11 has `datetime.UTC`, `tomllib` and performance gains. | Go (faster, weaker ecosystem for email/ML); TypeScript. |
| Web framework | FastAPI 0.1xx + Uvicorn | Typed request models (Pydantic), dependency injection for auth/permissions, async where useful, OpenAPI in dev. | Flask (less typing), Django (heavier ORM/admin not needed). |
| ORM | SQLAlchemy 2.0 (typed `Mapped[]`) | Same code on SQLite and PostgreSQL; explicit sessions and transactions; conditional updates for exactly-once transitions. | Django ORM; raw SQL. |
| Production database | PostgreSQL 16 | Row-level locking, transactional DDL, JSON, mature managed offerings. | SQL Server (possible via SQLAlchemy; not tested). |
| Dev database | SQLite (WAL, busy timeout) | Zero setup for demos and fast tests. Tests enforce PostgreSQL's rules (§22.2) so SQLite never hides production bugs. | Docker PostgreSQL for everything (slower loop). |
| Validation | Pydantic 2 | Request bodies, settings. | Marshmallow. |
| HTTP client | httpx | Sync client with timeouts and connection pooling; `Timeout(read, connect=)` for LLM tiers. | requests (no fine-grained timeouts). |
| Auth tokens | PyJWT (`[crypto]`), MSAL | RS256/JWKS validation for Entra; MSAL for the confidential-client flow. | python-jose. |
| Fuzzy matching | rapidfuzz | Fast string similarity for hostnames and look-alike domains. | difflib (slow). |
| Crypto | `cryptography` Fernet / MultiFernet | Authenticated encryption (AES-128-CBC + HMAC-SHA256) with built-in key rotation. | AES-GCM directly (more foot-guns). |
| Documents | python-docx, python-pptx | Native Word/PowerPoint output; client templates can be used as the base. | PDF only (clients edit Word). |
| Email parsing | Python stdlib `email` (policy.default) | No dependency, handles MIME fully. Hardened for malformed headers (§9.1). | flanker, mail-parser. |
| QR / fuzzy hash | pyzbar + Pillow, ppdeep | QR phishing detection; ssdeep-compatible attachment similarity. | - |
| Frontend | Vanilla JavaScript SPA, no build step | Strict CSP (no inline script) is easy to hold; no supply chain of npm runtime dependencies; one file per concern; fast to audit. | React/Vue (build tooling, larger dependency surface). |
| Browser automation (tests only) | playwright-core against the installed Chrome/Edge, axe-core | Real-browser tour, layout audit, accessibility scan, XSS probe. | Selenium. |
| Property-based testing | Hypothesis | Finds edge cases in parsers and redaction. | - |
| Lint / security scan | ruff, bandit, pip-audit, npm audit, pyright (triage) | §23. | flake8+isort+black (ruff replaces them). |
| Containers | Docker multi-stage, `python:3.11-slim`, non-root user | Small image; the optional ML engine is a build argument. | - |

---

## 4. Code organisation

```text
soc_platform/
  __main__.py            CLI: init-db, demo, reset-demo, serve, scheduler, token, fixtures
  config.py              Settings (env-driven), secret() with *_FILE support
  jobs.py                job registry, run_job (lease, retries, record, dead letter)
  scheduler.py           embedded/standalone scheduler, heartbeat, status()
  api/
    app.py               FastAPI app: middleware, auth dependencies, all routes
    dashboards.py        read models: overview, coverage, shadow IT, Prometheus text
    static/              index.html, app.js (shell, router, auth), views.js (screens), theme.js, styles.css
  connectors/
    base.py              BaseConnector, TokenBucket, with_backoff, SyncRunner, Page, LookupResult
    http.py              Transport protocol; HttpTransport; FixtureTransport; auth strategies
    registry.py          discovery (modules + entry points), manifests, config, ConnectorRegistry
    tools/*.py           one module per tool (20 connectors), shared helpers in _common.py / _microsoft.py
  core/
    schema.py            NormalizedRecord, EntityRef (canonical schema)
    models.py            ORM tables for the core; utcnow() (the platform clock); new_id()
    db.py                Database, sessions, UTCDateTime, BoundedText, NUL stripping, schema widening
    context_store.py     ingest(), neighbours, timelines
    entity_resolution.py EntityResolver (deterministic -> probabilistic -> queue)
    identity.py          user_ref(): cross-tool user identity normalisation
    cases.py             CaseService: cases, evidence, recommendations, decisions
    enrichment.py        EnrichmentOrchestrator: parallel lookups with per-source timeouts
    actions.py           ActionSpec, ActionRegistry, ActionService (the only execution path)
    policy.py            autonomy levels, PolicyEngine.decide(), PolicyStore (propose/approve)
    auth.py              roles, permissions, token validation, dev tokens
    access.py            role grants, API keys, revocation, break-glass, kill switch
    audit.py             hash-chained audit log
    crypto.py            DataCipher (Fernet/MultiFernet), write_protected (atomic)
    retention.py         retention and legal hold
    selfcheck.py         cross-surface consistency proof, budget alert
    notify.py            Teams / Slack / webhook notifications for findings (notifications table)
    asset_types.py       which assets are expected to run an EDR agent
  domains/
    phishing/            service.py, models.py, supplier.py, agents/{decompose,analyzer,investigation}.py, engine/ (optional ML)
    incident/service.py
    vulnerability/       service.py, misconfig.py, models.py
  intelligence/          risk.py, correlation.py, analyst.py, story.py, deep_analysis.py, attack_coverage.py,
                         shadow_it.py, drift.py, models.py
  llm/                   gateway.py, redaction.py, providers/{openai_compatible,anthropic_provider}.py
  reporting/             builder.py, reports.py, compliance.py, models.py
  fixtures/              vendor-shaped fixtures per connector (fake mode)
  tests/                 platform test suite
config/                  connectors.yaml, suppliers.yaml, sanctioned_services.yaml
scripts/                 fixture/corpus builders, variant estates, verification, ui_tour/, measure_llm_usage.py, load_env.ps1
deploy/                  Dockerfile, docker-compose.yml, docker-compose.dev.yml, sandbox/
artifacts/phishing/      labelled e-mail corpus, ML model artifacts (engine)
docs/                    this and the other documents
```

**Conventions:**
- Services take a SQLAlchemy `Session` and never commit. The caller's unit of work (an API request, a job run)
  commits or rolls back.
- Every timestamp comes from `core.models.utcnow()`.
- Every id is `uuid4().hex` (32 characters).

---

## 5. Connector SDK

### 5.1 Interface (`connectors/base.py`)

A connector subclasses `BaseConnector` (via `ToolConnector` in `tools/_common.py`) and implements:

| Member | Purpose |
|---|---|
| `streams` | Named datasets it can pull (`alerts`, `hosts`, `vulnerabilities`...) |
| `fetch_page(stream, cursor) -> Page` | One page of raw records, the next cursor, and optionally the tool-reported total |
| `normalize(stream, raw) -> list[NormalizedRecord]` | Raw vendor record → canonical records (entities and/or events) |
| `lookup(entity_type, value) -> LookupResult` | On-demand enrichment (per IP, domain, hash, user, host...) |
| actions (`ConnectorAction`) | Write operations with optional pre-conditions and a `reverse_type` |
| `health()` | One page of the health stream (`POST /connectors/{name}/test`); the full check is the preflight (§5.5) |

**Malformed records** (`connectors/conform.py`). Every subclass's `normalize` is wrapped (`__init_subclass__`) so the
raw record is first brought to the stream's documented shape: the shape is learned once per stream from the
connector's own fake-mode fixtures (live mode included), and a field of the wrong type is coerced (object expected
-> `{}`, list expected -> `[obj]` or `[]`, text expected -> a number as text, number / boolean expected -> parsed text
or empty). The vendor's record is copied on first change, never modified; a record that already conforms is returned
as is. Coercions are counted per field path (never with values) and returned by `take_quality(stream)`;
`SyncRunner.sync` puts them on the `SyncReport` (`coerced`) and logs one `connector.data_quality` line. The canonical
schema also accepts a numeric `source_id` as text and empties an odd `title`, `severity`, `deep_link` or
`attributes`. `parse_ts` (`tools/_common.py`) never raises: placeholder dates before 1990 and out-of-range epochs are
no time; `ContextStore.ingest` stores a time more than 24 h ahead as now (vendor value kept as `reported_time`).
`SyncRunner.ingest_records` gives records that arrive without a sync (the SIEM push) the same per-record isolation.

### 5.2 Rate limits and retries

- **`TokenBucket(rate_per_sec, burst)`** per connector (default 5/s, burst 10; tuned per tool under each vendor's
  documented limits, for example 50/s for threat-intel fusion). Every outbound call is wrapped by
  `connector.call()`, which acquires a token. The bucket lives in the process, so each of N processes calling the
  tools takes 1/N of it (`SOC_CONNECTOR_RATE_SHARE`); a limiter shared across processes would need Redis or the
  database on every call.
- **`with_backoff`** retries up to 5 times:
  - on `TransientError` (network errors and 5xx): exponential backoff (0.5 s × 2ⁿ, capped at 30 s) with jitter
  - on `RateLimited` (429): the vendor's `Retry-After` is honoured, capped at `MAX_RETRY_AFTER` = 120 s, so one
    answer can never stall a job for hours

  After that it raises `ConnectorError`. 4xx other than 429 is not retried (it will not get better), with two
  distinctions: **401** (`AuthExpired`) - the token is renewed once (`transport.reauthenticate()`, which drops the
  cached OAuth token) and the call repeated, fake mode included; **403** (`PermissionDenied`) stops at once and the
  health check reports `missing_permission` with the connector's `required_scopes`. `Retry-After` may be seconds or an
  HTTP date.

### 5.3 Transports and authentication (`connectors/http.py`)

Connectors talk to a `Transport` protocol, never to httpx directly. That is what makes fake and live modes run the
same code:
- **`HttpTransport`:** base URL, auth strategy, timeout (30 s), TLS verification, error mapping shared with the
  fixture transport (`raise_for_status`: 429 → `RateLimited`, 5xx and transport errors → `TransientError`, 401 →
  `AuthExpired`, 403 → `PermissionDenied`, other 4xx → `ConnectorError`). An HTML page answering instead of JSON (a
  proxy or login page) is a clear `ConnectorError`; an unparsable JSON body is retried.
- **`FixtureTransport`:** routes loaded from `fixtures/<tool>.json`. Each route matches method, path regex, listed
  parameters (only the listed ones; `~` means regex, `*` means any value) and optional body substrings. Routes can
  answer any status (429 / 401 / 403 / 5xx raise exactly what the live transport raises), carry `headers`
  (`Retry-After`), answer only `times` times before the next matching route answers (pages in order, "throttled once"),
  and can select fields from the request.
- **`RecordingTransport`** (`connectors/recording.py`): wraps a live transport when `SOC_RECORD_FIXTURES_DIR` is set and
  writes each response, sanitised, as a replayable fixture (#43 in the decision log).
- **`RoutingTransport`:** several upstreams behind one connector (threat-intel fusion).
- **Auth strategies:**
  - `NoAuth`
  - `ApiKeyHeader`
  - `ApiKeyQuery`
  - `BasicAuth`
  - `OAuth2ClientCredentials`, with token caching and refresh (form or JSON body; `entra_app_auth()` for Microsoft
    tenants)

### 5.4 Sync runner (`SyncRunner.sync`)

- **Incremental.** It resumes from the stored cursor (`ConnectorCheckpoint`) and checkpoints and **commits** after
  every page, so an interrupted backfill resumes rather than restarts. `full_backfill=True` starts from scratch. A
  page marked `reset` ends the stream: its cursor is what the next sync starts from - a time watermark
  (`since:<time>`, the newest change seen; queried minus `SOC_WATERMARK_OVERLAP_MINUTES` for late logs; times more
  than an hour in the future ignored) or nothing (read the inventory in full). Continuation tokens are never kept
  between syncs. `SOC_SYNC_MAX_PAGES` (1,000) bounds one sync; a larger backlog continues next time (`truncated`).
- **Fault isolation without a savepoint per record.** A page is normalised record by record (a normaliser error
  fails only that record) and stored in **one** savepoint; only if that fails is the page replayed record by record,
  and 20 identical failures in a row end the replay as a systematic fault. (A savepoint per record exhausted
  PostgreSQL's lock table on large streams.)
- **Bounded parallel download.** `sync_many` downloads every stream at once but keeps at most 8 pages per stream ahead
  of ingestion; pages ingestion did not take are drained so a download never blocks.
- **Reconciliation.** Source records, ingested and failed counts are accumulated on the checkpoint. Where the tool
  reports a total, `SyncReport.reconciled` compares them.
- **Freshness.** `last_success_at` per stream is compared with the stream's expected cadence for the Integrations
  screen (fresh/stale/error).

### 5.5 Registry (`connectors/registry.py`)

- **Discovery.** Every module in `connectors/tools` that exports `MANIFEST`/`MANIFESTS`, plus any installed package
  exposing the `soc_platform.connectors` entry-point group. A third-party connector needs no platform change.
- **`ConnectorManifest`:** name, kind, config fields, factory, fake settings, fixture file, action factory. Each
  `ConfigField` declares whether it is secret or required and its **kind** (`url`, `bool`, `int`, `choice`, `map`,
  `list`, `email`, `path`, `text`) - used to check values and to draw the console form. Every setting a connector reads
  must be declared (`COMMON_FIELDS` holds the ones the shared code reads, e.g. `watermark_overlap_minutes`).
- **Configuration.** `config/connectors.yaml` sets `enabled`, the rollout **stage** (`fake`, `record`, `read`,
  `recommend`, `automate`; the older `mode: fake | live` still works) and settings per tool, with `${ENV}`
  substitution; secrets can come from `<NAME>_FILE`. Approved console changes are layered on top
  (`core/connector_config.py`). `SOC_CONNECTOR_MODE` sets the default mode. `SOC_FIXTURES_DIR` points fake mode at
  another estate, which may carry `fixtures/settings.json` for its tenant-specific settings.
- **Strict checking** (`connectors/config_schema.py`): unknown tools, keys, stages and settings ("did you mean ...?"),
  malformed values, a secret written in clear, and missing secrets of a live tool (naming the variable). `serve` and
  `scheduler` refuse to start on file errors; a missing secret only isolates that tool.
- **`ConnectorRegistry`:** `configured_names()` (switched on), `enabled_names()` (switched on *and* usable),
  `get(name)`, `construct(name)` (an uncached instance, for preflight) and `action_registry()` (every usable
  connector's actions in one `ActionRegistry`). **Isolation:** a connector whose entry is invalid, whose secret is
  missing, whose constructor or action factory fails, or whose module does not import is left out of every workflow
  with the reason (`problems_of`); it used to raise `ConfigError` out of `action_registry()` and stop every domain.
- **Stages in code:** `record` wraps the live transport for record-and-sanitise; `record` and `read` offer no
  actions (the recommendation becomes a manual step); `recommend` wraps each action in a `StagedAction` with
  `max_level = 2`, passed to `PolicyEngine.decide(..., ceiling=)` so the policy can never take it above L2.
- **Preflight** (`connectors/preflight.py`): configuration, start-up, sign-in, one page of every stream (the
  permission each needs, parsing of up to 20 records, freshness of the newest event, a clock or time-zone fault, the
  volume to expect) and the write scopes actions need. It builds its own instance (no shared paging state) and writes
  nothing to the context store; results are kept in `connector_preflights`.
- **Development kit** (`connectors/devkit.py`): `connector new` writes a connector that already follows the sync
  rules, its fixtures, its paging test and a switched-off config entry; `connector check` runs it through the shared
  conformance suite. The coverage test reads `PAGING_TESTED` from every `test_connector_<name>.py`.

### 5.6 The 20 connectors

The Entra connector also reads each person's **Azure role assignments** (Owner, Contributor, User Access
Administrator... on subscriptions or resource groups, directly or through a group) from Azure Resource Manager,
through a `RoutingTransport` that gives `management.azure.com` its own token audience. The subscriptions come from
`azure_subscriptions`, or every subscription the app can read (Reader role). If ARM cannot be read, the identity
lookup still succeeds and says so.

CrowdStrike Falcon, Defender for Endpoint, Defender for Office 365 (+ Exchange via Graph), Avanan (HEC Smart API;
falls back to the shared mailbox), Entra ID (+ Identity Protection), Cisco Umbrella, Thinkst Canary, Delinea Secret
Server, Delinea Privilege Manager, Rapid7 InsightVM (API v3 or CSV export), Wiz (GraphQL), NVD, FIRST EPSS,
CISA KEV, threat-intel fusion, ServiceNow, Jira, CMDB CSV, Microsoft Sentinel, and the generic SIEM webhook.
- **Threat-intel fusion** covers VirusTotal, AbuseIPDB, OTX, URLhaus, ThreatFox, MalwareBazaar, GreyNoise and
  Shodan, with per-source attribution.
- **The generic SIEM webhook** takes `POST /api/v1/ingest/alerts` with a configurable field map.

What each pulls and does is tabled in PRESENTER_GUIDE.md §15.1.

---

## 6. Canonical schema and the context store

### 6.1 Canonical schema (`core/schema.py`)

A `NormalizedRecord` is either:
- **an entity observation:** kind `asset`, `identity` or `indicator`, with strong **keys** (vendor ids, serial,
  UPN...) and weak **hints** (hostname, IP, OS), or
- **an event:** kind `alert`, `finding`, `email`, `signin`, `click`, `dns`, `secret_access`, `elevation`,
  `cloud_issue`, `deception`... It carries:
  - tool and source type/id
  - `observed_at`
  - title and severity
  - dimension (identity, endpoint, email, dns, privileged_access, exposure, cloud...)
  - attributes and a deep link
  - `refs`: `EntityRef`s to the entities it mentions, each with a role (host, user, sender, recipient,
    destination...)

User naming differs between tools. `core/identity.py:user_ref` turns `ACME\jane.doe`, `jane.doe@acme.com`,
`Jane Doe <…>` and a bare `jane.doe` + domain into an `EntityRef` with `upn` and/or `sam` keys. It returns `None`
for built-in and machine accounts (SYSTEM, root, www-data, `HOST$`), so they never become phantom people.

### 6.2 Context store (`core/context_store.py`)

`ingest(rec)`:
1. Stores a `SourceRecord` with full provenance, and writes the raw payload to the encrypted store.
2. Resolves each referenced entity (§7).
3. Creates an event entity and `Relation` rows linking it to the resolved entities.

It also serves:
- **neighbour and pivot queries**, which the domains, risk engine, story and 360 view use
- **timelines** (events for an entity in a window)
- **`keys_of`** (every identifier for an entity)

`first_seen`/`last_seen` on entities track observation time (the record's `observed_at`, or ingest time when the tool
gives none).

---

## 7. Entity resolution

`core/entity_resolution.py:EntityResolver`. This is the hardest problem in the system: wrong merges route alerts and
tickets to the wrong people and cannot be undone safely; splits are recoverable.

**Order of precedence for every observation:**
1. **Analyst override** for (tool, source type, source id): durable and audited.
2. **Deterministic match on strong keys:** CrowdStrike agent id, MDE device id, cloud resource id, serial, MAC, Entra
   object id, UPN, SAM... Keys pointing at two different entities are a **conflict** and go to the unresolved queue.
   Vendor ids are conflict keys: two different CrowdStrike AIDs are never merged, even with the same serial. Cloned
   VMs share serial numbers; this was a real bug found in testing.
3. **Scored probabilistic match on weak hints:**
   - normalised hostname or FQDN: +0.75 if seen in the last 30 days, else +0.6
   - fuzzy hostname similarity ≥ 0.9: up to +0.5
   - IP within the time window (default 3 days): +0.2; an IP match outside the window is ignored
   - OS family agreement: +0.1; disagreement: −0.4

   Auto-match needs a score ≥ **0.85** and a clear **0.1 margin** over the runner-up. Scores between **0.55** and the
   auto threshold go to the unresolved queue, never silently merged.
4. **Otherwise** a new canonical entity.

**Identities are never fuzzy-merged automatically.** Likely matches are queued for an analyst.

**Measured:** 0 false merges on 400 hosts and on 300 people across 6 naming conventions in random order (stress
tests in `scripts/eval_*_at_scale.py`, run by the verification report). Asset split rate is 7.8 % and 5.4 % are
unresolved, by design.

---

## 8. Data model and persistence

### 8.1 Tables (40)

| Area | Tables |
|---|---|
| Context store | `entities`, `entity_keys`, `entity_hints`, `source_records`, `relations`, `evidence` |
| Resolution | `resolution_overrides`, `unresolved_items` |
| Cases | `cases`, `case_entities`, `case_notes`, `dispositions` |
| Actions and policy | `action_requests`, `policy_versions` |
| Governance | `audit_log`, `llm_calls`, `llm_usage_policies`, `access_log`, `role_assignments`, `api_keys`, `token_revocations`, `system_flags` |
| Operations | `connector_checkpoints`, `connector_config_versions`, `connector_preflights`, `enrichment_cache`, `job_runs`, `notifications` |
| Phishing | `ph_submissions` |
| Vulnerability | `vm_findings`, `vm_vuln_intel`, `vm_campaigns`, `vm_action_plans`, `vm_exceptions`, `vm_risk_register`, `vm_validations`, `vm_misconfigurations` |
| Intelligence | `insights` |
| Reporting | `report_runs`, `report_templates` |

`system_flags` is a small key/value table for durable cross-replica state:
- the kill switch
- job leases (`job_lease:<job>`)
- scheduler heartbeats (`scheduler:<hash>`)
- the audit chain lock (`audit_chain_head`)

### 8.2 Column types and rules

- **`UTCDateTime`** (a TypeDecorator in `core/db.py`). Every timestamp is stored as UTC and returned timezone-aware.
  SQLite drops offsets; without this, naive datetimes serialised without a zone and browsers rendered them in local
  time, so one event showed different times on different screens.
- **`BoundedText(n)`**, for free text from vendors and people: titles, subjects, senders, display names, user agents,
  request paths, product names, owners. It keeps values to the column width (cut with "…") and strips NUL.
  PostgreSQL rejects over-long text and NUL and fails the whole write; SQLite accepts both, so this only ever failed
  in production. **Identifiers are never `BoundedText`:** cutting an id would silently break matching, so those fail
  loudly instead.
- **NUL stripping for every text column.** A `before_flush` listener in `core/db.py` (`_strip_nul`) removes NUL from
  every string attribute of every new or changed row, on every table and code path.
- **JSON columns** for structured payloads: case assessments, evidence details, action params and results, insight
  evidence, policy documents.
- **IDs** are `uuid4().hex` strings. They are globally unique, never guessable in sequence, and portable across
  databases.
- **Constraints doing correctness work:**
  - `action_requests.idempotency_key` UNIQUE
  - `ph_submissions.source_ref` UNIQUE (one case per reported message)
  - `audit_log.hash` UNIQUE
  - the `vm_findings` asset+CVE uniqueness

### 8.3 Sessions and transactions

- `Database.session()` is a context manager: commit on success, rollback on any exception, always close.
- The API uses one session per request (the `db_session` dependency). A job run uses one session per attempt.
- **The request commits before the response is sent.** Every `Depends(db_session, scope="function")` ends the
  session - commit or rollback - when the handler returns, before FastAPI sends the reply. FastAPI's default
  (`request` scope) ends it *after* the reply. A real-server check found an uploaded report's case missing from the
  very next case list in 28 of 40 tries (the upload is an `async` handler; sync handlers raced far less often but
  the same way), and a failed commit would have been reported to the client as success. Guarded by
  `test_commit_before_response.py`: every route's session scope is checked, and a real server must show each
  upload in the next list.
- **Exactly-once state transitions use conditional updates:** `UPDATE action_requests SET status=… WHERE id=… AND
  status IN (approvable)` and check `rowcount`. Six simultaneous approvals of one action execute it exactly once
  (tested).

### 8.4 Schema management

- `Database.create_all()` creates missing tables.
- `_add_missing_columns()` (both engines) then compares each existing table with the model and adds every column
  the model defines that the table lacks, **when that is safe: the column is nullable**, so existing rows simply
  get NULL. The DDL type is compiled for the running dialect and identifiers are quoted by the dialect. A new
  NOT NULL column is not added; it is logged as needing a scripted migration. This is how an existing database
  gained `llm_calls.latency_ms` (§12.2) with no manual step.
- On PostgreSQL, `_widen_columns()` then compares every VARCHAR column's length with the model and widens columns
  the model has made longer. That is always safe and loses no data. **Nothing is ever narrowed, renamed or dropped
  automatically.**
- Tested on both engines (`test_schema.py`): an "old" database loses a column, the new release starts, the column
  is back, existing data is intact, and a second start is a no-op.
- There is no migration framework yet (see §26). Additive changes (new tables, new optional columns, wider
  columns) are handled automatically; anything else needs a scripted migration.

### 8.5 SQLite specifics (dev and demo)

On connect:
- `PRAGMA foreign_keys=ON`
- `PRAGMA busy_timeout=30000`: a writer waits up to 30 s for a busy database instead of failing at once
- `PRAGMA journal_mode=WAL`: readers are not blocked by a writer

The embedded scheduler writes alongside request threads; measured under load, 90/90 requests succeeded during job
runs. In-memory databases use `StaticPool` so every session sees the same data.

---

## 9. The three workflow domains

### 9.1 Phishing (`domains/phishing/`)

**Pipeline** (`PhishingService.process`):
1. **Intake.** From the Defender reporting mailbox (original MIME fetched intact, so headers are preserved), Avanan
   events, or upload (`POST /api/v1/phishing/submit`).
   - The message is stored encrypted under its SHA-256 (`write_protected`: an atomic temp file + `os.replace`, with a
     short retry for Windows' transient replace lock under concurrency).
   - `source_ref` is unique, so a re-report returns the existing case. **Idempotent.**
2. **Decompose** (`agents/decompose.py`, pure stdlib):
   - headers, SPF/DKIM/DMARC, and the received path with the origin IP (the first non-private hop)
   - bodies, and all URLs, including hidden-link mismatches (link text ≠ target)
   - attachments (SHA-256, ssdeep-style fuzzy hash, risky extension, macro hints)
   - QR codes in images (pyzbar)

   **Hardened:** header access goes through `_hdr`/`_hdr_all`/`_part_meta`/`_headers`, which fall back to the raw
   header when Python's structured parser raises. It does raise, with `IndexError`, on a display name containing a
   raw newline; fuzzing found this stdlib bug. Undecodable payloads fall back to raw bytes. Arbitrary bytes never
   crash the parser (a fuzzing property).
3. **Analyse** (`agents/analyzer.py`). `HeuristicAnalyzer` is a sum of named, weighted signals:
   - authentication failures
   - look-alike sender/URL domains (edit distance, homoglyphs, brand embedding)
   - link tricks, credential lures, urgency, bank-detail change
   - risky attachments, threat-intel hits

   Strong authentication or an internal authenticated sender subtract weight. The score is clamped to 0-1.
   **Verdicts:**
   - malicious if ≥ 0.70, or ≥ 0.50 with malicious intel
   - suspicious if ≥ 0.35
   - spam if bulk or urgency without phishing signals
   - otherwise safe

   **The trained ML engine runs alongside it by default** (§21): `CompositeAnalyzer` asks both and fuses the two
   opinions. The heuristic is the fallback when the engine is not installed or fails.
4. **Enrich.** Threat-intel fusion on up to 12 indicators (sorted, so the same e-mail always checks the same
   ones). The indicators, and the 8 sources for each, are queried in parallel. A failed lookup is logged and the
   source reported as unavailable, never as clean.
5. **Investigate** (`agents/investigation.py`). The vendor lookups run **in parallel**, with results merged in a
   fixed order so the evidence is identical run to run (§16.2).
   - **Campaign.** Defender advanced hunting for similar messages (similarity threshold 0.5) gives recipients and
     variants.
   - **Control reconciliation.** Defender vs Avanan verdicts; a disagreement is a finding.
   - **User impact.** Clicks (`UrlClickEvents`, blocked or not), post-delivery actions, endpoint activity after the
     click, and identity compromise indicators (risky sign-ins, new MFA method, inbox rules).
6. **Case:** evidence (E#), MITRE mapping, cited explanation, recommendations through the policy.
7. **Auto-close.** Clear-safe and clear-spam at confidence ≥ 0.7 close with reporter feedback. 10 % are sampled for
   QA, chosen by a stable hash so the sample does not change between runs. Auto-closed mail gets a deterministic
   explanation and spends no LLM tokens (`SOC_LLM_EXPLAIN_AUTO_CLOSED=0`).
8. **Supplier monitor** (`supplier.py`), against `config/suppliers.yaml`:
   - account compromise: bad mail that *authenticates* as the supplier
   - payment diversion
   - impersonation (look-alike domain)
   - spoofing (claims the domain, fails authentication)

   Criticality amplifies severity; a click amplifies it further.

### 9.2 Incident (`domains/incident/service.py`)

1. **Ingest** from every alert-producing connector through the SyncRunner.
2. **Cluster** with union-find over alerts that share a resolved user or host within **24 hours** (a 30-day
   lookback). Detections with a poor track record in analyst dispositions are flagged as noisy.
3. **Investigate:** extract principals; `EnrichmentOrchestrator` fans out lookups to every enabled connector that
   supports each entity type, in a `ThreadPoolExecutor` (16 workers). Each lookup has a **20 s deadline** and a
   30-minute cache. Timeouts and failures become named "unavailable" results, and the case is marked incomplete
   rather than failing.
4. **Severity:**
   - base: the alert severity
   - critical on a deception hit
   - +1 level for KEV exposure on the host
   - at least high with 3+ corroborating dimensions

   **Confidence:** 0.35 + 0.10 per dimension, capped at 0.95. **Verdict:** true positive if ≥ high and ≥ 0.6
   confidence.
5. **MITRE:** alert metadata plus evidence rules (deception token → T1039, forwarding rule → T1114.003, risky
   sign-in → T1078, secret copied → T1555...).
6. **Recommendations**, ranked and policy-gated; similar past incidents by signature; handover report.

### 9.2.1 Deferred explanations (incident and phishing jobs)

The written explanation is the only part of an investigation that needs the model, and it is the slowest part
(§16.1). Nothing else depends on it: verdict, severity, confidence, MITRE mapping, evidence numbering and
recommendations are all computed in code. So the scheduled jobs split the work:

1. `investigate(case_id, narrate=False)` / `process(sub_id, narrate=False)` do everything, store the deterministic
   cited explanation (`deterministic_grounded`), and record in `case.assessment["narration_pending"]` what the model
   will need: the workflow, the question, the tier and **the exact evidence row ids** the case was assessed on.
2. The job **commits**. The cases are on screen and actionable, with recommendations waiting for approval.
3. `narrate_pending(ids)` (`CaseService.narrate_pending`, shared by both domains) rebuilds the evidence list from
   the stored row ids - so the E-numbers are identical, even if evidence was added since - and asks the model for
   all cases at once in a thread pool (`SOC_LLM_CONCURRENCY`). Results are applied in order on the job's thread.
   A grounded answer replaces the summary and claims and is audited as `case.narrated`; an answer that fails
   grounding, or no model, leaves the deterministic explanation. Either way the pending marker is removed.
4. If a job stops between steps 2 and 3, the next run picks up every pending case of the last 7 days
   (`pending_narration`).

The bulk API endpoints (`POST /incidents/run`, `POST /phishing/ingest`) use the same two steps within the request,
so a batch's explanations are generated in parallel instead of one after another. Single-case calls (investigate
one incident, upload one e-mail) still narrate inline. Tested: decisions are identical before and after
narration, calls overlap, evidence ids match, and nothing is left pending (`test_incident.py`,
`test_phishing.py`).

### 9.3 Vulnerability (`domains/vulnerability/`)

1. **Consolidate** Rapid7, CrowdStrike Spotlight, Defender TVM and Wiz findings, after entity resolution, into one
   `vm_findings` row per (asset, CVE) with every source listed.
2. **Enrich:** NVD CVSS (the connector pages explicitly: NVD returns an empty page for single-CVE lookups
   otherwise, which a live test caught), EPSS, KEV, internet exposure (Wiz), criticality and owner (CMDB/ServiceNow).
3. **Priority score:** 0.30 × CVSS/10 + 0.25 × EPSS + 0.20 × KEV + 0.10 × internet-exposed + 0.15 × criticality
   weight (critical 1.0 / high 0.75 / medium 0.4 / low 0.1).
   - **Bands:** P1 if ≥ 0.65 *or* KEV + internet-exposed; P2 ≥ 0.45; P3 ≥ 0.25; else P4.
   - **SLA:** 7 / 15 / 30 / 90 days from first seen. KEV always takes the P1 SLA. CISA's due date is informational
     only.
4. **Campaign per CVE:**
   - states: draft → notifying → in_progress → validating → closed
   - per-team action plans: awaiting_notification → notified → acknowledged → in_progress → done/blocked
   - notifications and tickets are action requests, so they go through approval
   - creating a campaign for a CVE that already has an active one returns it (idempotent)
5. **Weekly follow-up** (the job runs daily; the cadence is per plan, `SOC_VM_FOLLOWUP_DAYS`, default 7): each open
   plan hears from the SOC at most once a week - an escalation draft when it is unacknowledged 3+ days after
   notification, past its committed date or past SLA (a plan's first escalation goes out at once; level 2+ is
   "stalled"), otherwise a routine weekly status check with the open-finding count, which does not count as an
   escalation. The first version escalated the same plan every day. Two-way ticket sync. A ticket marked done while a
   scanner still sees the vulnerability is a **false closure**, reopened and counted.
6. **Validation:** re-query each scanner. The result per source is `still_present` / `not_present` /
   `unverifiable: <error>`, and a fix is never accepted on an unverifiable answer.
7. **Exceptions and risk register.** An exception needs a justification, a compensating control and an expiry, and
   is approved by a different person; expiry reopens the finding. The **risk register is kept current** after every
   vulnerability refresh (`refresh_risk_register`): open P1 CVEs are proposed as entries (a lead approves them);
   existing entries get their affected-asset count and owners updated; an entry is marked *remediated* once nothing
   is open and sent back to *proposed* for a lead to review if the vulnerability returns. Each change is audited
   (`vm.risk_register_updated`).
8. **Cloud misconfigurations** (`misconfig.py`): Wiz issues consolidated per (resource × rule), owner by CMDB or
   subscription, SLA by severity (tightened for toxic combinations on internet-exposed resources), routed, then
   fixed and validated against Wiz.
9. **Natural-language query:** keyword-to-filter mapping (status, priority, KEV, internet exposure, CVE, asset,
   team). The generated filter is shown with the answer. It is never SQL.

---

### 9.4 Shared case work: ownership, notes and search

- **Ownership.** `cases.assignee` (a work e-mail, lower-cased). `CaseService.assign`:
  - taking a case yourself needs `investigate`
  - giving it to someone else, or taking it off someone else, needs `approve_high_impact` (a lead)
  - releasing your own case needs only `investigate`
  - every change is audited (`case.assigned`, with the previous owner)

  `GET /cases?assignee=me|unassigned|<email>` filters; `GET /cases/summary` adds `mine` and `unassigned` counts.
  The case list has an *Owner* column and Everyone / Mine / Unassigned filters; the case page has *Take case* and
  *Unassign*.
- **Notes.** `case_notes` (case, author, text up to 4,000 characters, time). Append-only like an investigation log:
  a correction is a new note, nothing is edited or deleted. `POST /cases/{id}/notes` needs `investigate` and the
  case in scope; audited as `case.note_added` (length only, not the text). Shown newest first on the case page;
  each note's time is forced strictly after the case's previous note, so the order holds even for two notes in one
  clock tick (Windows' clock advances in ~15 ms steps; a full-suite run caught the random order).
- **Global search.** `GET /search?q=` (2-200 characters) from the box in the top bar. One query per group, each
  limited (default 10, max 50) and **each limited to what the caller may see**:
  - cases, by title or exact id (domain scope applied)
  - people, hosts and indicators, by display name **or any identifier from any tool** (UPN, e-mail, hostname,
    serial, MAC, cloud id...) through `entity_keys` - all-domain users only, because entities span domains
  - correlated findings (all-domain users)
  - vulnerabilities, by CVE or asset name (all-domain or vulnerability scope)

  Matching is case-insensitive substring with `LIKE ... ESCAPE '\'`; the user's `%`, `_` and `\` are escaped, so
  input is always literal (tested with `%` and `_`, which must not match everything). Each search is audited with
  its length only.

## 10. Intelligence layer

### 10.1 Risk engine (`intelligence/risk.py`)

- **Formula:** `score = round(100 × (1 − e^(−Σ decayed / 60)))`. It saturates towards 100, so one noisy signal can't
  max it out. Bands: critical ≥ 80, high ≥ 60, medium ≥ 30.
- **Weights:**
  - deception 50; phishing identity compromise 30 (once per person); risky sign-in 30/15
  - alerts 40/25/10/3 by severity; click 20; privileged credential access 15; KEV exposure 15
  - malicious destination 12; privileged user at risk 10; elevation denied 8; P1/P2 vulnerability 8/4
  - no EDR 5 (machines only); internet-exposed vulnerable 5; recipient 4
  - open incident: half its severity weight
- **Decay:**
  - Activity decays with a 7-day half-life (`HALF_LIFE_DAYS`).
  - `STANDING_SIGNALS` (open KEV/priority/exposed vulnerabilities, open incidents) count in full until closed.
  - `AMPLIFIER_TRIGGERS` fade with the signals that triggered them.
  - Found by time-travel testing: open exposure used to fade while still open, and the privileged amplifier never
    faded.
- **"Now"** is the latest observation in the data (`max(Entity.last_seen)`), so replayed or historic data decays
  sensibly. `as_of` evaluates at any instant. If every feed stops, scores freeze; stale connectors raise the alarm.
- **Rules:** each case counts once per entity whatever its roles; decoys are never scored.
- **Scale:** `candidates()` pre-filters to entities with a risk source (relations, case links, open findings) instead
  of profiling every entity. At 20,000 entities: 16 s → 0.06 s.

### 10.2 Correlation (`intelligence/correlation.py`)

12 deterministic rules emit `Insight` rows with the exact evidence relied on, a dedupe key, severity, score and next
steps:
- phishing → endpoint → identity chain
- privileged access after compromise
- deception corroborated
- exposed host under attack
- attacked host without EDR
- control gap
- repeat clicker
- new KEV exposure
- shared infrastructure
- high entity risk
- supplier risk
- model drift

Insights are upserted by dedupe key; a narrative is rewritten only when the evidence basis or severity changes, which
saves tokens. Operational insights come from elsewhere: job dead-letter, break-glass used, platform integrity, LLM
budget. A failing rule is logged and the other rules still run.

### 10.3 Attack story (`intelligence/story.py`)

1. **Scope** the principal users and hosts, plus related cases one hop away.
2. **Classify** each stored event onto an ATT&CK tactic, including phishing milestones.
3. **Group** events of the same stage within 15 minutes into steps. Confidence is high when 2+ tools corroborate or
   the detection is critical.
4. **Gaps:** for each tactic with no evidence, the enabled tools that could have seen it, or a *blind spot*.
5. **Test benign hypotheses** against specific evidence: rejected / unlikely / plausible / cannot assess.
6. **Blast radius.**
7. **Phased plan:** contain, preserve, eradicate, recover, communicate. Duplicates across related cases are merged.
8. **Assessment:**
   - *confirmed*: 3+ stages reached, a deep stage, 3+ tools, no plausible benign explanation
   - *likely*: a deep stage or 2+ stages
   - *attempt blocked*: every step blocked
   - otherwise *suspicious*
9. **Fingerprint:** a hash of the evidence. The same attack gives the same story from any related case, and deep
   analysis is cached per fingerprint.

It is rebuilt on demand and never stored. An event not in the store cannot appear.

### 10.4 Deep analysis (`intelligence/deep_analysis.py`)

- The LLM receives only story evidence ids (S/G/H/B/P/X) and must return fixed JSON.
- Uncited statements, invented ids and figures not in the cited evidence are dropped and counted. Statuses and
  confidence come from fixed vocabularies.
- Priorities may reference only real pending actions (`P#`) or "manual".
- Disagreement with the deterministic assessment is flagged.
- Results are cached on the case by fingerprint.

### 10.5 Analyst Q&A and brief (`intelligence/analyst.py`)

- **The planner** chooses tools from a fixed read-only catalogue: find_entity, search_entities, entity_risk,
  entity_timeline, top_risky, list_insights, search_cases, case_summary, vulnerability_query, affected_devices,
  pending_approvals, attack_story, entity_context.
  - The platform executes the calls: unknown tool names are ignored and arguments are type-checked; a failing tool
    is reported in the answer.
  - The answer must cite result ids (R#).
  - Without an LLM, a deterministic planner and a fact-list writer give the same interface.
- **The situation brief** is computed facts plus a cited narrative. It is cached for up to 15 minutes by a
  fingerprint of its facts, so opening the screen repeatedly costs one call per change. The intelligence job prepares
  it after every re-correlation, so with the built-in scheduler the first viewer does not wait either.
- **Counts are true totals** (`Page` totals), never the length of a capped list; a real bug once said "30" where
  there were 34.

### 10.6 Coverage, shadow IT, drift

- **Coverage** (`attack_coverage.py`): a static capability map of 56 ATT&CK techniques (41 marked priority) × tools (full/partial),
  intersected with *enabled* connectors, plus observed firing. It reports blind spots and single-source priority
  techniques. Enabling a connector changes the map immediately.
- **Shadow IT** (`shadow_it.py`): Umbrella DNS aggregated in memory per run (never stored: it's high volume and
  personal data) against `config/sanctioned_services.yaml`.
- **Drift** (`drift.py`): per domain, a recent window vs a baseline window on agreement with analyst dispositions,
  PSI of the verdict mix (alert above 0.2) and mean confidence. It raises `model_drift`.

---

## 11. Action layer and autonomy policy

### 11.1 Action requests (`core/actions.py`)

`ActionService` is **the only path to execution**.
- **`request()`** computes an **idempotency key**: `action_type:` + SHA-256 of the canonical JSON of (type, params,
  targets, case). An existing request with that key is returned, not duplicated. The policy then decides the
  outcome: observed, recommended, pending_approval, execute or blocked.
- **`approve()`:**
  - checks the permission: `approve_action`, or `approve_high_impact` when the decision is high-impact
  - refuses self-approval (the requester)
  - refuses non-human principals
  - then performs a **conditional update** (`status IN approvable`, check `rowcount`), so concurrent approvals
    execute exactly once
- **Execution** re-checks pre-conditions, calls the connector action and records the result or error (`failed` is a
  recorded status, never swallowed).
- **`rollback()`** creates a linked reverse action (`reverse_type`, e.g. `endpoint.isolate` → `endpoint.release`).
  It needs `rollback_action`.
- **Per-case actions** (tickets, notifications, reporter feedback) are never merged across cases. Other identical
  requests for the same targets are shared.
- Every transition is audited.

### 11.2 Policy (`core/policy.py`)

- **Levels:** L0 observe, L1 enrich, L2 recommend (default), L3 approve, L4 autonomous.
- **The per-action document** holds level, `max_targets` (default 25), `hard_limit` (default 5,000) and `four_eyes`.
- **`decide()` order:**
  1. precondition failure → blocked
  2. more targets than the hard limit → blocked
  3. kill switch → cap at L3
  4. destructive → cap at L3
  5. VIP/critical target → L3 + high-impact
  6. more targets than `max_targets` → L3 + high-impact
  7. four-eyes → high-impact

  All reasons are returned for display.
- **`PolicyStore`:** versioned documents; propose (automation admin) → approve (a different person with
  `approve_policy`) → active. Every version is kept.
- **Kill switch:** a durable flag in `system_flags` (or `SOC_KILL_SWITCH`), read by every replica. It halts
  autonomous execution immediately.

---

## 12. LLM gateway

### 12.1 Structure (`llm/gateway.py`)

`LLMGateway` wraps a `Provider` (`complete(system, user, tier) -> Completion(text, prompt_tokens, completion_tokens,
model)`).

**Providers:**
- `openai_compatible` (OpenAI, vLLM, Ollama, LM Studio)
- `azure_foundry` (the same protocol on Azure AI Foundry / Azure OpenAI v1, `api-key` header): the live-tested one
- `anthropic` (official SDK; server-side refusal fallback for the large tier)

**Tiers:**
- `large` for summaries, deep analysis and reports
- `small` for routine narrative and planners (`SOC_LLM_DEPLOYMENT_SMALL`)

### 12.2 Controls on every call

1. **Approved endpoints only.** A provider refuses an endpoint not in `SOC_LLM_APPROVED_ENDPOINTS` (fail closed).
2. **Pinned model.** A response from a different model version is logged as a mismatch.
3. **Pseudonymisation** (`llm/redaction.py`):
   - Internal e-mails, known names, phone numbers, Indian PAN and Aadhaar, and Luhn-valid card numbers become tokens
     (`<USER_1>`...), restored in the answer, including when the model drops the brackets.
   - IPs and attacker indicators are kept, because they are the evidence. IPs are shielded *first*, with random-tagged
     private-use markers, so no number pattern can swallow an octet. Card detection runs before the 12-digit Aadhaar
     pattern so spaced card numbers are masked whole.
   - Fuzzing found three bugs here: a marker lookalike crash, partial card masking, and IP corruption.
4. **Grounding** (`grounded()`, `complete_json()`). The model receives evidence with ids and must cite them.
   Uncited claims or claims with invented ids are dropped. No evidence means an explicit "insufficient evidence"
   answer with no model call.
5. **Numeric fidelity** (`unsupported_numbers`, `supported_summary`). A sentence stating a figure (a count, score,
   percentage or time) not present in the evidence it cites is removed. Identifiers (hostnames, IPs, CVE ids, dates)
   are not treated as figures. Removals are counted and shown.
6. **Timeouts** (`llm_timeout(tier)`): connect 10 s; read 30 s (small) / 120 s (large). A single 30 s limit once
   broke deep analysis on the real model, and the live suite caught it.
7. **Retry** (`post_with_retry`): one retry on 429/5xx after `Retry-After` (capped at 5 s).
8. **Circuit breaker** (`_Breaker`): after 3 consecutive failures, calls are skipped for 60 s (logged as
   `circuit_open`) and callers use the deterministic path instantly. The next success closes it. Before this, a hung
   endpoint could make an 8-section report take about 16 minutes.
9. **Diagnostics**: each call stores its trace id (the request or job that caused it), the answer cap, and for
   grounded answers every statement the evidence check removed with the reason (`guardrail`); each call is also a
   structured log line (`llm.call`). See OPERATIONS.md "Logs, traces and diagnostics".
9b. **Usage policy** (`llm/usage_policy.py`, set by administrators on the AI usage screen, versioned and audited,
   read once per gateway - one request or job run): monthly and daily token budgets; per-person hourly / daily limits
   (person override > most generous role override > default; 0 = no model text) for calls made on a person's behalf
   (`LLMGateway(actor=)`, set by `api/app.py:llm(s, p)` for questions, deep analysis and reports); per feature the
   tier, the answer cap (passed to providers as `max_tokens` when their `complete()` accepts it) and on/off. A refused
   call raises `BudgetExceeded` (`UserLimitExceeded` for a person's limit), logged with its reason; every caller
   already falls back to deterministic text, and `gateway.notice` tells the person why. Findings at the warning level
   and at 100 % of the month, and while a day's budget is used up, come from the self-check job.
10. **Logging.** Every call goes to `llm_calls`: workflow, tier, actor (None = scheduled), provider, model, tokens,
    status (`unparseable` when the answer was not JSON), the statements the grounding guardrail kept and removed,
    grounded flag, redacted prompt and response. `usage_report` turns it into per-feature use, cost, quality and a
    tier recommendation computed from those figures. The text is purged after `SOC_LLM_LOG_RETENTION_DAYS`; token counts are kept.

### 12.3 Concurrency

- **Thread-safe gateway.** A gateway's database use (the budget check and the call log) is serialised by a lock.
  The model calls themselves run outside it, so several can be in flight at once. The circuit breaker's counters
  have their own lock.
- **Batches run in parallel.** Finding narratives in a re-correlation, and the sections of a report, are sent to
  the model in parallel (`SOC_LLM_CONCURRENCY`, default 4; keep it under the provider's rate limit). The data for
  each item is computed first, in order and on the caller's session. Results are applied in order on the calling
  thread, so the output is the same as sequential.
- **Measured:** a first full re-correlation with 19 new narratives went from 67 s to 19 s, and a CISO report from
  22 s to 7 s.
- **Case explanations are deferred** in the incident and phishing jobs and batched in parallel (§9.2.1).
- **Response times are recorded.** Every call's duration is stored in `llm_calls.latency_ms`, and
  `GET /api/v1/llm/status` returns the median and 95th percentile per workflow over 30 days
  (`LLMGateway.latency_status`), so the figures in §16.1 can be checked against production.

**Design rule:** callers pass computed figures in as evidence; the model never produces figures. Turning the LLM off
changes no number, verdict or action; the test suite proves it on three estates.

---

## 13. Security architecture

### 13.1 Authentication (`core/auth.py`, `api/app.py:current_user`)

- **Production:** Entra ID. RS256 tokens verified against the tenant's JWKS (`PyJWKClient`), with audience and
  issuer (`https://login.microsoftonline.com/<tenant>/v2.0`) enforced, and **`exp` and `iat` required**. Missing
  tenant or audience configuration fails closed.
- **Development:** HS256 tokens signed with `SOC_DEV_JWT_SECRET`, also requiring `exp`/`iat`.
  - Refused entirely when `SOC_ENVIRONMENT=prod`.
  - `/api/v1/dev/token` answers only on loopback unless `SOC_DEV_TOKENS_REMOTE=1`.
- **Algorithms are pinned per mode.** `alg: none`, HS256 signed with the public key (algorithm confusion), HS512,
  other keys, wrong audience/issuer, expired and not-yet-valid tokens are all refused (tested).
- **Service accounts:** `X-API-Key` of the form `sk_soc_<id>_<secret>`.
  - Only SHA-256 of the secret is stored, and comparison is constant-time even for unknown ids.
  - Keys expire (at most 365 days).
  - They may hold only analyst, auditor or automation-admin roles.
- **Break-glass:** the `X-Break-Glass` header. Only the credential's SHA-256 is configured (`SOC_BREAKGLASS_SHA256`),
  compared in constant time. Every use and every failed attempt is audited, and a use raises a critical insight.
- **Revocation:** per token (`jti`, used by logout) and per principal (`not_before`, "revoke all sessions").
- **Step-up MFA:** `approve_action`, `approve_high_impact`, `approve_policy`, `kill_switch`, `manage_access` and
  `rollback_action` need `amr` containing `mfa`, or the configured Conditional Access auth context. It's on by
  default in production.

### 13.2 Authorisation

- **Roles → permissions** (`ROLE_PERMS`): analyst, lead, automation_admin, admin, auditor (PRESENTER_GUIDE.md §15.3).
- **Human-only permissions** (`HUMAN_ONLY_PERMS`: approvals, policy, access management, rollback) are never granted
  to API-key principals, whatever roles they hold.
- **Domain scope:** a principal may be limited to phishing / incident / vulnerability.
  - Every list is filtered.
  - Every id route checks the record's domain and answers **404** out of scope, which also hides existence.
  - The audit log, access log and reports are scoped too. Cross-domain views (intelligence, brief, `/metrics`) need
    all-domain scope.
  - Tested for every id route with a phishing-only user.
  - **Scope is per role.** What a principal may *see* is the union of its roles' scopes; what it may *do* in a
    domain comes only from roles covering that domain (`Principal.role_domains`, `acting_in`). `need(perm, domain)`
    hands the handler the principal as it acts in that domain; case writes act in the case's domain; `ActionService`
    judges every approval, rejection, rollback and request-time self-approval in the action's domain. An action
    requested on a case belongs to the case's domain; case-less actions are `platform` (all-domain roles only).
    Platform grants add a role with its own scope; a scoped administrator grants only their own domains.
- **Separation of duties:** nobody approves their own action, policy, exception or access grant; the proposer of a
  policy cannot approve it.

### 13.3 Web and input hardening

- **Headers on every response:**
  - `Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src
    'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'`
  - `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`,
    `Cross-Origin-Opener-Policy: same-origin`, `Permissions-Policy`, `Cache-Control: no-store`
  - HSTS on HTTPS (including `X-Forwarded-Proto: https` from a trusted proxy)
- **No CORS grants.** The console is same-origin.
- **Limits:**
  - body size 30 MB, enforced on the byte stream (chunked uploads without Content-Length too)
  - per-client token bucket (20/s, burst 120). `X-Forwarded-For` is read only from `SOC_TRUSTED_PROXIES`, and the
    client is its right-most hop that is not a proxy (the left-most is caller-controlled). Past 50,000 tracked
    addresses, idle buckets are evicted.
  - linear-time content parsing: every regex over e-mail content is bounded (§25 #36); unknown ids answer 404 and
    programming errors a generic 400, never interpreter internals
- **Input handling:**
  - NUL in path or query is refused (400)
  - database `DataError` → 400, never 500
  - Pydantic validation on bodies
  - query parameters bounded (`Query(le=…)`, patterns)
- **Output escaping in the console:** every interpolated value goes through `esc()`. Clicks are dispatched only to
  an allow-list (`ALLOWED`) of functions via `data-fn`, never `eval` or inline handlers. The stored-XSS probe (8
  screens, CSP disabled) executed nothing.
- **No SSRF surface.** No code path fetches URLs taken from e-mail content; outbound calls go only to configured
  vendor endpoints and configured notification webhooks (HTTPS only, from settings, never from data). The unwired visual-URL scaffold returns "unavailable" instead of a made-up verdict.
- **No template injection.** No template engine renders user text.

### 13.4 Data protection

- **Encryption at rest** (`core/crypto.py`): raw payloads, reported e-mails, generated reports and evidence packs.
  - Fernet (AES-128-CBC + HMAC-SHA256) via **MultiFernet**. `SOC_DATA_KEY` holds comma-separated keys: the first
    encrypts, all decrypt, so keys rotate without bulk re-encryption.
  - Files carry a `SOCENC1:` prefix; legacy plaintext is still readable.
  - `write_protected()` writes atomically with owner-only permissions (0600).
  - A key is mandatory in production.
- **Retention** (`core/retention.py`), all configurable, each run audited:
  - raw payloads pruned after 180 days
  - e-mails of closed cases after 180 days; open cases are on legal hold
  - LLM prompt text purged after 180 days (token counts kept)
  - the access log after 400 days
  - **the audit log never**
- **The audit chain** (`core/audit.py`): each record's SHA-256 covers the previous record's hash and the record's
  canonical fields. The ORM refuses UPDATE/DELETE on the table. `verify()` recomputes the chain and reports the first
  bad sequence.
  - **Concurrent appends are serialised** by updating a chain-head row first (`_lock_chain`): a row lock on
    PostgreSQL, the write lock on SQLite. This was found by a concurrency test: 8 simultaneous writers forked the
    chain on both databases before the fix.
  - In production, grant the service role INSERT/SELECT only on `audit_log`.
- **The access log** records every API request (principal, auth method, method, path, status, client IP, user
  agent, latency). Rows are queued and written in batches by a background thread, **bound to the database of the
  request that produced them**, which fixed rows landing in the wrong database when the default changed before a
  flush.

### 13.5 Secrets

- No secret has a default.
- Every secret can come from `<NAME>_FILE` (vault or CSI mounts).
- `.env` is gitignored, and a scan before every push checks no configured secret value appears in any tracked file.

---

## 14. Reliability

### 14.1 Jobs (`jobs.py`)

Ten jobs:

| Job | Default interval |
|---|---|
| notify | 1 min |
| phishing | 2 min |
| incident | 5 min |
| intelligence | 10 min |
| self_check | 1 h |
| vulnerability | 6 h |
| follow_up | 1 day |
| daily_report | 1 day |
| weekly_reports | 7 days (weekly VM report + weekly management deck) |
| retention | 1 day |

Intervals are set by `SOC_JOB_*_SECONDS`.

`run_job(name)`:
1. **Lease:** `system_flags[job_lease:<name>]` with holder = `hostname:pid:thread-id` and a 30-minute expiry. If
   another holder has a live lease, skip. Taking it is atomic: an existing row is changed with a compare-and-swap
   (`UPDATE ... WHERE updated_at = <value read>`, one row changed or the lease is lost), and the first-ever lease is
   an insert that only one scheduler can win; the loser gets "not acquired", never an exception. (A first version
   read then wrote: two schedulers starting together both inserted the row and one pass crashed. It hid behind a
   thread warning in a passing test; the scheduler tests now fail on any exception in a background thread.)
2. **Check again once the lease is held** (`still_due`). If someone ran the job between the due check and the lease,
   skip.
3. **Run** the body in its own session, retrying up to 3 attempts with exponential backoff (2ⁿ s, capped at 60 s).
4. **Record** a `JobRun` (start, end, attempts, status, error, JSON summary, strictly increasing ordinal).
   `dead_letter` after 3 failing runs in a row raises a `job_dead_letter` insight. It keeps being attempted on
   schedule, so it recovers on its own.
5. **Release** the lease. This happens **after** the record is written; releasing before it let a second scheduler
   run the job again, which a race test found.

### 14.1.1 Notifications (`core/notify.py`)

Important findings are pushed to Teams, Slack or any webhook by the `notify` job (every minute):

- **What:** every finding (`insights`) with status `new` and severity at or above `SOC_NOTIFY_MIN_SEVERITY`
  (default `high`). Operational alerts are findings, so a dead-lettered job, break-glass use, a failing self-check
  and the LLM budget are sent too - no separate alerting path.
- **Where:** only the channels in `SOC_NOTIFY_WEBHOOKS` / `SOC_NOTIFY_WEBHOOKS_FILE` (`kind|url`, kinds `teams`,
  `slack`, `json`). Only `https://` is accepted (`http://` only to localhost). No address ever comes from data,
  so an e-mail or alert cannot make the platform call out somewhere (no SSRF path). Invalid entries are skipped
  with a warning, never a start-up failure.
- **Once per channel:** `notifications` has a UNIQUE (`dedupe_key`, `severity`, `channel`). The same finding is not
  repeated; an escalation to a higher severity is a new row, so it is sent again.
- **Failures:** recorded on the row (`failed`, `attempts`, `last_error`) and retried each run, up to 5 attempts.
  10 s read / 5 s connect timeout. A delivery failure never affects the job that raised the finding.
- **Secrets:** the channel is stored and shown as `kind:host` only. The webhook URL, which contains its credential,
  is never stored, logged or returned by the API.
- **Payload:** Teams and Slack get `{"text": "[HIGH] title\n- next step..."}` with a link to the console when
  `SOC_PUBLIC_URL` is set; `json` gets a structured record (id, rule, severity, title, status, domains, next steps,
  first seen) for a SIEM or SOAR.
- **Visible:** Integrations → *Notifications* card and `GET /api/v1/admin/notifications` (audit-read, all-domain).
- **Test message:** `POST /api/v1/admin/notifications/test` (*Send test message*, `manage_connectors`) posts a marked
  test message to every channel and returns a result per channel (`kind:host`, ok, error). Audited, not recorded
  as a delivery, and it never returns the URL.
- Tested in `test_notify.py`: threshold, once per channel, escalation, retry cap, HTTPS-only parsing, secret file,
  and the job wiring.

### 14.2 Scheduler (`scheduler.py`)

- **Embedded by default:** the API's lifespan starts it (`SOC_EMBEDDED_SCHEDULER=1`) and stops it on shutdown. One
  process is the whole platform. `python -m soc_platform scheduler` runs the same code standalone.
- **The database decides what is due:** a job is due when no run of it, by anyone, started within its interval. A
  restart does not re-run everything, and extra schedulers do not double-run.
- **Threads:** a supervisor restarts the heartbeat and job threads if either stops. The job loop catches every
  exception per pass. Retry backoff waits on the stop event, so shutdown is prompt.
- **Heartbeat:** `system_flags[scheduler:<sha256(holder)[:24]>]` records the holder, mode and `at` (every 30 s from
  a separate thread), plus `loop_at` and the current job from the loop. The key is hashed because the flag key column
  is 64 characters. Rows gone for a day are pruned. Both threads write the same row, so each write merges its own
  fields into the latest version with a compare-and-swap on `updated_at` (retried on conflict). A plain
  read-modify-write let the heartbeat put back an older copy, so the "running job" could briefly be wrong; a race
  test reproduced it in 1 of 10 runs and now guards it. The version a swap writes is always later than the one it
  read (`jobs.next_version`): with `now` alone, two writes in one ~15 ms Windows clock tick got the same stamp and a
  stale writer still matched (it showed once in a full run); a frozen-clock test reproduces that every time.
- **`status()`** for `/health`:
  - `running`
  - `stuck`: alive, but a job has run past its lease (30 min)
  - `stale`: no heartbeat for `SOC_SCHEDULER_STALE_SECONDS`, default 180 s - unless the scheduler runs inside this
    server and its heartbeat thread is alive and still trying (`alive_here`): then `running` with
    `heartbeat_write_delayed`. On SQLite a long transaction (a slow LLM call in a demo) blocks the heartbeat write,
    and the console used to show "Scheduler stopped" for a scheduler that was fine; the browser tour caught it.
  - `never`

  The console shows "Scheduler stopped" or "Scheduler stuck (job)".
- **Verified:** 28/28 repetitions of the two-schedulers race test; a real server with real jobs (90/90 concurrent
  requests OK); a second scheduler and a restart re-ran nothing.

### 14.3 Idempotency everywhere

| Operation | Mechanism |
|---|---|
| Reported e-mail | unique `source_ref` / content hash: one case per message |
| Actions | unique idempotency key: the same request returns the existing one |
| Campaigns | one active campaign per CVE |
| Insights | dedupe key: upsert |
| Connector sync | cursors plus natural source ids |
| Jobs | database-decided due time plus lease |

Tested by running every pipeline and job twice on three estates with zero change.

### 14.4 Platform self-check (`core/selfcheck.py`)

Hourly, and on demand at `GET /api/v1/admin/self-check`:
- It recomputes each shared figure (awaiting approval, open cases, open findings, open insights...) through every
  independent code path (dashboard, database count, analyst tool, report builder) and compares them.
- It resolves every stored reference and checks uniqueness invariants.
- It verifies the audit chain.

`confirm()` re-runs a failing check before alerting, so a commit landing between two counts can't raise a false
alarm. It raises or resolves `platform_integrity`, and checks the LLM budget.

### 14.5 Failure handling summary

Per-source timeouts; partial results named; LLM breaker; connector backoff; dead letters; a scheduler that heals
itself; durable kill switch; hostile-input hardening. The full table is in [FAILURE_MODES.md](FAILURE_MODES.md).

---

## 15. Consistency and correctness mechanisms

- **One computation per figure.** Each figure has one function, and every surface (dashboard, lists, badges, brief,
  analyst answer, report, generated document) calls it. The consistency suite compares them all, including values
  read off the rendered screens.
- **True totals.** Summary endpoints (`/api/v1/cases/summary`, `/api/v1/actions/summary`) give counts; lists say
  "showing N of M". Backlogs are never windowed: an approval waiting 90 days is still waiting.
- **Scoped consistently.** The dashboard's action counts use the same domain scope as the action list.
- **UTC everywhere,** explicit offsets in every API timestamp, "All times UTC" in the console.
- **The platform clock** (`core.models.utcnow`):
  - `SOC_CLOCK_OFFSET_SECONDS` shifts it (time-travel tests)
  - `SOC_CLOCK_FREEZE` stops it (runs compared figure-for-figure)
  - both are ignored in production
- **Determinism:** QA sampling by stable hash; story fingerprints; ordered evidence numbering (collection time, then
  row id).

---

## 16. Performance and scale

| Hot path | Technique | Measured |
|---|---|---|
| Risk ranking | `candidates()` pre-filter; reuse while the data is unchanged (#47) | 20,000 entities, little activity: ~16 s → 0.06 s; 21,728 entities, realistic activity: 9.4 s → 4.7 s once, then 0.02 s |
| Ingestion | exact resolution candidates, (kind, canonical key) index, page-level savepoints (#42, #45) | 40x messy estate: sync 244 s → 149 s, flat 29 statements per record; per new host flat (was 1,846 statements at 600 hosts) |
| Request load | several server processes, sized pool, 503 under saturation (#46) | 1 process: 43 requests/s, everything queued; 4 processes: 150 requests/s for 100 analysts, no error |
| Correlation | runs over risk candidates only | 36.5 s → 0.09 s |
| A case's shared actions | database-side `LIKE` narrowing on the JSON result before the Python check | 20,000 actions: 0.47 s → 0.005 s |
| Situation brief | cached by facts fingerprint (15 min) | one model call per change, however many viewers |
| Enrichment | parallel lookups (16 workers), 30-minute cache | bounded by the slowest source, capped at 20 s |
| Access log | batched background writes (up to 500 rows per batch) | no per-request write latency |
| Finding narratives | rewritten only when evidence or severity changes | token saving (LLM_TOKENS_AND_COST.md) |

The API is stateless and scales horizontally. The scheduler coordinates through the database. Volume and request
load are measured with `scripts/measure_scale.py` (messy estates of growing size, statements per record, review
queue) and `scripts/load_test.py` (a real multi-process server, concurrent analysts, jobs writing); figures in
OPERATIONS.md. The client's own volume is measured during deployment (§26).

### 16.1 Latency: measured end to end

Measured on a laptop with every vendor API call delayed **400 ms**, which is typical for Microsoft Graph,
CrowdStrike and similar SaaS APIs, and with the real LLM (Azure AI Foundry, gpt-4.1-mini). Figures are for one item
on the built-in estate. The script is the one used for §12.3; the vendor-call counts let you rescale to other API
speeds.

| Step | Who waits | Vendor calls | Without LLM | With LLM |
|---|---|---|---|---|
| Analyse a reported phishing e-mail (campaign, clicks, impact) | nobody (background) - sets time to case | 31 | **2.9 s** (was 12.5 s) | 9-12 s (the model writes the explanation) |
| Analyse a benign e-mail (auto-closed) | nobody | 20 | **1.2 s** (was 8.1 s) | 1.2 s (no model call) |
| Ingest alerts from every tool (incident) | nobody (every 5 min) | 11 | **0.9 s** (was 4.5 s) | 0.9 s |
| Investigate an incident (enrichment across tools) | nobody | 92 | **1.8-2.6 s** (was 3.8 s) | 8-16 s (the model's response time varies) |
| Vulnerability refresh (4 scanners + feeds) | nobody (every 6 h) | 32 | **6.5 s** (was 13.1 s) | 6.5 s |
| Re-correlate (risk, 12 rules, narratives) | nobody (every 10 min) | 0 | 0.1 s | 19 s first time (was 67 s); 0.1 s when nothing changed |
| Open a case, story, 360 view or list | analyst | 0 | < 0.1 s | < 0.1 s (results are stored) |
| Situation brief | analyst | 0 | < 0.1 s | 0 s when prepared by the job; ~6 s if not yet prepared |
| Analyst question | analyst | 0 | < 0.1 s | ~6-7 s |
| Deep analysis | analyst (on request) | 0 | - | ~14 s once, then instant (cached) |
| Report (CISO weekly, all sections) | analyst | 0 | 0.2 s | ~7 s (was 22 s) |

**With deferred explanations (§9.2.1)** the case is on screen at the "Without LLM" time even when the model is on;
the model's explanation follows a few seconds later, and in a batch the explanations for all of a run's cases are
written in parallel (a run of 10 incidents waits for about 3 model calls' time with `SOC_LLM_CONCURRENCY=4`, not 10).

**Time from a user pressing *Report* to a case on screen** = up to the phishing job interval (default 2 minutes;
lower `SOC_JOB_PHISHING_SECONDS` for faster pickup) + the analysis above. Uploads through the console are analysed
immediately.

### 16.2 How the latency was brought down

- **Parallel syncs** (all three modules). `SyncRunner.sync_many` downloads every (tool, stream) at once, while the
  calling thread ingests each stream's pages in the original order, with a checkpoint after every page. The result
  is identical to syncing one stream after another, in about the time of the slowest stream. Used by incident
  ingest (inventory still ingested before alerts), the vulnerability refresh (assets before findings) and the
  scheduler's jobs.
- **Parallel vulnerability intelligence.** The KEV catalogue, EPSS scores and every due NVD detail are fetched at
  once, then applied in CVE order. NVD without an API key simply queues on its rate budget.
- **Parallel vendor lookups.** In one phishing analysis, these all run in parallel in bounded thread pools:
  - the threat-intel indicators, and the 8 sources for each indicator
  - control reconciliation, alongside campaign scope and user impact (reconciliation is awaited first only when
    campaign scope depends on it: a "clean" verdict that the controls disagree on)
  - the DNS queries per domain
  - the per-user checks, and within each user Defender for Endpoint, CrowdStrike and Entra
  - Entra's seven identity-context reads

  Incident enrichment was already parallel (16 workers, 20 s deadline per source).
- **Determinism is kept:** results are always merged in a fixed order, and the connector registry builds each
  connector once under a lock. Re-running every pipeline still changes nothing, and LLM on vs off still gives
  identical figures on all three estates.
- **Rate limits are respected:** every call still goes through its connector's token bucket, which is thread-safe,
  so parallelism never exceeds a vendor's budget.
- **Parallel LLM batches**, the prepared brief and deferred case explanations (§12.3, §10.5, §9.2.1).
- **A regression test** (`test_phishing_analysis_asks_the_tools_in_parallel`) fails if an analysis takes more than
  half the time its vendor calls would take one after another.

---

## 17. API design

- **REST under `/api/v1`**, JSON, grouped by domain:
  - `/cases`, `/actions`, `/phishing`, `/incidents`, `/vm`, `/intelligence`, `/reports`, `/admin`, `/audit`,
    `/jobs`, `/connectors`, `/dashboard`, `/entities`, `/resolution`, `/policy`, `/kill-switch`, `/llm`,
    `/ingest/alerts`, `/search`
  - collaboration: `POST /cases/{id}/assign`, `POST /cases/{id}/notes`; notifications:
    `GET /admin/notifications`, `POST /admin/notifications/test`
  - `/health` (unauthenticated: status, audit chain, kill switch, scheduler) and `/metrics` (Prometheus text,
    audit-read permission)
- **Permissions are declared per route** with `Depends(need(Perm.X, "domain"))`. Record-level scope is checked in
  the handler (`_case_in_scope`).
- **Errors:** 400 for invalid input, 401 unauthenticated, 403 not permitted (with a reason), 404 unknown or out of
  scope, 413 too large, 422 schema validation, 429 rate-limited. Never a stack trace.
- **Idempotent writes** (see §14.3). `POST /actions/{id}/approve` with an empty body `{}`.
- **OpenAPI** at `/docs` in dev only.

---

## 18. Frontend

- **A no-build vanilla JavaScript SPA:**
  - `index.html`
  - `app.js`: shell, hash router, sign-in, API wrapper, click delegation, health polling
  - `views.js`: one function per screen, rendered to HTML strings with `esc()`
  - `theme.js`
  - `styles.css`: CSS variables for light and dark themes
- **CSP-compatible by construction:** no inline scripts or handlers. `data-fn` / `data-args` (JSON) are dispatched
  through the `ALLOWED` map, and `data-enter` handles Enter-to-submit.
- **Data:** every screen reads the same API a script would use. Badges and tabs use summary endpoints. `/health` is
  polled for the kill-switch and scheduler status pills.
- **Auth in dev:** the sign-in form mints a dev token (loopback only) kept in `localStorage`. Production uses Entra
  sign-in; see §26 on token storage.
- **Accessibility:** labelled controls, underlined in-text links, AA contrast. It passes axe-core WCAG 2.1 A/AA on
  every screen in both themes.
- **Responsive:** audited at 1440, 1280, 1024 and 768 px (nothing clipped, overflowing or squeezed; no table needing
  sideways scroll at desktop widths).

---

## 19. Reporting

- **Builder** (`reporting/builder.py`): a report is a **spec** (title, audience, format docx or pptx, sections).
  - Each section pairs a **data source** from a catalogue of 16 computed sources with a writing instruction.
  - There are 7 standard specs; saved specs live in `report_templates`.
  - A report described in words is planned by the LLM (or keyword rules) using catalogue sources only, and shown
    for review first.
  - Narrative per section cites fact ids (F#); uncited or unsupported sentences are dropped.
  - **Charts** (`reporting/charts.py`): a source may return chart data built from its own figures. PowerPoint gets
    a native python-pptx bar chart; Word gets a PNG drawn with Pillow (no plotting library; the same data gives the
    same bytes, so reports stay deterministic).
  - Downloads re-check that the reader's scope covers every domain in the report.
- **Recurring and per-case reports** (`reporting/reports.py`): daily exposure, weekly VM, weekly management deck,
  per-case investigation record. A client's `.docx` or `.pptx` template can be the base.
- **Compliance pack** (`reporting/compliance.py`): a ZIP of `evidence.json` (controls, computed pass/fail tests,
  figures), `audit_log.jsonl` (full chained export with verification) and `summary.docx`. No secrets and no prompts.
- **Output** is encrypted at rest and audited.

---

## 20. Configuration and secrets

- `config.get_settings()` builds a cached `Settings` from environment variables with the `SOC_` prefix. `.env` is
  not read automatically; `scripts/load_env.ps1` loads it for a session, and `docker compose --env-file` in
  containers.
- **Production posture** comes from `SOC_ENVIRONMENT=prod`:
  - MFA on by default
  - no `/docs`, no dev sign-in
  - a data key required
  - test clocks ignored
- **Connectors:** `config/connectors.yaml` plus approved console changes (§5.5; OPERATIONS.md "Connecting and
  changing tools"). Each process re-reads which console version is in force every `SOC_CONFIG_RELOAD_SECONDS`
  (5), so an approved change applies everywhere without a restart. The supplier and sanctioned-service lists can be
  replaced in the console the same way (`load_suppliers(session=)`, `registry.lists`). **Suppliers:** `config/suppliers.yaml` (or `SOC_SUPPLIER_DOMAINS`).
  **Sanctioned services:** `config/sanctioned_services.yaml`. **Organisation domains:** `SOC_ORG_DOMAINS`.
- **Settings from the environment are strings.** Boolean and JSON connector settings are parsed explicitly
  (`RAPID7_VERIFY_TLS=false` turns verification off; `GENERIC_SIEM_FIELD_MAP` is a JSON object), and the database URL,
  which carries a password, can come from a vault file (`SOC_DATABASE_URL_FILE`); `init-db` prints it with the password
  masked.
- **Corporate CAs:** `SSL_CERT_FILE` (honoured by httpx) covers every outbound TLS connection; `SOC_LLM_CA_BUNDLE`
  covers only the LLM gateway.
- Moving into a client environment (hosting, sign-in, each tool, the client's own LLM):
  [CLIENT_DEPLOYMENT_GUIDE.md](CLIENT_DEPLOYMENT_GUIDE.md).
- The full list of settings is in [OPERATIONS.md](OPERATIONS.md). Every setting in production documentation is also
  in `deploy/docker-compose.yml`.

---

## 21. The phishing ML engine (trained models per e-mail component)

`soc_platform/domains/phishing/engine/` is an earlier, self-contained phishing analysis system. It runs **inside the
platform by default** whenever its libraries (scikit-learn, XGBoost, LangGraph) are installed:
- a seven-agent swarm: header, content NLP, URL, attachment/OCR, sandbox, threat intel, user behaviour
- a LangGraph decision graph (weighted scoring with a consensus boost), a counterfactual engine, MITRE mapping
- RabbitMQ workers, Redis caching and a sandbox executor for detonation, when deployed as its own service
- models verified by SHA-256 manifest before loading

**The trained models** (`artifacts/phishing/models/`): header (random forest), content (a text classifier, below), URL
(random forest), attachment and sandbox (scikit-learn), threat intel and user behaviour (XGBoost).

**The content model was replaced** (2026-09-29). The delivered model was a 2-layer BERT reading the first 128 tokens;
on 2,000 held-out public messages it reached 68 % accuracy and caught 25 % of phishing, and on the platform's corpus
it called three phishing e-mails "Legitimate" with 90-95 % confidence and never predicted *Spam*. The new model
(`scripts/train_content_model.py`, model card in `content_agent/model_card.json`):
- TF-IDF word (1-2) and character (3-5) features + logistic regression, three classes (legitimate, spam, phishing);
  9.5 MB, half the old model, ~6 ms per e-mail on a laptop CPU (measured; the list of 300k feature names
  used to explain a score is built once per loaded model - rebuilding it per e-mail cost 149 ms)
- the whole message, HTML reduced to visible text; links, addresses and numbers as neutral tokens
  (`content_agent/text_prep.py`, the same function in training and at inference)
- risk = expected risk over the classes (legitimate 0, spam 0.65, phishing 0.95); the words that pushed most towards
  the predicted class become evidence (`content_terms:`)
- trained on public data: the Nazario phishing corpus 2019-2025 (real phishing; CC BY 4.0 - attribution below),
  the SpamAssassin public corpus (legitimate and spam; non-live testing terms: the messages are never sent) and the
  "Safe Email" rows of zefang-liu/phishing-email-dataset (LGPL-3.0). That dataset's "Phishing Email" rows were left
  out: most are ordinary spam, which would teach "spam = phishing". 11,499 messages after de-duplication, 20 %
  held out
- results: hold-out 99.1 % accuracy (phishing recall 98.9 %, spam 96.3 %) - likely flattered by the older
  legitimate mail - and, on the platform's corpus it was never trained on, 10 of 12 base messages right (the old
  model 7), every phishing message caught. It still reads invoice wording as phishing, so it never confirms an alarm
  on its own.

Attribution: phishing corpus by Jose Nazario, https://monkey.org/~jose/phishing/, licensed CC BY 4.0.

**Integration:**
- `SOC_PHISHING_ENGINE`: `auto` (default: on when installed), `1` (on), `0` (heuristic only). Used by the server,
  the jobs and `demo` (which prints which analysis it used). The test suite pins `0` except `test_phishing_engine.py`.
- `EngineAnalyzer` runs the agents in parallel on the parsed e-mail, then the engine's decision graph. The engine's
  own persistence, actions, LLM and the retired "Garuda" hop are disabled; the platform's action layer, policy,
  audit, LLM gateway and impact agents replace them.
- Models load in a background thread at server start (`warm_up_engine`): ~9-11 s on a laptop CPU, then ~1 s per
  e-mail. The models are cached per process.
- The engine logs through loguru at INFO per graph node; in-process it is set to `SOC_PHISHING_ENGINE_LOG_LEVEL`
  (default `WARNING`). scikit-learn is pinned to 1.8.x, the version the models were saved with.

**The platform feeds the models what they cannot see in the e-mail** (each measured before and after, below):
- **Threat intel:** inside the platform the engine's own agent had no API keys and an empty local store, so it
  scored every message 0. It now receives the platform's threat-intel fusion (8 sources, already queried by the
  heuristic for the sender domain, link domains, attachment hashes and origin IP; `platform_threat_intel_result`):
  malicious indicators score 0.8-1.0 by how many sources agree, suspicious 0.45, nothing found 0.
- **User behaviour:** four of its seven inputs were defaults in this deployment (contact history "never", department
  "medium risk", business hours "always"). The platform now supplies them (`behavior_context`, passed as
  `payload["behavior_context"]` and read by the engine's feature contract): the recipient's delivered-mail history
  with the sender's domain over 90 days (Defender for Office 365 advanced hunting, `sender_history`, the reported
  message itself excluded), the recipient's department (the directory) and whether the message arrived in business
  hours (its Date header, in the sender's time zone). Anything that cannot be looked up keeps the model's default.
- **Sandbox:** without an isolated detonation host only the agent's static fallback runs, and on the labelled corpus
  that ranked malicious attachments no better than chance (separation 0.40) while the attachment agent covers the
  same ground correctly. It is therefore **not run** in-platform unless `SOC_PHISHING_SANDBOX=1` (a detonation host
  is configured).

**Fusion** (`CompositeAnalyzer.fuse`): the more severe verdict wins; both opinions, every model's score and each
model's measured reliability are kept on the case and shown on the case page (*Analysis*). Two safeguards send a
case to an analyst as *suspicious* instead of declaring it malicious:
- **Corroboration:** when the engine alone says malicious (the heuristic says safe or spam) and none of the reliable
  models (header, URL, attachment, threat intel - `MODEL_RELIABILITY`) scores 0.5 or more, i.e. only the content and
  user-behaviour models drove it.
- **Authenticated sender:** when the engine alone calls a DMARC/DKIM-authenticated sender malicious below 0.85.

Engine indicators that describe the agent's own state or an absence (`ml_header_model_used`, `urls_analyzed=2`,
`virustotal_not_configured`, `no_attachments`, the content model's own label...) are not turned into evidence
(`ENGINE_STATUS_NOTE`, checked against every indicator the agents emitted on the corpus).

**Measured** (`scripts/eval_phishing.py --engine [--no-context]`: the built-in corpus plus the corpora of two
generated organisations, each analysed against its own tools and people; 46 labelled messages, 28 malicious or
suspicious, 18 legitimate or spam):

| | Detection | Legitimate called malicious | Exact verdict |
|---|---|---|---|
| Heuristic analyser alone | 28 / 28 | 0 | 44 / 46 |
| ML engine alone, without the platform's data | 22 / 28 | 3 (the genuine invoice, in each organisation) | 33 / 46 |
| ML engine alone, **with** the platform's data | 22 / 28 | **0** | 36 / 46 |
| ... and the new content model | **25 / 28** | **0** | **39 / 46** |
| **Combined, as the platform runs it** | **28 / 28** | **0** | **46 / 46** |

Each model on its own (separation: the chance a malicious message scores above a legitimate one; 0.5 = coin flip):

| Model | Separation | Notes |
|---|---|---|
| Header | 0.85 | never scored a legitimate message 0.5+; misses attacks with clean authentication |
| URL | 1.00 on the 13 messages with links | 0.49 over all 46: a message without links scores 0, correctly |
| Attachment | 1.00 on the 13 with attachments | ranks correctly but scores many malicious attachments below 0.5 |
| Content | 0.88 → **0.99** with the new text classifier | phishing scored below 0.5: 7 → 0; still flags the genuine invoice |
| User behaviour | 0.86 → **0.93** with real contact history | legitimate messages scored 0.5+: 3 → 0 |
| Threat intel | 0.50 on this corpus | the intel sources know none of the corpus domains; contributes on known campaigns |
| Sandbox | 0.40 (static fallback only) | not run without a detonation host |

Read with care: the corpus is small and synthetic, the generated organisations reuse its base messages, and the
heuristic was written alongside it. With the new content model the engine's only blind spot on it is a
bank-detail-change request from a real supplier's account (no link, no attachment, a familiar sender); the heuristic
covers it. Next steps: retrain the content model on the client's reported mail once shadow mode has collected it
(the public legitimate mail is old), and recalibrate the attachment model. Real accuracy is measured on the client's
reported mail in shadow mode.

**Tested in the platform** (`test_phishing_engine.py`, 13 tests): every in-platform agent answers inside the real
pipeline; the genuine invoice is safe and phishing still caught with the platform's data; threat intel fed from the
platform; sandbox off without a detonation host; both safeguards; status notes not cited; the behaviour features
use real history, department and arrival time; fallback when the engine fails; the setting.

**Quality:** 205 engine tests. It is lint-clean under the repository's policy (resilience-boundary catch-alls
documented in `pyproject.toml`; silent `pass` handlers replaced with logging). Real bugs fixed during review:
- a warning-banner action that reported success without changing the message (it now tags delivered mail, the only
  change Graph allows)
- an ignored severity filter
- IOC timestamps mislabelled as UTC
- a blocking write inside an async handler
- a leaked file handle

---

## 22. Testing strategy

### 22.1 Layers

| Layer | Where | What it proves |
|---|---|---|
| Unit and workflow | `soc_platform/tests/test_*.py` | Every workflow, rule, formula and API route behaves as specified |
| Consistency | `test_consistency.py` | Same figure on every surface; re-runs change nothing; LLM on/off identical; every GET route × 7 roles; every write route fuzzed; every reference resolves |
| Generalisation | `test_generalisation.py`, `test_variants.py` | Renamed and seeded variant organisations give correct results; no demo names leak |
| Time travel | `test_time.py` | SLAs, budget roll-over, retention with legal hold, risk decay, all consistent as the clock moves |
| Penetration | `test_pentest.py` | 24 attack tests refused (SECURITY.md), incl. round 2: per-role scope, scoped self-approval, proxy-header spoofing, vulnerability-workflow abuse, cross-domain leaks on shared screens, ReDoS |
| Property-based | `test_properties.py` | Redaction, guardrail, timestamps, bounded text, e-mail parser hold for generated inputs |
| Concurrency | `test_scheduler.py`, `test_audit_concurrency.py`, pentest races | No double runs, no forked chain, exactly-once approvals, one case per e-mail |
| Live (opt-in) | `test_live_llm.py`, live feed tests | The real LLM and public feeds |
| Engine | `domains/phishing/tests/` | The ML engine |
| Browser | `scripts/ui_tour/tour.js` | Every screen in a real browser, 4 roles, 2 themes, 4 widths; screen values = API; accessibility; stored XSS |
| Feature map | `scripts/verify_features.py` | 89 features, each mapped to the tests that prove it → FEATURE_VERIFICATION.md |

### 22.2 PostgreSQL parity

- **`SOC_TEST_POSTGRES=<uri>`** runs the whole suite on PostgreSQL. `conftest.py` maps each SQLite URL to a fresh
  database, with `NullPool`. `pgserver` provides an embedded PostgreSQL 16 for machines without one.
- **SQLite runs are held to PostgreSQL's rules.** A `before_flush` listener rejects over-long strings (except
  `BoundedText`) and 32-bit overflow in Integer columns; a cursor listener rejects NUL in query parameters. So the
  fast suite catches production-only bugs.

### 22.3 Test data

- **The built-in estate** ("Acme") comes from `scripts/build_fixtures.py` and `scripts/build_email_corpus.py`.
- **Variant estates** come from `scripts/build_estate_variant.py --seed N [--scale X]`: renamed people, hosts, IP
  plan, suppliers and volumes, with a structurally identical attack. Their own fixtures, settings, suppliers and
  corpus.
- The suite runs on three estates (`demo`, `seed7`, `seed23`).

### 22.4 Isolation

- Tests never write into the project folder (temporary raw and report directories).
- The embedded scheduler is off in tests (`SOC_EMBEDDED_SCHEDULER=0`).
- Fixtures register cleanup before setup, so a failed setup cannot leak its environment into later tests.
- Runs compared figure-for-figure freeze the clock.
- **No test may depend on chance or on machine speed.** Generated sample data is byte-identical for the same seed
  (Message-IDs and MIME boundaries derived from the message; a test builds an organisation twice and compares every
  file) - random IDs once made the auto-close QA sample, keyed on content hashes, change between runs. Parallelism is
  proved by counting calls in flight, never by wall-clock time. Waits for a server or thread have generous deadlines
  (up to 120 s) and end as soon as the condition holds. The timing-sensitive files are checked with every CPU core
  saturated.
- A PostgreSQL run whose `SOC_TEST_POSTGRES` is empty or not a PostgreSQL URL stops with an error; it never falls back
  to SQLite silently.

---

## 23. Code quality tooling

- **ruff** (0.16 default rule set) across the whole repository: **0 findings**. The project policy in
  `pyproject.toml`:
  - FastAPI's `Depends`/`Query`/`File`... are declared immutable calls
  - `B008` is scoped to `api/app.py` for the `need()` permission factory
  - `BLE001` (catch-all) is allowed at documented resilience boundaries (phishing engine, tools, agents,
    connectors); elsewhere each catch-all carries an inline reason
  - silent `try/except: pass` is not allowed anywhere
- **bandit:** 0 medium/high in platform code and scripts.
- **pip-audit and npm audit:** no known vulnerabilities (the PyTorch CPU build can't be audited from PyPI).
- **pyright** (basic mode) over the platform core: findings triaged. The real ones were fixed; the rest are library
  typing limits (SQLAlchemy optional returns, connector duck-typing).
- **Hypothesis** example database and coverage output are gitignored.

---

## 24. Deployment and operations

- **Image** (`deploy/Dockerfile`): a multi-stage build on `python:3.11-slim`; build dependencies only in the builder
  stage; a non-root `soc` user (uid 1001); `HEALTHCHECK` on `/health`; Uvicorn with 2 workers. The ML engine's
  libraries come from the `WITH_PHISHING_ENGINE=true` build argument (scikit-learn, XGBoost, LightGBM, LangGraph; no
  PyTorch); compose sets `SOC_PHISHING_ENGINE=auto`, so an image built with them runs the models and one without uses
  the heuristic. `.dockerignore` keeps secrets, environments and local data out of the build context. Verified on
  Docker: build, start from empty volumes, scheduler-driven first pass, demo figures identical to a laptop (with and
  without the engine), restart persistence, report download with charts.
- **Job order on a first start**: `jobs.JOBS` lists vulnerability first, so when everything is due at once the
  exposure picture exists before incidents are scored; the incident job also reassesses open incidents when KEV-listed
  exposure appears on their hosts later. Evidence is idempotent (same case, source, wording, entity and lookup), so a
  reassessment adds only what is new. Found by the Docker test: scheduled from a fresh start, one incident came out
  medium with no actions instead of high with three.
- **The in-platform engine ignores the developer's `.env`** for behaviour that changes verdicts: local QR/barcode
  decoding is pinned on in `OFFLINE_SETTINGS` (it was on in the laptop's `.env` and off in the container, and one
  e-mail scored 0.82 vs 0.92).
- **Compose** (`deploy/docker-compose.yml`):
  - `postgres`
  - `platform-api` (built-in scheduler off)
  - `platform-scheduler`
  - optional `--profile engine` services: RabbitMQ, Redis, engine agents, sandbox executor. The executor never
    mounts the Docker socket; `docker-compose.dev.yml` does, for local development only.
  - The API binds to 127.0.0.1 by default; expose it through a TLS reverse proxy.
- **Health:** `/health` reports status, version, audit-chain validity, connectors enabled, kill switch and scheduler
  state (unauthenticated, so load balancers can use it).
- **Metrics:** `/metrics` (Prometheus text): open cases by domain and severity, actions by status, open insights by severity, unresolved entities, seconds since each stream's last successful sync, and the kill switch.
- **Backups:** PostgreSQL backups plus the encrypted file store; keep the data keys in the vault separately.
- **Key rotation:** prepend a new `SOC_DATA_KEY`; old keys keep decrypting.

Operations detail: [OPERATIONS.md](OPERATIONS.md).

---

## 25. Decision log

| # | Decision | Alternatives | Why | Consequence |
|---|---|---|---|---|
| 1 | Deterministic scoring; the LLM only narrates | LLM verdicts | Explainability, auditability, reproducibility; no hallucinated numbers; works with the LLM off | More engineering in code; narrative quality depends on the evidence given |
| 2 | Default autonomy L2 (recommend) for every action; promotion per action type through a reviewed policy | Autonomous by default | Requirement NFR-01; trust is earned with shadow-mode evidence | 0 % automation at go-live, by design |
| 3 | One platform, three domains over a shared context store | Three separate tools | Cross-domain correlation (the attack story) needs one entity graph | A larger single service; clear layering keeps it tractable |
| 4 | Connector SDK with a `Transport` abstraction and a fake mode | Vendor SDKs directly; mocks in tests only | The same parsing code for demo, tests and production; demonstrable before tenant access | Fixtures must be maintained vendor-shaped |
| 5 | Entity resolution prefers split + queue over a guess; identities never auto-merged by fuzzy match | Aggressive merging | Wrong merges are unrecoverable and misroute alerts | An unresolved queue for analysts; 7.8 % split rate on assets |
| 6 | SQLAlchemy with PostgreSQL in production, SQLite in dev | PostgreSQL everywhere | Zero-setup demos and fast tests | Engine differences mitigated by PostgreSQL-rules enforcement and a full PostgreSQL run |
| 7 | `BoundedText` for free text, strict `String` for identifiers | Unbounded `Text` everywhere | Width-limited indexes and predictable storage, without production write failures on vendor text | Free text over the width is cut with "…" |
| 8 | Hash-chained, append-only audit; appends serialised by locking a chain-head row before reading the last hash | A plain audit table; a database sequence only | Tamper evidence and a verifiable export; without serialisation, concurrent appends forked the chain (reproduced on both databases) | Appends queue behind each other (microseconds; fine at SOC volumes) |
| 9 | Fernet/MultiFernet for files | Database-level encryption only | Raw e-mails and payloads are the most sensitive data; rotation without re-encryption | Key management in the vault |
| 10 | Conditional updates for state transitions | Application locks | Exactly-once across replicas without distributed locks | - |
| 11 | Scheduler embedded in the API, coordinated by the database: due-ness from job history, an atomic (compare-and-swap) lease per job, a re-check once the lease is held, the lease released only after the run is recorded, and a heartbeat | Separate mandatory process; Celery/Redis; in-memory "last run" | Nothing to forget; no extra infrastructure; restarts and extra schedulers never re-run a job (two races were found and closed by tests) | The API process also runs jobs (turn off with one setting) |
| 12 | Vanilla JS SPA without a build step | React/Vue | Strict CSP, a minimal supply chain, easy to audit | More manual DOM code; no component library |
| 13 | Evidence ids and citation validation for every model output | Trust the model | Grounding is enforceable in code | Some model statements are dropped (the count is shown) |
| 14 | Numeric-fidelity guardrail | Prompt instructions only | Found real stale figures in model output | Occasional false removal of a legitimate figure, erring on the safe side |
| 15 | Circuit breaker and tiered timeouts for the LLM | Plain timeouts | A hung endpoint must not freeze screens | - |
| 16 | Risk as a saturating sum of decayed weights, with standing signals | ML risk model | Every point arguable; tunable in one place | Weights are expert-set, and validated in shadow mode |
| 17 | Idempotency by natural keys everywhere | Exactly-once messaging | Replays, restarts and double clicks are harmless | Unique constraints to maintain |
| 18 | Domain scope answers 404, not 403 | 403 | Hides the existence of records outside scope | - |
| 19 | `create_all` + automatic column addition and widening, no migration framework yet | Alembic from day one | Additive schema evolution covered automatically during build-out | Non-additive changes will need Alembic (§26) |
| 20 | Tests hold SQLite to PostgreSQL's rules and run the suite on PostgreSQL | Separate PostgreSQL CI only | Production-only bugs surface on every developer run | A small listener in the test harness |
| 21 | Parallel vendor I/O in all three modules (syncs, intel feeds, per-analysis lookups), with bounded thread pools; database work stays on one thread in a fixed order | Sequential calls; async/await rewrite | Latency is dominated by vendor round trips (a phishing analysis went from 12.5 s to 2.9 s); threads suit the synchronous connector code and httpx client | More threads per analysis (bounded); results must be merged deterministically |
| 22 | LLM batches in parallel, with the gateway's database use behind a lock | One call at a time; a separate session per thread | Narratives and report sections are independent; a lock keeps the budget check and call log on one session | Throughput is bounded by `SOC_LLM_CONCURRENCY` and the provider's rate limit |
| 23 | The background job prepares the situation brief | Compute on first view only | Nobody waits for the most-viewed LLM output | Prepared per process (with a separate scheduler service, the API's first view still computes it) |
| 24 | Honour a vendor's `Retry-After`, capped at 120 s | Honour it fully; ignore it | Be a good API citizen without letting one answer stall a job for hours | Very long throttles are retried a few times, then reported |
| 25 | Jobs commit a case before asking the model for its explanation; explanations for a batch run in parallel | Narrate inline, case by case | The explanation changes no decision, so nobody should wait for it; a batch is bounded by concurrency, not count | A case briefly shows the deterministic explanation (marked "being prepared") |
| 26 | Notifications from findings, through configured HTTPS webhooks only, deduplicated per channel and severity | A separate alerting subsystem; e-mail; destinations per rule | One path for detection and operational alerts; no SSRF path; no spam from unchanged findings | Channel set is platform-wide (no per-team routing yet) |
| 27 | Case ownership and append-only notes in the platform | Rely on the ITSM ticket for ownership | Analysts triage in the console; ownership must filter the queue; notes must be audit-grade | Two places a case can be discussed when a ticket exists (the ticket link is on the case) |
| 28 | Global search with escaped `LIKE` over names and every tool identifier, scope-filtered per group | A search engine (OpenSearch); full-text indexes | No extra infrastructure; any identifier from any tool finds the entity; scope rules reused | Substring scans; fine to hundreds of thousands of rows, a search index is the next step beyond |
| 30 | The trained ML engine on by default (when installed), fed with the platform's threat intel and mail-flow history, fused with the heuristic; a models-only alarm needs a reliable model to agree | Heuristic only; engine only as delivered | Measured: with the platform's data the engine stopped calling legitimate mail malicious, and the combination got every labelled message right | +1 s per e-mail in the background, ~10 s model load at start; the sandbox agent does not run without a detonation host |
| 31 | Weekly per-plan follow-up, weekly reports as a job, risk register refreshed after every scan | Daily escalations; reports and register on demand only | The client's stated recurring workload; no daily nagging of platform teams | Reports land in Reports every week whether or not anyone reads them |
| 33 | Content model: a compact TF-IDF + logistic-regression classifier trained on public data, replacing a 2-layer BERT | A larger transformer; the LLM as content analyser | Measured far better (hold-out 99 % vs 68 %; corpus 10/12 vs 7/12) at half the size, explainable by its words, no GPU; the LLM would let model output change verdicts (hard rule 7) and fail with the LLM off | Public legitimate mail is old; retrain on the client's mail when available |
| 34 | Offline engine enforced on its live settings (every lookup switch off, every external credential cleared) | Environment variables only | The engine reads the project's .env itself; with import order against it, image attachments went to an Azure OCR service and URLs / hashes to public lookup services | A test blocks all network access and requires zero connection attempts |
| 32 | Azure role assignments read from Azure Resource Manager inside the Entra connector | A separate connector | One identity picture per person (directory roles and Azure roles); ARM has its own token audience through `RoutingTransport` | Needs the Reader role on the subscriptions |
| 29 | Automatic *nullable* column addition at start-up on both engines | Alembic immediately | New optional fields reach existing databases with no manual step | Required columns, renames and drops still need a scripted migration |
| 35 | Per-role data scope: a principal sees the union of its roles' domains, but each permission counts only where the role granting it applies (`Principal.acting_in`); route guards, case writes and `ActionService` decide with the acting principal | One merged scope per principal; separate accounts per scope | Penetration testing found the merged scope let a phishing lead who was also an all-domain auditor approve incident actions | Cross-domain decisions (policy, evidence export, correlated findings) need an all-domain role; `/me` shows `role_scopes` |
| 36 | Every regex over message content is bounded (no unbounded run before a required character; scans stop at the next tag) and tested on 2.4 MB hostile bodies | An HTML parser for extraction; a timeout around analysis | Quadratic patterns let one reported e-mail hold a worker for hours; bounded patterns keep the verdict logic unchanged | Anchor text beyond 5,000 characters and addresses beyond RFC lengths are not matched |
| 37 | Console single sign-on implemented in the console itself (authorization code + PKCE against Entra ID, no library), configured from a public `GET /api/v1/auth/config` | MSAL.js; sign-in at a reverse proxy (Easy Auth / oauth2-proxy) | Keeps the strict CSP (`script-src 'self'`, only `login.microsoftonline.com` added to `connect-src`) and no third-party script; one app registration serves API and console | No silent token refresh: an expired token means one more click on *Sign in with Microsoft* (Entra keeps the session). Exercised end to end only in a real tenant |
| 38 | An organisation's own LLM gateway is reached through settings, not code: auth header and prefix, fixed extra headers, CA bundle, JSON mode off, beta fallback off | A provider per client | Multi-vendor gateways (Claude, Gemini, OpenAI behind one endpoint) mostly speak the OpenAI chat-completions protocol but differ in these details; everything else (redaction, guardrails, budget, breaker) stays in the gateway | Token-per-call (OAuth) gateways or non-OpenAI protocols still need a small provider class (`docs/CLIENT_DEPLOYMENT_GUIDE.md` 5.7) |
| 39 | Connector formats audited against vendors' public references and reference integrations; fixtures regenerated in the real shapes | Trusting the first implementation | The audit found mismatches that would only have shown in a live tenant: HEC events without message fields and per-engine verdicts, Wiz union fields and resource fields, ServiceNow local-time display timestamps, InsightVM fix text and severity words, MDE alert evidence, Graph beta-only sign-in fields | Each connector still needs its first run against the client's tenant |
| 40 | A conformance suite runs every connector through the API behaviour a tenant has and the demo fixtures do not: its vendor's paging, resume, 429, 401, 403, missing / null fields; fixtures can say "answer this way N times" and carry headers | More hand-written demo data | The demo is one tidy scenario; the suite found resume bugs in nine connectors, crashes on missing fields in fourteen, a swallowed timezone offset and Sentinel incidents without entities | Proves behaviour against documented shapes, not the client's: record-and-sanitise (#43) closes that gap during deployment |
| 41 | Event streams resume from a time watermark (newest change seen, minus a 30-minute overlap; future times ignored); inventories are read in full; a continuation token is never kept between syncs; a stream says when it is complete (`Page.reset`) | Keep the last cursor (the previous behaviour) | Continuation tokens expire or point past the end; offsets into moving windows skip or repeat; logs arrive late | Each sync re-reads up to 30 minutes of events (de-duplicated); inventories cost one full read per sync |
| 42 | Ingest is committed per page with one savepoint per page (record-by-record replay only when a page fails, stopped after 20 identical failures) | One transaction per sync with a savepoint per record | A savepoint per record ran PostgreSQL's lock table out on large streams; an uncommitted checkpoint made every interrupted backfill restart from zero; SQLite blocked other writers for the whole sync | A sync is no longer all-or-nothing: what was stored before a failure stays (it is idempotent, so a retry changes nothing) |
| 43 | Record-and-sanitise: live responses written as fixtures with keyed, stable pseudonyms; secrets never recorded; vendor vocabulary kept; a scan report for review | Ask the client for samples by hand | Tests against the tenant's real shapes without tenant access; the same input always maps to the same pseudonym, so cross-references and replay survive | Sanitising is rule-based: a person's name inside free text is redacted wholesale, and the scan plus a human review gate any recording leaving the client |
| 44 | Umbrella stores only security-categorised DNS by default (`dns_sync`) | Every DNS query as a record | Tens of millions of queries a day per tenant; only security-categorised events feed any analysis, and "did anyone reach this site?" asks Umbrella live | `dns_sync: all` for small tenants; if the category list is unreadable, blocked queries only |
| 45 | Entity-resolution candidates retrieved exactly: name near-misses by an indexed range (plus a separator-free name hint that is collation-proof), IP candidates within the window when the record has a name, nameless-record absorption by one query; all candidate data read in three queries | Prefix scan with LIMIT 50; per-candidate queries | A NAT address shared by the fleet and a shared naming prefix made each new host cost a query per known host (1,846 statements per host at 600 hosts) | Identical matching results on the stress estate; near misses beyond 100 lexicographic neighbours under one prefix are not considered |
| 46 | Several server processes (`SOC_API_WORKERS`), a sized and self-checking connection pool, 503 + `Retry-After` when the database is saturated or locked | One process; default pool | Measured: one process queued every request at 43 requests/s; four served 100 analysts at 150 requests/s with no error | Rate limits and caches are per process; put a gateway limit in front for many replicas |
| 47 | The risk ranking is reused while its inputs are unchanged (data fingerprint + a local write counter; 5-minute backstop for other processes) | Recompute per request; persist scores in a job | Risk is a pure function of the data, so reuse is exact; ranking 22,000 entities took 9.4 s per request | The first request after new data pays the full ranking once per process (4.7 s at 22,000 entities) |
| 48 | Outages degrade, never fail: a down feed keeps its last values (KEV never cleared), the reporting mailbox records the outage on its checkpoint and resumes later, live-reading screens and report sections say "unavailable" | Let the job or request fail | One unreachable tool crashed the vulnerability refresh, the phishing job, shadow IT and every report that contained it; an empty KEV answer would have lowered every KEV priority | A section left out of a report is listed with its reason; the report is still produced |
| 49 | CrowdStrike hosts listed through the scroll query; alerts restart from their watermark before offset 10,000 | Offset paging | Falcon refuses offset + limit past 10,000, so a larger fleet or alert backfill stopped with an error | 10,000 alerts sharing one second would still hit the limit (reported as an error, never silently truncated) |
| 50 | Telemetry events (sign-ins, DNS, mail events, secret accesses, elevations) pruned after `SOC_EVENT_RETENTION_DAYS` (400), except those a case, evidence, insight or override refers to | Keep everything; archive to cold storage | A client tenant writes hundreds of thousands of events a day; risk decays them long before 400 days, and the source tools keep their own history | Investigations older than the window rely on the tool's own records (deep links) |
| 51 | A connector that cannot be used is isolated, not fatal | Fail the domain (as before: `ConfigError` out of `action_registry()`) | One missing secret stopped phishing, incident and vulnerability handling and the approvals screen | The isolated tool's data and actions are missing until fixed - shown as "misconfigured" with the reason |
| 52 | Strict configuration schema; start-up refuses file errors | Ignore unknown keys and names | A misspelled tool was ignored and `enabeld: false` left a tool on - silently | A file with errors stops `serve`; `config check` lists every problem first |
| 53 | Connector configuration and the organisation lists (key suppliers, sanctioned services) editable in the console, layered over the files, governed like the autonomy policy (propose, second-person approval, versioned, audited, hot reload) | File edits and a restart; a separate config service | Admins change tools without a deployment, and every change is reviewed and reversible | Secrets stay in the vault/environment (the console only references them); the file remains the deployment-time base |
| 54 | Rollout stages (Fixtures -> Recording -> Read-only -> Recommend -> Automate) with a passing preflight before any live stage | One fake/live switch | A tool is trusted step by step; `recommend` caps every action at L2 whatever the policy says | Promotion is per tool, one proposal per step |
| 55 | Pause takes effect at once without a second approver | Four-eyes for every change | Switching a misbehaving tool off only reduces what the platform does | Audited with a reason; switching it back on needs approval |
| 56 | Connector development kit (scaffold + one-command conformance) | A written guide only | A new connector starts compliant and cannot pass `check` until paging, faults and missing fields behave | The template is a starting point: endpoints and fields must be adapted to the vendor |
| 57 | AI budgets, per-person limits and per-feature tier / answer cap set by administrators in the console (versioned, audited, no restart) | Environment settings only; one monthly cap | A burst could spend the month in a day; one person could starve scheduled work; answer length was bounded only by the prompt | Limits are checked before a call against what was already used, so the call that crosses a limit still completes |
| 58 | Tier advice computed from the call log (usable rate, statements the guardrail removed, answer length), never by a model | Fixed tiers in code; ask a model to judge quality | The guardrail already measures whether a model keeps to the evidence; the same figure on both tiers is a fair comparison | Advice needs 20 calls in the period; it is a recommendation, the administrator decides |
| 59 | One trace id per request / job / CLI command, stored on access-log rows, audit events, model calls and job runs, printed on every log line; a trace view joins them | A tracing system (OpenTelemetry) from day one | Answers "what did this request or job do, and why" from the platform's own records, with no extra infrastructure; the id is compatible with a proxy's `X-Request-ID` | No spans or timings below the request level; the outbound-call log lines give per-call timing |
| 60 | Every successful write request leaves an audit event: a generic `api.<method>` event, in the same transaction, when the route's own code wrote none | Rely on each route remembering | A pushed-alert route had no audit; a route added later cannot forget | The generic event records who, the route and the ids, not a domain-specific description |
| 61 | The evidence check's removals stored per model call, each with its reason | Counts only | "Why is this explanation thin?" is answered by the call itself | Stored with the prompt and answer, so purged with them after `SOC_LLM_LOG_RETENTION_DAYS` |
| 62 | Malformed vendor records are conformed to the stream's documented shape, learned from the connector's fixtures, before parsing; coercions are reported per sync | Fix each parser by hand; reject the record; a hand-written schema per stream | A wrong-type fuzz crashed 715 ways in 26 of 27 streams; one generic layer fixes every connector, including future ones, and the fixtures already are the documented shape | A field the fixtures never contained is passed through unchecked: record-and-sanitise during deployment keeps the fixtures - and so the shapes - true to the tenant |
| 63 | A reported e-mail the parser cannot read reliably is held as suspicious, never safe | Trust the recovered parse | UTF-16 and NUL bytes are filter-evasion tricks; damaged MIME hides parts from the analysis; "safe" on a partial read is the costly error | A few damaged but benign messages reach an analyst |
| 64 | Settings are validated as a whole before start (`settings_check.py`), with a fix per problem and unknown names reported | Read lazily, fail on first use | A typo surfaced as a traceback at start or a crash mid-request, or was silently ignored | The specification lists every setting; a new setting must be added to it (or `config check` warns that it is unknown) |
| 65 | Model JSON read with `model_list` / `model_choice` / `model_ids`; any malformed item is dropped and counted | Validate with a strict schema and reject the whole answer | One odd field should cost that statement, not the answer; the deterministic fallback covers an answer with nothing usable | Statements are dropped silently from the answer, but each removal is counted and stored on the call |
| 66 | Paging by offset (newest first, id tiebreak) for the case and approval lists | Keyset cursors | Lists are browsed a page at a time by people; offset is simple and correct with a total order | Deep offsets are slower; search and filters remain the way to a specific old case |
| 67 | Irreversible action types are marked destructive (mail purge, password reset, secret rotation, confirm-compromised), so the policy never lets them run autonomously | Leave it to the policy document | The policy rule "destructive -> at most L3" existed but no action carried the flag, so a policy raising everything to L4 would have run them unattended - found while writing the client security review | They can still be promoted to L3 (a person approves); a test raises every action to L4 and checks exactly these four still wait |
| 68 | Microsoft app registrations can authenticate with a certificate (RFC 7523 client assertion, `x5t`, 10-minute lifetime) as well as a secret | Secret only | Security reviews commonly require certificate credentials; no shared secret then leaves the platform | The PEM (key + certificate) is one vault-mounted secret, `<CONNECTOR>_CLIENT_CERTIFICATE_FILE` |
| 69 | Internal indicators are never sent to outside threat-intelligence sources: private / reserved addresses, single-label and private-suffix host names, anything under `SOC_ORG_DOMAINS` | Send everything the case names | An incident's internal IP or a link to the organisation's own site would have been disclosed to VirusTotal, Shodan and others, with no reputation to gain | Such an indicator reads "not checked"; the check sits in `ThreatIntelConnector.enrich`, the one path every lookup takes |
---

## 26. Known limitations and trade-offs

- **Not yet run against the client's tenants.** Connectors follow documented APIs and are exercised through fixtures.
- **No schema migration framework.** Additive changes (new tables, new optional columns, wider text) are automatic
  on both engines; required columns, renames and drops need Alembic, which should be introduced before the first
  such change in production.
- **Load at the client's own volume not yet measured.** Measured on generated messy estates up to 21,675 records /
  21,728 entities (cost per record flat as they grow) and with 100 concurrent analysts on one laptop (no error). The
  client's volume, network latency to PostgreSQL and vendor API budgets are measured during deployment with the same
  scripts against the target environment. Ingestion is ORM-bound (about 29 statements per record): around 146
  records/s on SQLite and 75 on a local PostgreSQL; a first backfill of a very large tenant takes hours (it is
  committed per page and resumable). Each new incident's enrichment waits on the tools' request budgets (about 1.5 s).
- **SQLite is for demos and development only.** On SQLite, a job that calls the LLM inside its transaction holds the
  write lock for the call's duration, so a user's write can wait up to the 30 s busy timeout. The incident and
  phishing jobs now commit their cases before the model is asked, which shortens this, but the explanation step
  still writes its call log as it goes. PostgreSQL (row locks) is unaffected; use it for anything beyond a laptop
  demo.
- **The dev sign-in keeps its token in `localStorage`.** That is acceptable in dev behind a strict CSP; production
  uses Entra sign-in (MSAL), where token handling follows Microsoft's guidance.
- **Security testing is internal** (automated pentest, fuzzing, XSS probe). An independent third-party test is still
  needed before go-live.
- **Accessibility is automated** (axe-core); a manual screen-reader review has not been done.
- **Latency depends on the client's APIs.** The measurements in §16.1 assume 400 ms per vendor call; real tenants
  can be slower (large advanced-hunting queries in particular). Enrichment has a 20 s deadline per source, so a slow
  tool delays one case by at most that and is then reported as unavailable.
- **Notifications are platform-wide:** one threshold and one set of channels; no per-team or per-domain routing
  and no quiet hours yet.
- **Search is substring matching**, not ranked full-text; results are ordered by recency (priority for
  vulnerabilities).
- **Other LLM providers:** only Azure AI Foundry is verified live.
- **The detonation host** is not run in the demo; its hardening is unit-tested.
- **The optional ML engine** is an earlier code base: tested and lint-clean, but not reviewed line by line like the
  platform core.
- **No per-person erasure.** Retention and legal hold exist, but a data-subject erasure request (remove one person's
  data everywhere) has no tool. The audit log is append-only and hash-chained, so erasure there needs a design - for
  example pseudonymising the person in place with a recorded, chained event - agreed with the client's data-protection
  officer.
- **Request rate limits and tool budgets are per process.** The API's per-client limit (20/s, burst 120) is held in
  each server process, so with N workers a client may reach N times it; tool budgets are divided by
  `SOC_CONNECTOR_RATE_SHARE`. A shared limiter (Redis, or the database) would make both exact; put the API's
  limit on the reverse proxy for a hard ceiling (OPERATIONS.md, "Network edge").
- **Backup and restore have not been rehearsed.** The procedure is documented (OPERATIONS.md); a restore drill on the
  target environment, with the audit chain verified afterwards, belongs in the go-live checklist.

---

## 27. Glossary

| Term | Meaning |
|---|---|
| Canonical schema | The tool-independent record format every connector normalises to (`NormalizedRecord`) |
| Context store | The shared entity/event graph built from every tool |
| Entity resolution | Deciding that records from different tools describe the same host or person |
| Evidence ids | E# (case evidence), S#/G#/H#/B#/P#/X# (story), F# (report figures), R# (analyst tool results) |
| Fake mode | A connector reading vendor-shaped fixtures through the same code as live mode |
| Idempotency key | A hash of an action's type, params, targets and case that makes repeated requests return the same request |
| Lease | A time-limited database claim that stops a job running twice at once |
| Standing signal | A risk signal describing a condition still true (open exposure/incident) that does not decay |
| Four-eyes | A second, suitably senior person must approve |
| L0-L4 | Autonomy levels: observe, enrich, recommend, approve, autonomous |
| Blind spot | An ATT&CK stage no enabled tool can observe |
| Shadow mode | System verdicts compared with analyst decisions before any automation |
| Fingerprint | A hash of a story's evidence; the same attack gives the same story and cached deep analysis |
| Legal hold | Raw data of open cases exempt from retention |
| PSI | Population stability index, used to detect verdict-mix drift |
| WAL | SQLite write-ahead logging: readers are not blocked by a writer |
