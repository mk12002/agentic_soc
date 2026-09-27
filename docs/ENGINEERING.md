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
21. [The optional phishing ML engine](#21-the-optional-phishing-ml-engine)
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
  __main__.py            CLI: init-db, demo, serve, scheduler, token, fixtures
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
| `health()` | Used by *Test* on the Integrations screen |

### 5.2 Rate limits and retries

- **`TokenBucket(rate_per_sec, burst)`** per connector (default 5/s, burst 10; tuned per tool under each vendor's
  documented limits, for example 50/s for threat-intel fusion). Every outbound call is wrapped by
  `connector.call()`, which acquires a token.
- **`with_backoff`** retries up to 5 times:
  - on `TransientError` (network errors and 5xx): exponential backoff (0.5 s × 2ⁿ, capped at 30 s) with jitter
  - on `RateLimited` (429): the vendor's `Retry-After` is honoured, capped at `MAX_RETRY_AFTER` = 120 s, so one
    answer can never stall a job for hours

  After that it raises `ConnectorError`. 4xx other than 429 is not retried (it will not get better).

### 5.3 Transports and authentication (`connectors/http.py`)

Connectors talk to a `Transport` protocol, never to httpx directly. That is what makes fake and live modes run the
same code:
- **`HttpTransport`:** base URL, auth strategy, timeout (30 s), TLS verification, error mapping
  (429 → `RateLimited`, 5xx and transport errors → `TransientError`, other 4xx → `ConnectorError`).
- **`FixtureTransport`:** routes loaded from `fixtures/<tool>.json`. Each route matches method, path regex, listed
  parameters (only the listed ones; `~` means regex, `*` means any value) and optional body substrings. Routes can
  answer any status, including 429 to exercise backoff, and can select fields from the request.
- **`RoutingTransport`:** several upstreams behind one connector (threat-intel fusion).
- **Auth strategies:**
  - `NoAuth`
  - `ApiKeyHeader`
  - `ApiKeyQuery`
  - `BasicAuth`
  - `OAuth2ClientCredentials`, with token caching and refresh (form or JSON body; `entra_app_auth()` for Microsoft
    tenants)

### 5.4 Sync runner (`SyncRunner.sync`)

- **Incremental.** It resumes from the stored cursor (`ConnectorCheckpoint`) and checkpoints after **every page**, so
  an interrupted backfill resumes rather than restarts. `full_backfill=True` starts from scratch.
- **Per-record fault isolation.** Each record is normalised and ingested inside a savepoint (`begin_nested`). One bad
  record is counted and logged; the rest of the page continues.
- **Reconciliation.** Source records, ingested and failed counts are accumulated on the checkpoint. Where the tool
  reports a total, `SyncReport.reconciled` compares them.
- **Freshness.** `last_success_at` per stream is compared with the stream's expected cadence for the Integrations
  screen (fresh/stale/error).

### 5.5 Registry (`connectors/registry.py`)

- **Discovery.** Every module in `connectors/tools` that exports `MANIFEST`/`MANIFESTS`, plus any installed package
  exposing the `soc_platform.connectors` entry-point group. A third-party connector needs no platform change.
- **`ConnectorManifest`:** name, kind, config fields (secret flags), factory, fake settings, fixture file, action
  factory.
- **Configuration.** `config/connectors.yaml` sets enabled, mode (`fake`/`live`) and settings per tool, with
  `${ENV}` substitution; secrets can come from `<NAME>_FILE`. `SOC_CONNECTOR_MODE` sets the default mode.
  `SOC_FIXTURES_DIR` points fake mode at another estate, which may carry `fixtures/settings.json` for its
  tenant-specific settings.
- **`ConnectorRegistry`:** instantiation, `enabled_names()`, `get(name)`, and `action_registry()` (collects every
  connector's actions into one `ActionRegistry`).

### 5.6 The 20 connectors

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

### 8.1 Tables (35)

| Area | Tables |
|---|---|
| Context store | `entities`, `entity_keys`, `entity_hints`, `source_records`, `relations`, `evidence` |
| Resolution | `resolution_overrides`, `unresolved_items` |
| Cases | `cases`, `case_entities`, `dispositions` |
| Actions and policy | `action_requests`, `policy_versions` |
| Governance | `audit_log`, `llm_calls`, `access_log`, `role_assignments`, `api_keys`, `token_revocations`, `system_flags` |
| Operations | `connector_checkpoints`, `enrichment_cache`, `job_runs` |
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
- **Exactly-once state transitions use conditional updates:** `UPDATE action_requests SET status=… WHERE id=… AND
  status IN (approvable)` and check `rowcount`. Six simultaneous approvals of one action execute it exactly once
  (tested).

### 8.4 Schema management

- `Database.create_all()` creates missing tables.
- On PostgreSQL, `_widen_columns()` then compares every VARCHAR column's length with the model and widens columns
  the model has made longer. That is always safe and loses no data. **Nothing is ever narrowed or dropped
  automatically.**
- There is no migration framework yet (see §26). Additive changes (new tables, wider columns) are handled
  automatically; anything else needs a scripted migration.

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

   `EngineAnalyzer` runs the optional 7-agent ML swarm in-process instead (`SOC_PHISHING_ENGINE=1`).
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
5. **Follow-up (daily):** chase plans unacknowledged after 3 days; two-way ticket sync. A ticket marked done while a
   scanner still sees the vulnerability is a **false closure**, reopened and counted.
6. **Validation:** re-query each scanner. The result per source is `still_present` / `not_present` /
   `unverifiable: <error>`, and a fix is never accepted on an unverifiable answer.
7. **Exceptions and risk register.** An exception needs a justification, a compensating control and an expiry, and
   is approved by a different person; expiry reopens the finding. Past-SLA findings are proposed for the register.
8. **Cloud misconfigurations** (`misconfig.py`): Wiz issues consolidated per (resource × rule), owner by CMDB or
   subscription, SLA by severity (tightened for toxic combinations on internet-exposed resources), routed, then
   fixed and validated against Wiz.
9. **Natural-language query:** keyword-to-filter mapping (status, priority, KEV, internet exposure, CVE, asset,
   team). The generated filter is shown with the answer. It is never SQL.

---

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
9. **Budget.** Monthly token budget (default 50 M); `BudgetExceeded` above it. Findings at 80 % and 100 % come from
   the self-check job.
10. **Logging.** Every call goes to `llm_calls`: workflow, provider, model, tokens, status, grounded flag, redacted
    prompt and response. The text is purged after `SOC_LLM_LOG_RETENTION_DAYS`; token counts are kept.

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
  - The audit log, access log and reports are scoped too. Cross-domain views (intelligence, brief) need all-domain
    scope.
  - Tested for every id route with a phishing-only user.
- **Separation of duties:** nobody approves their own action, policy, exception or access grant; the proposer of a
  policy cannot approve it.

### 13.3 Web and input hardening

- **Headers on every response:**
  - `Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src
    'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'`
  - `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`,
    `Cross-Origin-Opener-Policy: same-origin`, `Permissions-Policy`, `Cache-Control: no-store`
  - HSTS on HTTPS
- **No CORS grants.** The console is same-origin.
- **Limits:**
  - body size 30 MB, enforced on the byte stream (chunked uploads without Content-Length too)
  - per-client token bucket (20/s, burst 120; `X-Forwarded-For` honoured only from `SOC_TRUSTED_PROXIES`)
- **Input handling:**
  - NUL in path or query is refused (400)
  - database `DataError` → 400, never 500
  - Pydantic validation on bodies
  - query parameters bounded (`Query(le=…)`, patterns)
- **Output escaping in the console:** every interpolated value goes through `esc()`. Clicks are dispatched only to
  an allow-list (`ALLOWED`) of functions via `data-fn`, never `eval` or inline handlers. The stored-XSS probe (8
  screens, CSP disabled) executed nothing.
- **No SSRF surface.** No code path fetches URLs taken from e-mail content; outbound calls go only to configured
  vendor endpoints. The unwired visual-URL scaffold returns "unavailable" instead of a made-up verdict.
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

Eight jobs:

| Job | Default interval |
|---|---|
| phishing | 2 min |
| incident | 5 min |
| intelligence | 10 min |
| self_check | 1 h |
| vulnerability | 6 h |
| follow_up | 1 day |
| daily_report | 1 day |
| retention | 1 day |

Intervals are set by `SOC_JOB_*_SECONDS`.

`run_job(name)`:
1. **Lease:** `system_flags[job_lease:<name>]` with holder = `hostname:pid:thread-id` and a 30-minute expiry. If
   another holder has a live lease, skip.
2. **Check again once the lease is held** (`still_due`). If someone ran the job between the due check and the lease,
   skip.
3. **Run** the body in its own session, retrying up to 3 attempts with exponential backoff (2ⁿ s, capped at 60 s).
4. **Record** a `JobRun` (start, end, attempts, status, error, JSON summary, strictly increasing ordinal).
   `dead_letter` after 3 failing runs in a row raises a `job_dead_letter` insight. It keeps being attempted on
   schedule, so it recovers on its own.
5. **Release** the lease. This happens **after** the record is written; releasing before it let a second scheduler
   run the job again, which a race test found.

### 14.2 Scheduler (`scheduler.py`)

- **Embedded by default:** the API's lifespan starts it (`SOC_EMBEDDED_SCHEDULER=1`) and stops it on shutdown. One
  process is the whole platform. `python -m soc_platform scheduler` runs the same code standalone.
- **The database decides what is due:** a job is due when no run of it, by anyone, started within its interval. A
  restart does not re-run everything, and extra schedulers do not double-run.
- **Threads:** a supervisor restarts the heartbeat and job threads if either stops. The job loop catches every
  exception per pass. Retry backoff waits on the stop event, so shutdown is prompt.
- **Heartbeat:** `system_flags[scheduler:<sha256(holder)[:24]>]` records the holder, mode and `at` (every 30 s from
  a separate thread), plus `loop_at` and the current job from the loop. The key is hashed because the flag key column
  is 64 characters. Rows gone for a day are pruned.
- **`status()`** for `/health`:
  - `running`
  - `stuck`: alive, but a job has run past its lease (30 min)
  - `stale`: no heartbeat for `SOC_SCHEDULER_STALE_SECONDS`, default 180 s
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
| Risk ranking | `candidates()` pre-filter | 20,000 entities: ~16 s → 0.06 s |
| Correlation | runs over risk candidates only | 36.5 s → 0.09 s |
| A case's shared actions | database-side `LIKE` narrowing on the JSON result before the Python check | 20,000 actions: 0.47 s → 0.005 s |
| Situation brief | cached by facts fingerprint (15 min) | one model call per change, however many viewers |
| Enrichment | parallel lookups (16 workers), 30-minute cache | bounded by the slowest source, capped at 20 s |
| Access log | batched background writes (up to 500 rows per batch) | no per-request write latency |
| Finding narratives | rewritten only when evidence or severity changes | token saving (LLM_TOKENS_AND_COST.md) |

The API is stateless and scales horizontally. The scheduler coordinates through the database. It has not been
load-tested at client volume (§26).

### 16.1 Latency: measured end to end

Measured on a laptop with every vendor API call delayed **400 ms**, which is typical for Microsoft Graph,
CrowdStrike and similar SaaS APIs, and with the real LLM (Azure AI Foundry, gpt-4.1-mini). Figures are for one item
on the built-in estate. The script is the one used for §12.3; the vendor-call counts let you rescale to other API
speeds.

| Step | Who waits | Vendor calls | Without LLM | With LLM |
|---|---|---|---|---|
| Analyse a reported phishing e-mail (campaign, clicks, impact) | nobody (background) - sets time to case | 31 | **2.9 s** (was 12.5 s) | 9-12 s (the model writes the explanation) |
| Analyse a benign e-mail (auto-closed) | nobody | 20 | **1.2 s** (was 8.1 s) | 1.2 s (no model call) |
| Investigate an incident (enrichment across tools) | nobody | 92 | **1.8 s** | 8-16 s (the model's response time varies) |
| Vulnerability refresh (4 scanners + feeds) | nobody (every 6 h) | 32 | 13 s | 13 s |
| Re-correlate (risk, 12 rules, narratives) | nobody (every 10 min) | 0 | 0.1 s | 19 s first time (was 67 s); 0.1 s when nothing changed |
| Open a case, story, 360 view or list | analyst | 0 | < 0.1 s | < 0.1 s (results are stored) |
| Situation brief | analyst | 0 | < 0.1 s | 0 s when prepared by the job; ~6 s if not yet prepared |
| Analyst question | analyst | 0 | < 0.1 s | ~6-7 s |
| Deep analysis | analyst (on request) | 0 | - | ~14 s once, then instant (cached) |
| Report (CISO weekly, all sections) | analyst | 0 | 0.2 s | ~7 s (was 22 s) |

**Time from a user pressing *Report* to a case on screen** = up to the phishing job interval (default 2 minutes;
lower `SOC_JOB_PHISHING_SECONDS` for faster pickup) + the analysis above. Uploads through the console are analysed
immediately.

### 16.2 How the latency was brought down

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
- **Parallel LLM batches** and the prepared brief (§12.3, §10.5).
- **A regression test** (`test_phishing_analysis_asks_the_tools_in_parallel`) fails if an analysis takes more than
  half the time its vendor calls would take one after another.

---

## 17. API design

- **REST under `/api/v1`**, JSON, grouped by domain:
  - `/cases`, `/actions`, `/phishing`, `/incidents`, `/vm`, `/intelligence`, `/reports`, `/admin`, `/audit`,
    `/jobs`, `/connectors`, `/dashboard`, `/entities`, `/resolution`, `/policy`, `/kill-switch`, `/llm`,
    `/ingest/alerts`
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
- **Connectors:** `config/connectors.yaml`. **Suppliers:** `config/suppliers.yaml` (or `SOC_SUPPLIER_DOMAINS`).
  **Sanctioned services:** `config/sanctioned_services.yaml`. **Organisation domains:** `SOC_ORG_DOMAINS`.
- The full list of settings is in [OPERATIONS.md](OPERATIONS.md). Every setting in production documentation is also
  in `deploy/docker-compose.yml`.

---

## 21. The optional phishing ML engine

`soc_platform/domains/phishing/engine/` is an earlier, self-contained phishing analysis system, integrated as an
optional backend:
- a seven-agent swarm: header, content NLP, URL, attachment/OCR, sandbox, threat intel, user behaviour
- a LangGraph decision graph, a counterfactual engine, MITRE mapping
- RabbitMQ workers, Redis caching
- a sandbox executor for detonation on an isolated host
- models verified by SHA-256 manifest before loading

**Integration:**
- `EngineAnalyzer` runs the swarm in-process when `SOC_PHISHING_ENGINE=1`. The engine's own persistence, actions and
  the retired "Garuda" hop are disabled.
- The platform's action layer, policy, audit and impact agents replace them.
- The heuristic analyser remains the default and a second opinion.

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
| Penetration | `test_pentest.py` | 17 attack groups refused (SECURITY.md) |
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
  stage; a non-root `soc` user (uid 1001); `HEALTHCHECK` on `/health`; Uvicorn with 2 workers. The optional ML
  engine comes from the `WITH_PHISHING_ENGINE=true` build argument (installs CPU PyTorch).
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
| 11 | Scheduler embedded in the API, coordinated by the database: due-ness from job history, a lease per job, a re-check once the lease is held, the lease released only after the run is recorded, and a heartbeat | Separate mandatory process; Celery/Redis; in-memory "last run" | Nothing to forget; no extra infrastructure; restarts and extra schedulers never re-run a job (two races were found and closed by tests) | The API process also runs jobs (turn off with one setting) |
| 12 | Vanilla JS SPA without a build step | React/Vue | Strict CSP, a minimal supply chain, easy to audit | More manual DOM code; no component library |
| 13 | Evidence ids and citation validation for every model output | Trust the model | Grounding is enforceable in code | Some model statements are dropped (the count is shown) |
| 14 | Numeric-fidelity guardrail | Prompt instructions only | Found real stale figures in model output | Occasional false removal of a legitimate figure, erring on the safe side |
| 15 | Circuit breaker and tiered timeouts for the LLM | Plain timeouts | A hung endpoint must not freeze screens | - |
| 16 | Risk as a saturating sum of decayed weights, with standing signals | ML risk model | Every point arguable; tunable in one place | Weights are expert-set, and validated in shadow mode |
| 17 | Idempotency by natural keys everywhere | Exactly-once messaging | Replays, restarts and double clicks are harmless | Unique constraints to maintain |
| 18 | Domain scope answers 404, not 403 | 403 | Hides the existence of records outside scope | - |
| 19 | `create_all` + automatic widening, no migration framework yet | Alembic from day one | Additive schema evolution covered automatically during build-out | Non-additive changes will need Alembic (§26) |
| 20 | Tests hold SQLite to PostgreSQL's rules and run the suite on PostgreSQL | Separate PostgreSQL CI only | Production-only bugs surface on every developer run | A small listener in the test harness |
| 21 | Parallel vendor lookups inside one analysis, with bounded thread pools and a fixed merge order | Sequential calls; async/await rewrite | Latency is dominated by vendor round trips (a phishing analysis went from 12.5 s to 2.9 s); threads suit the synchronous connector code and httpx client | More threads per analysis (bounded); results must be merged deterministically |
| 22 | LLM batches in parallel, with the gateway's database use behind a lock | One call at a time; a separate session per thread | Narratives and report sections are independent; a lock keeps the budget check and call log on one session | Throughput is bounded by `SOC_LLM_CONCURRENCY` and the provider's rate limit |
| 23 | The background job prepares the situation brief | Compute on first view only | Nobody waits for the most-viewed LLM output | Prepared per process (with a separate scheduler service, the API's first view still computes it) |
| 24 | Honour a vendor's `Retry-After`, capped at 120 s | Honour it fully; ignore it | Be a good API citizen without letting one answer stall a job for hours | Very long throttles are retried a few times, then reported |

---

## 26. Known limitations and trade-offs

- **Not yet run against the client's tenants.** Connectors follow documented APIs and are exercised through fixtures.
- **No schema migration framework.** Additive changes are automatic; renames and drops need Alembic, which should be
  introduced before the first non-additive change in production.
- **Load at client volume untested.** Scale benchmarks go to 20,000 entities and actions.
- **SQLite is for demos and development only.** On SQLite, a job that calls the LLM inside its transaction holds the
  write lock for the call's duration, so a user's write can wait up to the 30 s busy timeout. PostgreSQL (row
  locks) is unaffected; use it for anything beyond a laptop demo.
- **The dev sign-in keeps its token in `localStorage`.** That is acceptable in dev behind a strict CSP; production
  uses Entra sign-in (MSAL), where token handling follows Microsoft's guidance.
- **Security testing is internal** (automated pentest, fuzzing, XSS probe). An independent third-party test is still
  needed before go-live.
- **Accessibility is automated** (axe-core); a manual screen-reader review has not been done.
- **Latency depends on the client's APIs.** The measurements in §16.1 assume 400 ms per vendor call; real tenants
  can be slower (large advanced-hunting queries in particular). Enrichment has a 20 s deadline per source, so a slow
  tool delays one case by at most that and is then reported as unavailable.
- **LLM call durations are not stored** in the call log (only tokens and status); they are measured by the latency
  script. Adding a duration column is a schema change for a future release.
- **Other LLM providers:** only Azure AI Foundry is verified live.
- **The detonation host** is not run in the demo; its hardening is unit-tested.
- **The optional ML engine** is an earlier code base: tested and lint-clean, but not reviewed line by line like the
  platform core.

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
