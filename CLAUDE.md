# CLAUDE.md - working on the Agentic SOC platform

Context for anyone (human or AI) changing this repository. Read the **Hard rules** first: they are not negotiable.
Deep detail lives in `docs/`; this file tells you what the project is, how it is put together, how to run and test
it, the conventions the code relies on, and the traps that have already cost time.

---

## 1. Hard rules

1. **Never write the client's name or its abbreviations** (the real client is anonymised) anywhere in the repo: code,
   docs, file names, commit messages, test data. The demo organisation is **Acme** (`acme-demo.com`); variant
   estates are generated names (Veridian Foods, Tidewell Insurance...). Before every push, scan tracked files for the
   banned names.
2. **Never commit secrets.** `.env` (holds the Azure AI Foundry key as `SOC_LLM_*`, plus engine keys) is gitignored;
   never print its values. Before every push, check that no `.env` secret value appears in any tracked or staged
   file (§9 has the snippet). Also keep out: `gdrive_credentials.json`, anything under `test_reports/private/` (real
   inbox exports), the internal requirements `.docx` at the repo root, `*.db`, `data/`, `logs/`.
3. **The user commits mid-task.** Before committing, run `git log --oneline -5` and `git status`; if there are new
   commits you did not make, scan them for secrets and banned names, and build on them.
4. **Commit attribution:** end commit messages with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.
   Commit or push only when asked.
5. **Kill processes only by specific PID** (found via `netstat -ano | findstr :<port>` or the command line), never by
   name - other Python processes on this machine belong to the user.
6. **Do not reproduce detailed attack tradecraft** in test data or docs. Sample data stays at alert-title level
   (e.g. "Suspicious PowerShell download"), never step-by-step techniques.
7. **The LLM never produces a figure, verdict, score or decision.** Everything numeric or decisional is computed in
   code; the model only writes narrative from evidence it is handed, and must cite it. Do not add features that let
   model output change a number, a verdict or an action.
8. **Nothing executes without approval by default.** Every write to a security tool is an `ActionRequest` through
   `ActionService` and the autonomy policy (default L2 = recommend). Never call a connector's write method directly
   from a domain or the API.
9. **Keep docs true.** When behaviour, numbers, settings or test counts change, update the affected docs in the same
   change (see §8 for which doc owns what). Never write a number in a doc you have not measured or read from code.

---

## 2. What this project is

An **agentic SOC platform**: one investigation and automation layer over an organisation's existing security tools.

- **20 connectors** pull from EDR (CrowdStrike, Defender for Endpoint), e-mail security (Defender for Office 365,
  Avanan), identity (Entra ID), DNS (Umbrella), deception (Canary), PAM (Delinea Secret Server / Privilege Manager),
  vulnerability scanners (Rapid7, Wiz, plus Spotlight/TVM via the EDRs), public intel (NVD, EPSS, CISA KEV),
  threat-intel fusion (8 sources), ITSM/CMDB (ServiceNow, Jira, CSV) and SIEM (Sentinel, generic webhook).
- Records from every tool are **resolved to one host / one person** (entity resolution) in a shared context store.
- **Three workflow domains** run on that picture:
  - **Phishing** - user-reported e-mail → verdict → campaign scope → who clicked → endpoint/identity impact → remediation.
  - **Incident** - alerts → clusters → parallel enrichment → deterministic severity → MITRE → recommended actions.
  - **Vulnerability** - 4 scanners → one finding per host+CVE → priority (CVSS/EPSS/KEV/exposure/criticality) →
    owner → campaign → validated fix; cloud misconfigurations share the lifecycle.
- An **intelligence layer** correlates across domains: explainable risk per user/host, 12 correlation rules, the
  **attack story** (cross-tool kill-chain reconstruction), optional LLM deep analysis, analyst Q&A, situation brief,
  ATT&CK coverage, shadow IT, drift monitoring, and a report builder (Word/PowerPoint).
- **Governance**: RBAC + domain scope + step-up MFA, four-eyes, versioned autonomy policy, durable kill switch,
  hash-chained audit log, encryption at rest, retention with legal hold, self-check.
- **Teamwork and alerting**: case owner (take / assign), append-only analyst notes, global search over cases, every
  tool identifier, findings and CVEs, and Teams / Slack / webhook notifications for findings above a threshold.
- Every connector has **fake mode** (vendor-shaped fixtures through the same parsing code) so the whole platform runs
  and demos with no tenant access.
- **Phishing ML engine** (`soc_platform/domains/phishing/engine/`, ~24k lines, earlier code base): 7-agent ML swarm
  (a trained model per e-mail component, `artifacts/phishing/models/`) + LangGraph. **On by default when installed**
  (`SOC_PHISHING_ENGINE=auto`), fused with the heuristic analyser (`CompositeAnalyzer.fuse`). The content model is a
  TF-IDF classifier trained on public data (`scripts/train_content_model.py`; attribution in README). The engine is
  strictly offline in-platform (`EngineAnalyzer.enforce_offline`): never add a code path that lets it call out. The test suite pins it
  off (conftest) except `test_phishing_engine.py`. scikit-learn is pinned to 1.8 (the models' version).

Scale: ~16.8k lines platform Python, ~5.6k lines platform tests, ~0.9k lines of vanilla JS UI.

---

## 3. Commands

This is a **Windows** machine. The Bash tool runs Git Bash; PowerShell 5.1 is also available. Use the venv
interpreter: `.venv/Scripts/python` (bash) or `.\.venv\Scripts\python` (PowerShell). The platform reads settings
**only from the environment** - `.env` is not auto-loaded (`. .\scripts\load_env.ps1` loads it into a PowerShell
session; `verify_features.py` reads the `SOC_LLM_*` lines itself).

```bash
# run
python -m soc_platform init-db                 # create tables (idempotent)
python -m soc_platform demo                    # sample org: 7 phishing + 3 incident cases, 34 approvals, 6 open vulns (same with or without the ML engine)
python -m soc_platform reset-demo [--yes]      # server stopped: wipe the demo DB + raw/report files, then init-db + demo
python -m soc_platform serve                   # API + console + built-in scheduler on 127.0.0.1:8080 (SOC_PORT/SOC_HOST)
python -m soc_platform scheduler [--once]      # optional separate scheduler service
python -m soc_platform token lena@acme-demo.com lead   # dev token (needs SOC_DEV_JWT_SECRET)
# minimum env for a local run: SOC_DEV_JWT_SECRET=<long random>, SOC_ORG_DOMAINS=acme-demo.com

# tests (full suite ~17 min SQLite, ~23 min PostgreSQL; run the relevant files first)
python -m pytest soc_platform/tests -q -p no:cacheprovider
python -m pytest soc_platform/tests/test_phishing.py -q -p no:cacheprovider -k <name>
SOC_TEST_POSTGRES=<postgresql://...> python -m pytest soc_platform/tests -q -p no:cacheprovider   # same suite on PostgreSQL
python -m pytest soc_platform/domains/phishing/tests/unit soc_platform/domains/phishing/tests/integration -q   # ML engine (~5 min)
SOC_LIVE_LLM=1 python -m pytest soc_platform/tests/test_live_llm.py      # real LLM (costs cents)
SOC_LIVE_TESTS=1 python -m pytest soc_platform/tests/test_live_public_feeds.py   # real NVD / EPSS / CISA KEV

# verification report (writes docs/FEATURE_VERIFICATION.md)
python scripts/verify_features.py                                 # tests mapped to 103 features
python scripts/verify_features.py --browser --engine --live --llm # + browser tour, engine, live feeds, real LLM (~25 min)

# quality gates (all must be clean before a commit)
.venv/Scripts/ruff check . --exclude .venv,node_modules
.venv/Scripts/bandit -r soc_platform scripts -ll -x "soc_platform/tests,scripts/ui_tour/node_modules,soc_platform/domains/phishing/tests"
.venv/Scripts/python -m pip_audit
```

**Embedded PostgreSQL for tests** (no server needed):
`python -c "import pgserver; print(pgserver.get_server('D:/pgtest_soc', cleanup_mode=None).get_uri())"` → use the
printed URI as `SOC_TEST_POSTGRES`.

**Running two full suites at once**: give each its own `--basetemp=<dir>`; otherwise they share pytest's numbered
temp folders and the variant-estate builders overwrite each other (seen as "demo names leaked" failures).

**Other scripts** (`scripts/`): `build_fixtures.py` + `fixture_builders.py` (regenerate fake-mode fixtures),
`build_email_corpus.py` (labelled `.eml` corpus), `build_estate_variant.py OUT --seed N [--scale X]` (a different
organisation: fixtures, settings, suppliers, corpus, `estate.json`), `rename_estate.py`, `eval_phishing.py`,
`eval_identity_resolution.py`, `eval_resolution_at_scale.py`, `measure_llm_usage.py` (token/cost measurement),
`build_connector_docs.py`, `ui_tour/tour.js` (Playwright browser tour: layout at 4 widths, axe-core accessibility,
stored-XSS probe, screen-vs-API cross-check; needs Node + installed Chrome/Edge), `load_env.ps1`.

---

## 4. Architecture map (where things live)

```text
soc_platform/
  __main__.py            CLI (init-db, demo, serve, scheduler, token, fixtures)
  config.py              Settings from SOC_* env vars; secret() also reads <NAME>_FILE
  jobs.py                JOBS registry + run_job: lease -> re-check due -> run w/ retries -> record -> release
  scheduler.py           Scheduler (embedded in serve by default), heartbeat, status() for /health
  api/app.py             FastAPI: middleware (body cap, NUL/rate limit, headers, access log), auth deps, ALL routes
  api/dashboards.py      read models: overview, ATT&CK coverage, shadow IT, Prometheus text
  api/static/            index.html, app.js (shell/router/auth/click delegation), views.js (screens), theme.js, styles.css
  connectors/base.py     BaseConnector, TokenBucket, with_backoff, SyncRunner (sync, sync_many), Page, LookupResult
  connectors/http.py     Transport protocol, HttpTransport, FixtureTransport (fake mode), auth strategies
  connectors/registry.py discovery (tools/*.py MANIFEST or entry points), config/connectors.yaml, ConnectorRegistry
  connectors/tools/      one module per tool; _common.py (ToolConnector, parse_ts, ok_lookup), _microsoft.py (Graph/OData)
  core/schema.py         NormalizedRecord / EntityRef - the canonical schema every connector emits
  core/models.py         core ORM tables; utcnow() (THE clock); new_id() (uuid4 hex)
  core/db.py             Database, sessions, UTCDateTime, BoundedText, NUL stripping, SQLite pragmas, add missing
                         nullable columns (both engines), PG column widening
  core/context_store.py  ingest(), neighbours, timelines, keys_of
  core/entity_resolution.py  deterministic keys -> scored fuzzy (0.85 auto, 0.1 margin, 0.55 review) -> queue
  core/identity.py       user_ref(): cross-tool user naming -> upn/sam keys; built-in accounts are not people
  core/cases.py          CaseService: cases, evidence, recommendations, decisions, actions_for_case, assign/add_note,
                         deferred narration (narration_request / pending_narration / narrate_pending)
  core/enrichment.py     EnrichmentOrchestrator: parallel lookups (16 workers, 20 s deadline, 30 min cache)
  core/actions.py        ActionSpec/Registry/Service - the ONLY execution path; idempotency keys; conditional updates
  core/policy.py         L0-L4 levels, PolicyEngine.decide(), PolicyStore (propose/approve), DEFAULT_POLICY
  core/auth.py           roles/permissions, token validation (Entra RS256 / dev HS256, exp+iat required), dev tokens
  core/access.py         role grants, API keys, revocation, break-glass, kill switch
  core/audit.py          hash-chained append-only audit; _lock_chain serialises appends
  core/crypto.py         Fernet/MultiFernet, write_protected (atomic, 0600, Windows replace retry), read_protected
  core/retention.py      retention + legal hold;  core/selfcheck.py  cross-surface consistency proof
  core/notify.py         Notification table + Teams/Slack/JSON webhook delivery (notify job); HTTPS-only config
  domains/phishing/      service.py (pipeline), models.py, supplier.py, agents/{decompose,analyzer,investigation}.py, engine/
  domains/incident/service.py
  domains/vulnerability/ service.py, misconfig.py, models.py
  intelligence/          risk.py, correlation.py, story.py, deep_analysis.py, analyst.py, attack_coverage.py, shadow_it.py, drift.py
  llm/gateway.py         LLMGateway, providers, grounding, numeric guardrail, breaker, timeouts, budget, llm_concurrency()
  llm/redaction.py       pseudonymisation before any prompt leaves; restore after
  llm/providers/         openai_compatible (also azure_foundry), anthropic_provider
  reporting/             builder.py (16 sources, 7 standard reports, planner), reports.py, compliance.py
  fixtures/              fake-mode vendor fixtures per connector
  tests/                 platform tests (conftest.py has PG mode, PG-rules enforcement, estates)
config/                  connectors.yaml, suppliers.yaml, sanctioned_services.yaml
artifacts/phishing/      labelled corpus (corpus/*.eml + labels.json), engine models/data
deploy/                  Dockerfile (multi-stage, non-root), docker-compose.yml (postgres, api, scheduler, engine profile)
docs/                    see §8
```

**Layering** (dependencies point down only): API → intelligence → domains → core → connectors. The LLM gateway is a
leaf any layer may call; everything must work without it.

**Request path**: BodyLimitMiddleware (30 MB) → SecurityMiddleware (NUL in path/query → 400, Content-Length → 413,
token bucket 20/s burst 120 → 429) → `current_user` (Bearer / X-API-Key / X-Break-Glass, revocation) →
`need(Perm.X, "domain")` → handler with one DB session (commit/rollback **before** the response - always
`Depends(db_session, scope="function")`) → security headers + queued access-log row.
`DataError` → 400, service `KeyError` → 404, `PermissionError` → 403. Out-of-scope records answer **404**.

---

## 5. Conventions the code relies on

**Time and ids**
- Always `soc_platform.core.models.utcnow()` - never `datetime.now()` / `utcnow()` from datetime. It honours the
  test-only `SOC_CLOCK_OFFSET_SECONDS` (time travel) and `SOC_CLOCK_FREEZE` (stop the clock); both are ignored when
  `SOC_ENVIRONMENT=prod`.
- Timestamp columns use `UTCDateTime` (always aware UTC). API timestamps carry explicit offsets.
- Ids are `uuid4().hex` (`new_id()`).

**Persistence**
- Services take a `Session` and **never commit**; the API request or job run owns the transaction.
- Free text from vendors/people → `BoundedText(n)` (kept to width with "…", NUL stripped). **Identifiers** stay strict
  `String(n)` so a mismatch fails loudly. NUL is stripped from every text column by a `before_flush` listener.
- Schema changes: `create_all` creates tables; `_add_missing_columns` then adds **nullable** columns the model defines
  but an existing table lacks (SQLite and PG); on PostgreSQL start-up also **widens** VARCHARs the model made longer.
  So a new table or a new *nullable* column reaches existing databases automatically. There is **no migration
  framework**: a NOT NULL column, a rename or a drop needs a scripted migration (Alembic) first. A new model module
  must be imported in `Database.create_all` (see the `# noqa: F401` imports) or its table is never created.
- `system_flags` holds durable cross-replica state (kill switch, `job_lease:*`, `scheduler:*` heartbeats,
  `audit_chain_head`). Its key column is 64 chars - hash long keys.
- Exactly-once transitions use conditional `UPDATE ... WHERE status IN (...)` and check `rowcount`.

**Idempotency everywhere** (re-runs must change nothing - a test runs every pipeline twice on 3 estates):
unique `ph_submissions.source_ref` (one case per reported message), unique action `idempotency_key`
(`type:` + sha256 of type/params/targets/case), one active campaign per CVE, insight `dedupe_key` upserts, connector
cursors, DB-decided job due-ness + lease.

**Determinism**: same inputs → same outputs. Sort anything built from a set before slicing or numbering
(an unsorted set of indicators once made verdicts vary between runs). QA sampling uses a stable hash. Story
fingerprints hash the evidence.

**Concurrency (parallel I/O, sequential database)**
- The SQLAlchemy session is not thread-safe. Only **network** work runs in threads; database reads/writes stay on
  the calling thread, and parallel results are merged **in a fixed order**.
- Patterns in use: `SyncRunner.sync_many` (all streams download at once, pages ingested in order),
  `ThreadPoolExecutor.map` for lookups (order-preserving), the LLM gateway's `_lock` around its session use so
  model calls can overlap (`SOC_LLM_CONCURRENCY`, default 4), `ConnectorRegistry` builds connectors under a lock.
- Every outbound call goes through the connector's `TokenBucket` (thread-safe), so parallelism never exceeds a
  vendor's rate budget. `Retry-After` is honoured but capped at 120 s.

**LLM use**
- Call through `LLMGateway` only (`grounded()` / `complete_json()`), passing computed figures as evidence with ids.
- Citations are validated; uncited claims and figures not in the cited evidence are dropped (numeric-fidelity
  guardrail). Internal identities are pseudonymised by `Redactor` and restored.
- Always provide a deterministic fallback path - the platform must behave identically (figures, verdicts, actions)
  with the LLM off. Small tier for routine narrative, large for summaries/deep analysis/reports.

**Security**
- Routes declare `Depends(need(Perm.X, "domain"))`; record-level scope checks in handlers (`_case_in_scope`).
- **Scope is per role**: `p.in_domain(d)` is *visibility* (union of roles); what `p` may *do* in `d` is
  `p.acting_in(d).can(perm)`. `need(perm, domain)` already returns the acting principal; a handler that writes to a
  case/action of a domain not fixed by its route must pass `p.acting_in(case.domain)` to the service. Actions requested
  on a case carry the case's domain; `ActionService` re-judges every decision in the action's domain.
- Human-only permissions (approvals, policy, access management, rollback) never go to API-key principals.
- UI: interpolate with `esc()`; clicks go through `data-fn` + the `ALLOWED` map (no inline handlers, strict CSP).
- Nothing fetches URLs taken from e-mail content (no SSRF surface) - keep it that way. The only configurable
  outbound destinations are connector endpoints and `SOC_NOTIFY_WEBHOOKS` (HTTPS only, from settings); never store,
  log or return a webhook URL (it holds a credential) - use `Channel.label` (`kind:host`).
- Error handling: no silent `except: pass` anywhere (ruff enforces). A catch-all must log or record the failure and,
  outside the resilience-boundary folders listed in `pyproject.toml`, carry `# noqa: BLE001 - <reason>`.

**Style**: ruff with the project config in `pyproject.toml` (line length 120). Match the surrounding code's density
of comments: short, explaining *why*. Tests read like specifications (`test_<behaviour_in_words>`).

---

## 6. Testing: how it is organised and what not to break

- **Fixtures** (`tests/conftest.py`): `db`/`session` (fresh in-memory DB), `ESTATES = ["demo", "seed7", "seed23"]`,
  `estate_configs` (builds variant estates once per session), `estate_env` (points fixtures, suppliers, org domain at
  an estate and resets caches). Tests default to `SOC_EMBEDDED_SCHEDULER=0` and temporary raw/report dirs - tests
  must never write into the project folder.
- **PostgreSQL parity**: `SOC_TEST_POSTGRES` maps every SQLite URL to a fresh PG database. Plain SQLite runs enforce
  PG rules via listeners (over-long strings except `BoundedText`, 32-bit Integer overflow, NUL in query params) -
  a `PostgresRuleViolation` in a test means production would fail.
- **Test files by concern**: `test_consistency.py` (same figure on every surface; re-runs change nothing; LLM on/off
  identical; every GET route × 7 roles; write-route fuzzing; references resolve), `test_time.py` (clock travel),
  `test_pentest.py` (24 attack tests incl. round 2: per-role scope, ReDoS), `test_properties.py` (Hypothesis), `test_scheduler.py`,
  `test_audit_concurrency.py`, `test_generalisation.py`/`test_variants.py` (no demo names leak on other orgs),
  `test_story.py`, `test_phishing.py` (incl. a latency test that fails if lookups become sequential),
  `test_incident.py`, `test_vulnerability.py`, `test_intelligence.py`, `test_report_builder.py`, `test_api.py`,
  `test_access_security.py`, `test_resilience_security.py`, `test_connectors.py`, `test_core_*.py`, `test_jobs.py`,
  `test_notify.py` (webhooks), `test_schema.py` (column addition on both engines), `test_cli.py` (`reset-demo`),
  `test_commit_before_response.py` (commit before reply, real server),
  `test_live_llm.py` / `test_live_public_feeds.py` (opt-in).
- **Comparing two runs figure-for-figure**: freeze the clock (`frozen_clock` fixture sets `SOC_CLOCK_FREEZE`) - risk
  decays with time, so a slower run otherwise rounds differently.
- **New behaviour needs a test**; a bug fix needs a regression test that failed before the fix. Don't hard-code
  demo-specific values in new tests - derive from settings/data or run over `ESTATES`.
- Current counts (keep docs in sync when they change): ~329 platform tests on SQLite and on PostgreSQL, 205
  engine tests, 103/103 features verified.

---

## 7. How to extend

- **A connector**: add `soc_platform/connectors/tools/<tool>.py` exporting `MANIFEST` (name, kind, config fields with
  `secret=True` where relevant, factory, `fake_settings`, fixture file, action factory). Implement `streams`,
  `fetch_page`, `normalize` → `NormalizedRecord`s (entities with strong `keys` + weak `hints`, events with `refs`),
  optional `lookup`. Add `soc_platform/fixtures/<tool>.json` routes (`FixtureTransport`: method, path regex, listed
  params only, `~` regex / `*` any, optional `body_contains`). Add it to `config/connectors.yaml`, a test in
  `test_connectors.py`, and a row in `docs/CONNECTORS.md` / PRESENTER_GUIDE §15.1.
- **An action**: a `ConnectorAction` in the connector's action factory (with `preconditions` and `reverse_type` if
  reversible), a policy entry in `core/policy.py:DEFAULT_POLICY` if it needs a non-default level/limit/four-eyes,
  and a test that it is recommended (not executed) by default.
- **A correlation rule**: a method in `intelligence/correlation.py` returning `Insight` with evidence, `dedupe_key`,
  severity, next steps; register it in `run()`; test the positive and negative case.
- **A report data source**: a `src_<name>(ctx)` in `reporting/builder.py` returning facts (label, value), optional
  table and a deterministic writer; add it to `SOURCES`. Figures come only from here, never from the model.
- **A job**: add to `jobs.JOBS` (env var + default interval) and `_body`; it must be idempotent.
- **A setting**: read it in `config.py` (or `os.environ` where it's operational), document it in
  `docs/OPERATIONS.md`, add it to `deploy/docker-compose.yml` if production-relevant.

---

## 8. Documentation map (who owns what)

| Doc | Owns |
|---|---|
| `README.md` | overview, quick start, doc index |
| `docs/ENGINEERING.md` | every engineering choice: architecture, stack, subsystems, security, reliability, measured latency, decision log (update when a design decision changes) |
| `docs/ARCHITECTURE.md` | diagram-level overview |
| `docs/RUN_GUIDE.md` | running the system, loading data, ingesting live in a demo, reset, Docker, troubleshooting |
| `docs/PRESENTER_GUIDE.md` | what to say/click in a demo, formulas, hard Q&A, numbers to remember, §15 component reference, §16 testing |
| `docs/DEMO_GUIDE.md` | short demo script |
| `docs/FEATURES.md` | screens and features |
| `docs/SECURITY.md` | threat model, hardening, pentest results |
| `docs/FAILURE_MODES.md` | failure → detection → behaviour → status |
| `docs/OPERATIONS.md` | settings, jobs, monitoring, access, backups, key rotation |
| `docs/LLM_TOKENS_AND_COST.md` | measured tokens and cost per component, budget settings |
| `docs/CONNECTORS.md` | per-connector details (partly generated by `scripts/build_connector_docs.py`) |
| `docs/CLIENT_DEPLOYMENT_GUIDE.md` | deploying into a client environment: hosting, Entra sign-in, every tool's permissions/settings/egress, the client's own LLM gateway, action rollout, go-live checklist |
| `docs/TEST_REPORT.md` | test rounds, newest first ("Round N" at the top) |
| `docs/FEATURE_VERIFICATION.md` | generated by `scripts/verify_features.py` - don't hand-edit |
| `docs/REQUIREMENTS_TRACEABILITY.md` | requirement → implementation → test |
| `docs/phishing/` | the ML engine's own docs |

---

## 9. Before committing (checklist)

1. Relevant test files pass; for core/cross-cutting changes run the full suite (and on PostgreSQL for DB-touching
   changes).
2. `ruff check . --exclude .venv,node_modules` → "All checks passed!"; bandit clean; JS: `node --check` on changed files.
3. Docs updated (§8), including test counts and any measured numbers you changed.
4. `git log --oneline -5` / `git status` - account for the user's own commits (rule 3).
5. Secret scan of staged files against `.env` values, without printing them:
   ```python
   import subprocess; from pathlib import Path
   vals=[l.split("=",1)[1].strip().strip('"') for l in Path(".env").read_text().splitlines()
         if "=" in l and not l.startswith("#") and any(k in l.split("=")[0] for k in ("KEY","SECRET","TOKEN","PASSWORD"))]
   staged=subprocess.run(["git","diff","--cached","--name-only"],capture_output=True,text=True).stdout.split()
   print([f for f in staged if Path(f).is_file() and any(v in Path(f).read_text(errors="ignore") for v in vals if len(v)>=12)])
   ```
6. Banned-name scan (rule 1): `git grep -n -I -i -E "<banned names>" -- .`.
7. Commit message with the attribution line (rule 4).

---

## 10. Gotchas that have already bitten

- **Shell escaping on Windows**: heredocs in Git Bash turned `"\n"` inside Python strings into real newlines and once
  wrote a literal NUL byte into `app.py`. For multi-line patches write a `.py` file with the Write tool and run it;
  after editing, `ruff check` catches broken strings.
- **PowerShell 5.1**: no `&&`, no `Invoke-RestMethod -Form` (use `curl.exe -F` for uploads), `Set-Content` defaults
  to ANSI (pass `-Encoding utf8`).
- **Git Bash paths**: `mktemp -d` gives `/tmp/...` which Windows Python cannot open in a SQLite URL - use the
  scratchpad's `C:/Users/...` path.
- **SQLite vs PostgreSQL**: SQLite accepts over-long text, NUL and 64-bit ints in Integer columns; PostgreSQL rejects
  them. The test listeners catch this - don't disable them.
- **Narrow ruff runs**: `ruff --select RUF100 --fix` with only a few rules enabled deletes `noqa` comments that are
  still needed. Always check RUF100 with the full rule set.
- **Module-level caches in tests**: `get_settings`, `app.registry`, `db._default`, the rate limiter and the LLM
  breaker are process-global; fixtures that change env must reset them and restore on teardown (register the
  finalizer *before* setup so a failed setup can't leak its environment).
- **Sweeping every route in a test with one token** hits `/auth/logout` and revokes it - use a fresh token per route.
- **Background writers bind to a database when the work is queued**, not when flushed (the access log once wrote rows
  into the wrong database).
- **Leases are released only after the run is recorded**, due-ness is re-checked after taking the lease, and taking a
  lease is a compare-and-swap whose insert race returns "not acquired" - each closed a real race.
- **"First insert" of a `system_flags` row races** (two threads both see no row): catch `IntegrityError` and treat
  it as lost / retry onto the existing row (`jobs._lease`, `Scheduler._beat`, `audit._lock_chain`). Two writers of
  one row must not read-modify-write: use a compare-and-swap on `updated_at` (`_lease`, `_write_beat`).
- **FastAPI runs a `yield` dependency's cleanup after the response by default.** For `db_session` that meant the
  commit came after the reply (an upload's case was missing from the next list in 28 of 40 tries). Every new route
  must use `Depends(db_session, scope="function")`; `test_commit_before_response.py` fails otherwise. TestClient
  cannot show this race - only a real server can.
- **SQLite blocks all writers during a long transaction** (an LLM call inside a request): background writes such as the
  heartbeat wait or fail. Commit before slow model calls (jobs and bulk endpoints do), and never infer "dead" from
  one missed write - `/health` asks the in-process scheduler (`Scheduler.alive_here`).
- **Thread exceptions only warn in pytest** (`PytestUnhandledThreadExceptionWarning`) - a crashed background thread
  can hide behind a green test. `test_scheduler.py` turns them into errors; do the same in new concurrency tests.
- **No randomness or speed in tests.** Generated data must be byte-identical for the same seed (never `make_msgid()`,
  random boundaries, `uuid4()` or wall-clock time in generated content: the auto-close QA sample is keyed on content
  hashes, and random Message-IDs once made a retention test fail at random). Prove parallelism by counting calls in
  flight, not by elapsed time; give waits long deadlines that end as soon as the condition holds.
  `SOC_TEST_POSTGRES` set but empty now aborts the run - a silent SQLite fallback looked like a PostgreSQL pass.
- **Environment settings are strings.** `bool("false")` is True and `**"{...}"` crashes: parse booleans and JSON
  settings explicitly (a Rapid7 `verify_tls` and the SIEM `field_map` both had this bug).
- **Never name the client's in-house LLM platform** in the repo - its name contains the client's abbreviation. Call it
  "the client's in-house LLM (gateway)".
- **Equal timestamps on Windows**: the clock advances in ~15 ms steps, so "newest first" by time alone is random
  within a tick - make times strictly increasing (case notes, `JobRun.ordinal`).
- **`demo` expectations** in the guides (7+3 cases, 34 approvals, 6 open vulnerabilities; the same with or without the ML engine) are real; if you change fixtures or
  pipelines, re-count and update RUN_GUIDE / PRESENTER_GUIDE.
- **Browser tour** runs the real scheduler with `SOC_SCHEDULER_START_DELAY=86400`: the heartbeat is live (no
  "Scheduler stopped" banner in screenshots) but no job runs to move figures under the screen-vs-API check. It gives
  the server a local webhook receiver so the Notifications card has a channel, and uploads the stored-XSS probe only
  after the screenshots. It fails on `undefined` / `NaN` / `[native code]` in any screenshot. `docs/screenshots` is
  refreshed only deliberately: `run_browser_tour(with_llm=True, shots=<tmp>)`, then copy the PNGs.
- **Job bodies may commit mid-way.** The incident and phishing jobs commit the investigated cases, then call
  `narrate_pending` (parallel model calls). Anything that reads a case must cope with
  `assessment["narration_pending"]` (deterministic explanation in place, model text still to come). Pass
  `narrate=False` only where a later `narrate_pending` is guaranteed (job or bulk endpoint).
- **Notifications are deduplicated by (`dedupe_key`, `severity`, `channel`)**: don't delete `notifications` rows in
  retention, or every open finding is sent again.
- **ReDoS in e-mail parsing**: patterns like `<[^>]+>`, `<a…>(.*?)</a>`, `[\w.+-]+@…` or `\d+[.,]?\d*` are
  quadratic on hostile input (one 240 KB message took 16 s; 25 MB would take hours). Bound every run (`{1,64}`), stop
  scans at the next tag (`<[^<>]*>`), anchor with a look-behind; `test_hostile_email_content_costs_linear_time` guards it.
- **`X-Forwarded-For`**: proxies append, so only the right-most untrusted hop is the client (`_client_ip`).
- **Risk "now"** is the latest observation in the data, not wall time; open exposures/incidents never decay
  (`STANDING_SIGNALS`); amplifiers fade with their triggers.

---

## 11. Glossary

Estate (a sample organisation's fixtures + corpus + settings) · fake/live mode · canonical schema / NormalizedRecord
· context store · entity resolution (keys vs hints, unresolved queue) · evidence ids (E#, S#/G#/H#/B#/P#/X#, F#, R#)
· L0-L4 autonomy · four-eyes · idempotency key · lease · standing signal · attack story / fingerprint · deep
analysis · grounding / numeric-fidelity guardrail · pseudonymisation · legal hold · self-check · shadow mode · drift
(PSI) · blind spot (ATT&CK stage no enabled tool can see).
