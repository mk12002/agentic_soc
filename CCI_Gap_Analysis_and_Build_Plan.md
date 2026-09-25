# CCI SOC — Gap Analysis of the Email Security Module and Build Plan

Basis: `CCI_SOC_AI_Automation_Consolidated_Requirements.docx` (v0.1) checked against the code in `email security/email_security/` (~41k lines of Python, 35 API routes, 16 compose services, 7 trained agent models). Date of review: 2026-09-24.

---

## Build status tracker (updated as work lands)

Legend: ✅ done and tested · 🟡 in progress · ⬜ not started · ⛔ blocked on an external input (see §5)

| Phase | Item | Status | Notes |
|---|---|---|---|
| 0 | Live Graph actions need analyst approval (`ACTION_REQUIRE_APPROVAL`, default on); override endpoint carries approval | ✅ | `response_engine.py`, `settings.py`, `api/main.py` |
| 0 | `ACTION_SIMULATED_MODE=1` by default | ✅ | `.env`, `.env.template` |
| 0 | Playbook engine records `recommended` / `pending_approval`, no longer claims `executed` | ✅ | `playbook_engine.py` |
| 0 | `docker.sock` removed from base compose; dev-only override keeps local detonation | ✅ | isolated detonation host still needed for prod (PH-T04) |
| 0 | `/api/v1/pewpew` removed | ✅ | |
| 0 | Rotate leaked keys (Azure OpenAI, Graph secret, VT, Shodan, AbuseIPDB, urlscan, GSB, OCR, GCP SA key) | ⛔ | Only you can rotate these in the vendor portals. They are kept out of git. |
| 0 | Fix the 8 failing email tests | ✅ | Re-run after Phase 0 changes: 176 passed, 0 failed (old failures were environment-specific) |
| 1 | Canonical schema + context store (entities, source provenance, relations, evidence, raw payload store) | ✅ | `soc_platform/core/schema.py`, `context_store.py` |
| 1 | Entity resolution: deterministic keys → scored fuzzy → unresolved queue → analyst override, match-rate metric | ✅ | `core/entity_resolution.py` (VM-F02, VM-T04, IM-T03). Scenario: 19 source records from 5 tools → 5 hosts, 100% match |
| 1 | Autonomy policy L0–L4, VIP/destructive/blast-radius gates, kill switch, versioned policy with propose/approve separation | ✅ | `core/policy.py` (§5.2, NFR-01, NFR-12) |
| 1 | Action layer: preconditions, idempotency, approvals, four-eyes, rollback, execution records, multi-vendor routing | ✅ | `core/actions.py`, `connectors/registry.py` RoutedAction (IM-T06, IM-T07, NFR-03) |
| 1 | Append-only hash-chained audit log with verify/export | ✅ | `core/audit.py` (NFR-04) |
| 1 | Entra SSO (RS256/JWKS) + RBAC + separation of duties; dev HS256 mode | ✅ | `core/auth.py` (NFR-09) |
| 1 | LLM gateway: redaction, approved endpoints, pinning, prompt log, token budget, tiered routing, grounded claims | ✅ | `soc_platform/llm/` (NFR-11, IM-T05, IM-T11) |
| 1 | Connector SDK: rate-limit budget, backoff, cursor checkpoints, reconciliation, per-record fault isolation | ✅ | `connectors/base.py`, `connectors/http.py` (NFR-14, VM-T02) |
| 1 | Plug-and-play connector registry + one connector per tool (live + fixture mode) | ✅ | 20 connectors: CrowdStrike, MDE, MDO (+reporting mailbox), Entra, Rapid7, Wiz, Avanan, Umbrella, Canary, Delinea SS, Delinea PM, NVD, EPSS, CISA KEV, TI fusion (8 sources), ServiceNow, Jira, CSV CMDB, Sentinel, generic SIEM |
| 1 | Refactor email system into `soc_platform/domains/phishing` | ✅ | ML engine at `domains/phishing/engine`, artifacts at `artifacts/phishing`; 173/176 engine tests pass in new layout (3 await repo-level deploy files) |
| 1 | Shared case / enrichment layer (consolidated view, parallel enrichment, partial-result transparency, shadow agreement) | ✅ | `core/cases.py`, `core/enrichment.py` |
| 1 | Platform API + analyst console (all 3 domains, approvals, policy, audit, reports) | ✅ | `soc_platform/api/` - strict CSP, rate limiting, RBAC; real-server smoke tested |
| 1 | Repo cleanup, README, .gitignore, push to GitHub | ✅ | https://github.com/mk12002/agentic_soc - models via Git LFS, no secrets (scanned) |
| 2 | Phishing: ingestion, decomposition incl. QR, analysis (engine + heuristic), reconciliation, campaign, user impact, recommendations, feedback, auto-close+sampling, propagation, metrics | ✅ | `domains/phishing/` - PH-F01..F16 covered; labelled corpus 10/10 (tuned on same corpus - see report) |
| 3 | Reporting engine: daily exposure, weekly VM, management deck, investigation record | ✅ | `soc_platform/reporting/` - CCI templates plug in via `templates` (A08) |
| 4 | Incident: ingestion, clustering+suppression, entity extraction, 8-dimension enrichment, exposure-informed severity, MITRE, grounded summary, recommendations, similar incidents, handover, Canary triage | ✅ | `domains/incident/service.py` - IM-F01..F16 |
| 5 | Vulnerability: ingestion, consolidation, NVD/EPSS/KEV prioritisation, ownership, affected devices, campaigns, notifications, follow-up, validation+false closure, exceptions, risk register, metrics, NL query, new-KEV assessment, coverage | ✅ | `domains/vulnerability/` - VM-F01..F18 (report templates pending under phase 3) |
| 6 | Guarded response: all actions via native APIs behind policy; promotion L2→L3/L4 by policy change | ✅ | promotion is a reviewed policy change; nothing auto-executes by default |
| — | Realistic-data testing: 20 connectors, 400-host resolution stress test, live NVD/EPSS/KEV, phishing corpus + engine evaluation, resilience & security tests | ✅ | `docs/TEST_REPORT.md` |
| H | Sandbox hardening: fail-closed isolation, host watchdog, output cap, pinned image, gVisor option, CAPEv2 backend for Windows payloads, executor fail-closed auth | ✅ | `docs/SECURITY.md` |
| H | Engine API auth on by default + constant-time compare; model integrity manifest (pickle); DB circuit breaker; bidi chars removed; dependency CVEs fixed / unused deps removed | ✅ | bandit + pip-audit clean |
| H | Entity resolution fixes found by stress test (clone-serial false merges, IP-only phantoms) | ✅ | 0 false merges |
| I | Intelligence layer: entity risk (all streams), 10 cross-domain correlation rules (U02/U04/U06/U07/U08/U10/U16), LLM analyst (narrative, daily brief, tool-planning Q&A), providers: Azure OpenAI / Anthropic Claude / OpenAI-compatible | ✅ | `soc_platform/intelligence/`, console Intelligence tab |
| R3 | Identity correlation across tools (UPN / SAM / aliases / former addresses / built-in accounts, authoritative merge, key-collision queue) | ✅ | 0 false merges, 0 % splits on 300-person stress test; `core/identity.py`, `test_identity_scale.py` |
| R3 | Connector fixes: MDE findbyip timestamp, Exchange admin API token audience, Rapid7 CVE search, Wiz `issuesV2` + pagination + CVE filter, Jira enhanced search, Delinea configurable paths, real health probes + Test endpoint | ✅ | `test_connectors.py` |
| R3 | Security: domain-scoped RBAC, step-up MFA, service-account keys, token/session revocation, break-glass, access log, durable kill switch, encryption at rest, retention, audit export; review fixes (scope bypasses, rate-limit key, stream body cap, /health DoS, dev-token exposure) | ✅ | `core/access.py`, `core/crypto.py`, `core/retention.py`, `test_access_security.py`, docs/SECURITY.md |
| R3 | U03 cloud misconfiguration lifecycle, U09 ATT&CK coverage, U11 shadow IT, U17 compliance pack, U18 supplier email risk | ✅ | FEATURES.md §2, §4, §5, §7 |
| R3 | Two-way ITSM sync with false-closure reopen (VM-T10 / IM-T10), durable jobs with dead letter + leases (VM-T11), drift monitoring (R14), measured latency (NFR-06) | ✅ | `test_vulnerability.py`, `test_jobs.py`, `test_intelligence.py` |
| R3 | Premium console (light default + dark mode, 16 screens, entity 360, dashboards), verified in Chrome with screenshots | ✅ | docs/FEATURES.md, docs/screenshots/ |
| R3 | Docs: FEATURES, ARCHITECTURE, CONNECTORS (generated), OPERATIONS, DEMO_GUIDE, REQUIREMENTS_TRACEABILITY | ✅ | docs/ |
| — | Deploy images built and run | ⛔ | Docker not available on the build machine; compose validated statically |
| — | Live connector validation against CCI tenants | ⛔ | needs CCI API access (A01, D01) |

Platform test suite: 108 passed + 3 live (opt-in). Phishing ML engine suite: 182 unit/top-level + 42 integration passed. Details: docs/TEST_REPORT.md.

---

Status legend: **Met** = works in code today · **Partial** = real code exists but falls short of the requirement · **Stub** = code exists but does not really do what it says · **Missing** = nothing in the codebase.

---

## 1. Are the doc's claims about the email system true?

Section 4.1 of the requirements doc describes the Multi-Agent Email Security System. Checked claim by claim:

| Claim in the doc (§4.1) | Verdict | Evidence in code |
|---|---|---|
| Seven analysis agents (header, content, URL, attachment + OCR, sandbox, threat intel, user behaviour) | **True** | `src/agents/*` — each has an agent, a feature extractor, inference code and a trained model in `models/` |
| Header: SPF/DKIM/DMARC plus Levenshtein lookalike detection | **True, and more** | `header_agent/` also has ARC validation (`arc_validator.py`) |
| Content: TinyBERT NLP classifier | **True** | `content_agent/`, `models/content_agent/model.safetensors`, plus `multilingual.py` |
| URL: entropy, heuristics, reputation, homoglyph detection | **True** | `url_agent/`, `utils/unicode_normalizer.py` (a curated confusables map for Cyrillic, Greek and fullwidth characters, plus punycode) |
| Attachment: EMBER features plus Azure AI Vision OCR | **True** | `attachment_agent/`, `services/ocr_service.py` |
| Sandbox: Docker execution with strace | **True, but unsafe** | `sandbox/executor_service.py` uses `docker.from_env()`. See the sandbox gap below. |
| Threat intel: local cache plus Azure AI Search | **True** | `threat_intel_agent/agent.py` (1,275 lines), `action_layer/azure_search_client.py`. External sources: VirusTotal, AbuseIPDB, urlscan, Shodan, Google Safe Browsing, OTX. |
| Deterministic LangGraph orchestrator that tolerates missing agent results | **True** | `orchestrator/langgraph_workflow.py`: score → correlate → decide → reason → (garuda) → persist → act → finalize |
| Counterfactual explanations and MITRE narratives via Azure OpenAI | **True, and better than claimed** | `llm_reasoner.py` makes every claim cite an evidence ID, drops claims with no valid citation, and falls back to deterministic output. This already covers most of IM-T05 and NFR-02. |
| Graph actions: quarantine, warning banner, endpoint hunt trigger | **Partly true** | "Quarantine" moves the message to the user's **Junk** folder in **one mailbox** (`graph_client.py:245`). It is not a Defender quarantine or a tenant-wide purge. The "endpoint hunt" is an HTTP POST to an external Garuda service (`garuda_integration/bridge.py`), and your own `SYSTEM_SHORTCOMINGS_AUDIT.md` says that service is missing. |
| Shadow-mode deployment with no MX changes | **Partly true** | There are no MX changes because ingestion never touches mail flow. There is no real shadow mode, though. `ACTION_SIMULATED_MODE` exists but is set to `0` in `.env`. |
| 17 REST endpoints, WebSocket streaming, SOC dashboard | **True, and more** | 35 routes in `api/main.py`, including `/ws/orchestrator`, `/soc/dashboard`, UI pages, PDF, STIX and ATT&CK Navigator export |
| 15-container Docker deployment (FastAPI, RabbitMQ, Redis, PostgreSQL) | **True** | `docker/docker-compose.yml` defines 16 services |
| About 45–50 ms latency and about 97% detection | **Not verifiable** | Measured on your own datasets only, as the doc itself warns. The last recorded test run had **8 failed and 124 passed** (`pytest_all_failures.txt`). I could not re-run the tests here because the Python dependencies are not installed on this Windows machine. |

### Things the doc does not say that matter

1. **Automated actions run with no human approval.** `act` is a normal graph node, so live Graph actions fire as soon as a verdict exists (`response_engine.py:153`). `/api/override` also executes actions straight away. The doc marks "VIP approval gate" as Ready, but that gate belongs to the endpoint system. In the email system, VIP status (`org_context.py`) only multiplies the risk score. **This violates NFR-01**, which is the main operating principle CCI asked for.
2. **The playbook engine only pretends to run.** `execute_playbook()` marks every step as `"executed"` with a timestamp but performs no action. No step has `requires_approval=True`. Anything reported from it overstates what happened.
3. **The sandbox is not hardened.** The compose comment says *"Base compose is hardened and does not mount docker.sock"*, but both `sandbox_agent_service` and `sandbox_executor_service` do mount `/var/run/docker.sock`. PH-T04 and R12 are therefore still open.
4. **Secrets are sitting in the working tree.** `.env` holds live keys: Azure OpenAI, Azure Search, the Graph client secret, VirusTotal, Shodan, AbuseIPDB, urlscan, Google Safe Browsing, Azure OCR, and the sandbox token. `gdrive_credentials.json` contains a GCP service-account private key. `API_AUTH_ENABLED=0`, and RabbitMQ uses the default guest credentials. `CRITICAL_SECURITY_ISSUES.md` already flags this, and it has not been fixed.
5. **There is no user identity anywhere.** Authentication is one shared API key, and it is off. The analyst name on an override is free text. NFR-04 requires actions attributed to a named human, and NFR-09 requires SSO and RBAC. Neither is possible today.
6. **The audit trail can be edited.** Decisions are stored as JSONB in `threat_reports` and events go to log files. Nothing is append-only or tamper-evident, which NFR-04 requires.
7. **Some items are missing that the doc treats as done or easy:** QR-code decoding (PH-F02), fuzzy hashing (PH-T03), and PII redaction before LLM calls (PH-T06).
8. **Housekeeping:** a joke endpoint at `/api/v1/pewpew`, real-looking sample mail and attachments committed under `data/` and `attachments/`, and six `ioc_store_*.db` copies.

**Bottom line.** The analysis half of phishing handling is real and strong, and the doc's "Largely ready" label is fair for detection and explanation. The action and governance layer is weaker than the doc says. As built, it would breach NFR-01, NFR-04, NFR-08 and NFR-09 in a client environment. Those problems need fixing before anyone calls it ready.

---

## 2. Phishing requirements (PH-*) against the code

| ID | Requirement | Status | Notes / what remains |
|---|---|---|---|
| PH-F01 | Reported-email ingestion | **Partial** | The parser keeps full headers (`email_parser.py`). Ingestion is only a folder drop, Google Drive, or API upload. No Graph mailbox reader, no Defender user-reported messages, no Avanan. |
| PH-F02 | Email decomposition | **Partial** | Headers, authentication, body, URLs, attachments and OCR all work. QR codes are missing. Routing-path analysis is basic. |
| PH-F03 | Multi-signal analysis | **Met** | Seven agents, fused by the orchestrator |
| PH-F04 | Avanan / Defender verdict reconciliation | **Missing** | |
| PH-F05 | Tenant-wide campaign scope | **Missing** | `campaign_detector.py` only counts 3 or more emails from the same sender domain within 10 minutes, and only among mail this system has seen. It cannot see the tenant. |
| PH-F06 | Who opened, clicked or submitted | **Missing** | The user-behaviour agent predicts click risk. It has no real click telemetry. |
| PH-F07 | Endpoint impact | **Stub** | Garuda POST with a retry queue. The target service does not exist. |
| PH-F08 | Identity impact (Entra) | **Missing** | |
| PH-F09 | Consolidated investigation view | **Partial** | The report page shows verdict, evidence, MITRE and IOCs. It has no scope, click or impact sections. |
| PH-F10 | Explainable verdict | **Met** | Counterfactuals, storyline and provenance chain, all grounded in evidence |
| PH-F11 | Recommended and approved remediation | **Partial** | Single-mailbox move to Junk or Deleted Items, banner, category, local sender block. No tenant purge, no Umbrella, Defender or Entra actions, and **no approval step**. |
| PH-F12 | Reporter feedback | **Missing** | |
| PH-F13 | Policy auto-close with analyst sampling | **Missing** | Routing files into folders by verdict is a starting point, but there is no policy or sampling. |
| PH-F14 | Campaign and user-risk reporting | **Partial** | Dashboard, overview and campaign endpoints exist. No repeat-clicker cohorts and no time-to-containment. |
| PH-F15 | Indicator propagation | **Partial** | IOC store, STIX export and webhooks exist. Nothing is pushed to Umbrella or Defender blocklists. |
| PH-F16 | Audit trail | **Partial** | Decision audit trail and provenance chain exist. The log can be edited and has no real actor identity. |
| PH-T01 | Graph, Defender and Avanan connectors | **Missing** | The only Graph code is for actions. |
| PH-T02 | Campaign, User-Impact and Reconciliation agents | **Missing** | The base swarm is reusable. |
| PH-T03 | Campaign clustering (fuzzy hash, embeddings) | **Missing** | |
| PH-T04 | Hardened sandbox | **Not met** | `docker.sock` is mounted |
| PH-T05 | Action layer (purge, Umbrella, Entra) behind gates | **Partial** | Mail moves only, with no gate |
| PH-T06 | Data handling and redaction | **Not met** | |
| PH-T07 | Throughput | **Unvalidated** | Benchmark tools exist (`tools/run_system_benchmark*.py`) |
| PH-T08 | Shadow-mode validation | **Partial** | Simulated-mode flag, `analyst_feedback` table, `/ops/agent-accuracy`, `/ops/drift-report`. No disposition-comparison workflow. |
| PH-T09 | No MX changes | **Met** | |

**Score: 3 Met, 12 Partial or Stub, 10 Missing or Not met, out of 25.** The missing items are mostly connectors, as the doc says. The governance gaps (approval, audit, security) are not in the doc's gap list and need adding.

---

## 3. The other two focus areas and the cross-cutting requirements

### Incident Management (IM-F01–16, IM-T01–11): 27 requirements

There is nothing for this area in this workspace. The doc bases its "Partially ready" rating on the **Agentic AI for Endpoint Security** system, and that code is **not in this folder**, so I could not verify it. Parts of the email codebase can be reused:

| Reusable from the email code | Serves |
|---|---|
| LangGraph fan-out/fusion pattern, partial-result tolerance | IM-T04, IM-F15 |
| Threat-intel enrichment across 6 sources with caching (`threat_intel_agent`) | IM-F04 (threat-intel dimension) |
| Grounded LLM reasoning with evidence IDs, MITRE engine, ATT&CK Navigator export | IM-F06, IM-T05 |
| STIX generator, PDF report, provenance chain | IM-F12, IM-F16 |
| Analyst feedback table and active learning | IM-F08, IM-F14 |
| Deduplication module (`orchestrator/deduplication.py`) | Starting point for IM-F02 |

Everything else must be built: 8 or more native connectors, the correlation graph, alert clustering, the consolidated view, similar-incident retrieval, shift handover, and forensics over CrowdStrike RTR and Defender Live Response.

### Vulnerability Management (VM-F01–18, VM-T01–13): 31 requirements

**Everything here is Missing.** The doc says so honestly. What can be reused is the orchestration pattern, LLM drafting, the reporting and PDF code, and the dashboard shell.

### Non-functional requirements (NFR-01–16) against the current platform

| NFR | Status | Gap |
|---|---|---|
| 01 Human in the loop by default | **Not met** | Actions fire automatically; no approval queue |
| 02 Explainability and evidence citation | **Met** for email | Deep links to source portals are still needed once connectors exist |
| 03 Reversibility | **Partial** | Moves are reversible, but no reverse action is defined or recorded |
| 04 Immutable audit with actor attribution | **Not met** | |
| 05 Partial-result tolerance | **Met** | Tested in `test_orchestrator_partial_finalization.py` |
| 06 Performance measurement | **Partial** | SLO and benchmark tooling exists |
| 07 Horizontal scaling | **Partial** | One container per agent on RabbitMQ; no connector tier yet |
| 08 Platform security | **Not met** | Secrets in files, auth off, docker.sock, guest broker credentials |
| 09 SSO, RBAC, separation of duties | **Not met** | One shared API key |
| 10 Data protection and residency | **Not met** | No redaction, classification or retention controls |
| 11 LLM governance | **Partial** | Grounding, temperature 0.1 and caching exist; no prompt/response log, token budget or model pinning policy |
| 12 Change management | **Missing** | Needs the autonomy policy engine |
| 13 Observability | **Partial** | Prometheus rules and a drift report; no per-connector freshness checks |
| 14 Vendor-neutral connector interface | **Missing** | |
| 15 Testability | **Partial** | 60+ test files, but 8 were failing; golden-set tooling exists (`build_hard_set_pack.py`) |
| 16 Documentation | **Partial** | Plenty of docs, some of which contradict the code |

### Overall count

| Area | Requirements | Met | Partial or Stub | Missing or Not met |
|---|---|---|---|---|
| Phishing (PH) | 25 | 3 | 12 | 10 |
| Incident (IM) | 27 | 0 | ~6 (reusable parts only) | ~21 |
| Vulnerability (VM) | 31 | 0 | ~3 (reporting/LLM shell) | ~28 |
| NFR | 16 | 2 | 8 | 6 |
| **Total** | **99** | **5 (5%)** | **~29 (29%)** | **~65 (66%)** |

Roughly **5% is done, about 30% has usable foundations, and about 65% is new work.** Almost all of the new work is connectors, entity resolution, workflow state and governance. The AI and detection work is largely done.

---

## 4. Build plan

### Guiding decisions

1. **Build one platform, not three products.** Turn the email system into the first domain module of a shared platform with a connector layer, a canonical schema, a context store, a policy engine, an action layer and an audit layer. Incident and vulnerability management become new domain modules on top of it. This is the doc's recommendation #2, and it is also what the codebase needs.
2. **Treat governance as core, not polish.** The approval queue, immutable audit, SSO/RBAC and the autonomy policy are the minimum needed to show anything to CCI. Build them first.
3. **Make every connector mockable.** You will not have CCI tenant access for months. Each connector gets a real implementation and a fixture-backed fake with the same interface. Develop against a Microsoft 365 E5 developer or trial tenant for the Graph and Defender work, and against recorded fixtures for CrowdStrike, Rapid7, Wiz, Umbrella, Canary and Delinea.
4. **Default to shadow mode.** Out of the box the platform is at L0 or L1. Any action type must be promoted explicitly in policy.

### Target platform layout

```
platform/
  core/
    connectors/        # BaseConnector: auth, pagination, rate-limit budget, cursor checkpoint, fakes
    schema/            # Pydantic canonical models: Email, Indicator, Identity, Asset, Alert, Finding, Action, Case
    context_store/     # Postgres (entities, relations, evidence) + object store for raw payloads
    entity_resolution/ # deterministic keys → scored fuzzy match → unresolved queue → analyst override
    policy/            # autonomy levels L0–L4 per action type, VIP/critical-asset gates, kill switch
    actions/           # ActionSpec: preconditions, idempotency key, execute, reverse, execution record
    approvals/         # approval queue, analyst decision capture, separation of duties
    audit/             # append-only, hash-chained audit log; actor = agent | named user
    llm/               # grounded reasoning (move llm_reasoner here), redaction, prompt log, cost budget
    reporting/         # deterministic metrics → docx/pptx templates; LLM for commentary only
    auth/              # Entra SSO (OIDC), RBAC roles: analyst / lead / admin / automation-admin
  domains/
    phishing/          # existing 7 agents + campaign, user_impact, control_reconciliation agents
    incident/
    vulnerability/
  api/ + ui/           # consolidated investigation view shared by all three domains
```

### Phase 0: Make the existing system safe (1–2 weeks, do now)

| # | Task | Closes |
|---|---|---|
| 0.1 | **Rotate every key in `.env` and the GCP service-account key.** Replace them with `.env.template` and a vault (Azure Key Vault, or Docker secrets for development). Scrub history if the folder was ever in git. | NFR-08, R07 |
| 0.2 | Turn on API auth by default. Change the RabbitMQ and Postgres credentials. | NFR-08 |
| 0.3 | Set `ACTION_SIMULATED_MODE=1` as the default. Stop the `act` node from executing live actions; it should write a *pending action* instead. | NFR-01 |
| 0.4 | Fix `execute_playbook()` so it records `recommended`, not `executed`, and connect it to the pending-action queue. | Honesty of outputs |
| 0.5 | Remove the `docker.sock` mounts. Move detonation to a separate VM or gVisor/Kata/Firecracker host with no network egress, controlled through the existing executor API. | PH-T04, R12 |
| 0.6 | Fix the 8 failing tests. Add CI that runs the unit tests on every change. | NFR-15 |
| 0.7 | Remove `/api/v1/pewpew`, the duplicate IOC databases, and real mail samples. Build a sanitised golden corpus instead. | Hygiene, NFR-10 |
| 0.8 | Correct the docs that contradict the code: the compose "hardened" comment, and the "Ready" row for the VIP gate. | Recommendation #11 |

**Exit:** no live action without approval, no secrets on disk, sandbox isolated, green test suite.

### Phase 1: Platform foundation (4–6 weeks)

- **Canonical schema and context store** (VM-T03, IM-T03). Start with Email, Indicator, Identity and Action, then add Asset, Alert and Finding.
- **Connector SDK and first connectors** (NFR-14, VM-T02, IM-T02). Include a rate-limit budget, cursor checkpointing and reconciliation counts. First real connector: **Microsoft Graph and Defender**, which unlocks phishing, identity and endpoint data in one app registration.
- **Autonomy policy engine and approval queue** (§5.2, NFR-01, NFR-12). Store L0–L4 per action type in versioned policy. VIP and critical-asset gates must block execution, not just raise the risk score. Add a kill switch.
- **Action abstraction** (IM-T06, IM-T07, NFR-03). Each action has preconditions, an idempotency key, a reverse action and an execution record. Re-implement the current Graph actions on top of it.
- **Immutable audit** (NFR-04, PH-F16, IM-F16, VM-F18). Append-only table, hash chain, and export.
- **Entra SSO and RBAC with separation of duties** (NFR-09, VM-T12).
- **LLM governance** (NFR-11, PH-T06). Redact PII before prompts, log prompts and responses, add per-workflow token budgets and pin model versions.

**Exit:** the existing phishing flow runs end to end through the new layers in shadow mode, with a verified audit trail.

### Phase 2: Finish phishing, the lead demo (4–6 weeks)

| Build | Requirement |
|---|---|
| Reported-message ingestion: Defender user-reported submissions, SOC shared mailbox through Graph, Avanan behind a feature flag with an export fallback | PH-F01, PH-T01 |
| QR-code extraction from images and PDFs (`pyzbar`/`zxing-cpp`) | PH-F02 |
| **Campaign Agent**: advanced hunting (`EmailEvents`, `EmailUrlInfo`, `EmailAttachmentInfo`) plus similarity clustering (normalised sender, subject template, URL skeleton, SHA-256 and ssdeep/TLSH, body embeddings) with a visible cluster rationale | PH-F05, PH-T03 |
| **User-Impact Agent**: `UrlClickEvents` and Safe Links data, Umbrella DNS once available, MDE `DeviceProcessEvents` for people who opened attachments, Entra sign-ins and risky users, inbox-rule changes | PH-F06, PH-F07, PH-F08 |
| **Control-Reconciliation Agent**: Defender and Avanan verdicts against ours, with disagreements highlighted | PH-F04 |
| Tenant-wide remediation through the action layer: Defender remediation or purge, tenant allow/block list, Entra session revocation. L3 only (runs after approval). | PH-F11, PH-T05 |
| Reporter feedback templates and an auto-close policy with mandatory random sampling | PH-F12, PH-F13 |
| Shadow-mode harness: agreement rate against analyst dispositions, confusion matrix, per-agent drift | PH-T08, NFR-15 |
| Investigation view: add scope, click, endpoint and identity panels | PH-F09 |
| Reporting: verdict mix, campaigns, repeat clickers, time to containment | PH-F14, U16 |

**Exit:** a reported email becomes a full investigation record (scope, clickers, endpoint and identity impact, reconciled verdicts, recommended actions) in shadow mode, with an agreement rate measured on a disposition-labelled corpus.

### Phase 3: Reporting engine, the early VM value (3–4 weeks, can run alongside Phase 2)

- Deterministic metrics layer: counts, ageing buckets, SLA breaches, MTTR, all computed in SQL or Python (VM-T08, VM-F14).
- Template rendering to CCI's own docx/pptx formats. The LLM only writes commentary paragraphs, which must cite the computed figures.
- Start from **file exports** (Rapid7 CSV, Defender TVM export) so no API access is needed. Deliver the Daily Exposure Report, the Weekly VM report and the management deck (VM-F13, U01).
- Risk-register draft entries for approval (VM-F12).

### Phase 4: Incident context (6–8 weeks)

- Alert connectors: CrowdStrike (detections plus streaming API), MDE and Graph Security alerts, Entra Identity Protection, Canary, Umbrella (IM-F01, IM-T01).
- Entity extraction from alerts, reusing the IOC extractors (IM-F03).
- Parallel enrichment across the 8 dimensions in §7.2, with per-source timeouts and caching (IM-F04, IM-T04). Missing sources are named explicitly (IM-F15).
- Clustering by entity, time window and ATT&CK technique (IM-F02). Extend `deduplication.py`.
- Consolidated view: entity cards, a unified timeline and deep links to source portals (IM-F05).
- Grounded summary and ranked actions with blast radius and reversibility (IM-F06, IM-F07); decision capture (IM-F08).
- Similar-incident retrieval using pgvector over past cases (IM-F11); shift handover brief (IM-F13).
- **Early win: Canary auto-triage (U04).** High confidence and low volume, so it is the first candidate for L3 or L4.
- Exposure-informed severity (U06) once Phase 5 asset data exists.

### Phase 5: Vulnerability consolidation (8–10 weeks; prove resolution first)

1. Four read-only connectors: Rapid7, CrowdStrike Spotlight/Exposure, Wiz GraphQL, Defender TVM (VM-F01, VM-T01).
2. **Asset resolution engine** (VM-F02, VM-T04). Match on deterministic keys first (agent ID, MDE device ID, cloud resource ID, serial, MAC), then scored matching on FQDN, IP within a time window and OS. Unresolved records go to a queue, and analyst overrides persist. Publish a match-rate metric. **Prove it on a bounded asset scope before going further.**
3. Finding normalisation and deduplication (VM-F03); enrichment with NVD, EPSS, CISA KEV and threat intel (VM-F04, VM-T06); affected-device lists (VM-F05).
4. Ownership routing from the CMDB, with an unknown-owner queue (VM-F07); notification drafts that need approval before sending (VM-F06, VM-T09).
5. Remediation campaigns, action plans, follow-ups and ITSM sync (VM-F08, VM-F09, VM-T10, VM-T11).
6. Validation by re-querying source tools and flagging false closures (VM-F10); exceptions with expiry (VM-F11); coverage and data-quality reports (VM-F17).
7. New-CVE and KEV exposure assessment (VM-F16, U02); natural-language query that shows the generated query (VM-F15, U12).

### Phase 6: Guarded response and continuous improvement (ongoing)

- Containment through native APIs: CrowdStrike containment, MDE isolation and scans, Entra disable and revoke, Umbrella block, Delinea rotation (IM-F09). Forensics over RTR and Live Response (IM-F10, IM-T09).
- Promote action types from L2 to L3 based on measured agreement; allow L4 only for reversible, low-blast-radius actions.
- Detection-tuning recommendations (IM-F14, U14), drift alerting (R14), control validation (U10), and ATT&CK coverage mapping (U09).

### Suggested order if you are a small team

```
Week  1–2   Phase 0 (safety)                     ← mandatory before any demo
Week  3–8   Phase 1 (foundation)
Week  6–13  Phase 2 (phishing complete)          ← headline demo to CCI
Week  9–12  Phase 3 (reporting, from exports)    ← parallel, low risk, weekly visible value
Week 14–21  Phase 4 (incident context + Canary)
Week 18–28  Phase 5 (VM: resolution first)
Week 22+    Phase 6
```

---

## 5. Decisions and inputs needed before Phase 1

1. **Is the Agentic AI for Endpoint Security code available?** The Incident Management "Partially ready" rating depends on it, and it is not in this workspace.
2. A Microsoft 365 E5 (or Defender P2 + Entra P2) dev or trial tenant for Graph, advanced hunting and Safe Links development.
3. The target runtime: Azure (Key Vault, Postgres Flexible Server, Container Apps or AKS) or on-premises. This decides the vault, storage and identity design.
4. Whether to restructure into `platform/core` + `domains/*` now (recommended) or bolt new modules onto the current `src/` layout.
5. The CCI discovery questions that change the architecture: Q01 (SIEM), Q03 (ITSM), Q13 (CMDB) and Q09 (Avanan API).
