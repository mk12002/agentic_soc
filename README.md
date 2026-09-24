# Agentic SOC Platform

AI-assisted investigation and automation layer for a Security Operations Centre, built against the
*CCI SOC – AI & Automation Consolidated Requirements*. One platform serves three workflows over a
shared, governed context store:

| Domain | What it does | Requirements |
|---|---|---|
| **Reported / phishing email** | Ingests user-reported mail, decomposes it (incl. QR codes), runs the 7-agent ML swarm and/or heuristic analyser, reconciles with Defender/Avanan verdicts, scopes the campaign tenant-wide, finds who clicked and whether any endpoint or identity was compromised, recommends gated remediation, answers the reporter, auto-closes clear benign reports with QA sampling | PH-F01…F16 |
| **Incident management** | Ingests alerts from every tool, clusters them into incidents, enriches every entity in parallel across endpoint, identity, privileged access, DNS, deception, exposure, email and threat-intel dimensions, scores severity deterministically (exposure-informed), maps MITRE ATT&CK with evidence, recommends ranked guarded actions, similar-incident recall and shift handover | IM-F01…F16 |
| **Vulnerability management** | Pulls findings from Rapid7, CrowdStrike, Wiz and Defender, resolves the same host across tools, deduplicates, prioritises with CVSS + EPSS + CISA KEV + exposure + criticality, routes to owners from the CMDB, drafts notifications, tracks plans, follows up, validates remediation (detects false closures), manages exceptions and the risk register, generates daily/weekly reports and the management deck | VM-F01…F18 |

**Operating principle (NFR-01):** AI gathers and correlates; the analyst decides. Every action is
policy-gated (autonomy levels L0–L4), nothing destructive runs autonomously, every step is in an
append-only hash-chained audit log, and every figure in a report is computed in code.

See [`CCI_Gap_Analysis_and_Build_Plan.md`](CCI_Gap_Analysis_and_Build_Plan.md) for the requirement
traceability and build status, and [`docs/TEST_REPORT.md`](docs/TEST_REPORT.md) for test results.

---

## Quick start (local, no credentials needed)

Every connector has a **fake mode** that replays vendor-shaped fixture data through the same code as
the live API, so the whole platform runs end to end on a laptop.

```bash
git clone https://github.com/mk12002/agentic_soc.git && cd agentic_soc
git lfs pull                                   # trained phishing models (only needed for the ML engine)
python -m venv .venv && . .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements/platform.txt -r requirements/dev.txt
pip install -e .
cp .env.example .env                           # set SOC_DEV_JWT_SECRET to a long random string

python -m soc_platform demo                    # runs all three workflows on fixtures, writes reports to ./data/reports
python -m soc_platform serve                   # API + analyst console on http://127.0.0.1:8080
```

In the console choose a role (analyst / lead / automation_admin / auditor) and *Sign in (dev)*.
Dev tokens exist only when `SOC_AUTH_MODE=dev`; production uses Entra ID SSO (`SOC_AUTH_MODE=entra`).

Optional – the full phishing ML swarm (TinyBERT content model, URL/header/attachment/sandbox/TI/behaviour models):

```bash
pip install torch --index-url https://download.pytorch.org/whl/cpu
pip install -r requirements/phishing.txt
export SOC_PHISHING_ENGINE=1
```

### Docker

```bash
cp .env.example .env    # set POSTGRES_PASSWORD, SOC_DEV_JWT_SECRET (or Entra settings)
docker compose -f deploy/docker-compose.yml --env-file .env up -d --build            # platform
docker compose -f deploy/docker-compose.yml --env-file .env --profile engine up -d   # + ML microservices
```

## Intelligence layer

Above the three workflows sits a cross-domain intelligence layer (`soc_platform/intelligence/`):

* **Entity risk** - one explainable, time-decayed 0-100 score per user and host, fused from every stream
  (EDR, identity, DNS, deception, privileged access, email, exposure, cloud, open cases); every point cites the
  event, finding or case it came from.
* **Correlation engine** - deterministic rules that surface what no single tool sees: phishing → endpoint →
  identity compromise chains, privileged access after compromise, deception hits corroborated by other
  telemetry, attacked hosts carrying KEV vulnerabilities (exploitation attempts called out), attacked hosts
  without EDR, control gaps (malicious destinations still reachable), repeat clickers, newly KEV-listed CVEs on
  exposed assets, shared attacker infrastructure. Insights are deduplicated, triaged (acknowledge / dismiss)
  and re-opened only if they get worse.
* **LLM analyst (when configured)** - narrates insights, writes the daily situation brief, and answers free-form
  questions by *planning* calls to a catalogue of read-only tools that the platform executes; answers must cite
  the tool results. The model never touches the database or any action, internal identities are pseudonymised
  before every call, and tool calls are shown to the analyst. Without a model, a deterministic planner gives the
  same interface.

LLM providers (`SOC_LLM_PROVIDER`): `azure_openai`, `anthropic` (Claude via the official SDK; large tier
`claude-opus-5` with server-side refusal fallback, small tier `claude-haiku-4-5`), or `openai_compatible` (OpenAI or a
self-hosted vLLM / Ollama endpoint for tenant-resident processing). All go through the same governance:
approved-endpoint allow-list, pseudonymisation, prompt/response log, monthly token budget, grounding.

## Connecting real tools (plug and play)

Connectors live in `soc_platform/connectors/tools/` and are listed with their required settings in
`config/connectors.yaml`. To go live with a tool, set `mode: live` for it and provide its credentials
as environment variables (or `<NAME>_FILE` vault mounts). Nothing else changes.

| Category | Connectors |
|---|---|
| EDR | CrowdStrike Falcon, Microsoft Defender for Endpoint |
| Email | Defender for Office 365 (+ SOC reporting mailbox), Avanan |
| Identity | Microsoft Entra ID / Identity Protection |
| DNS / web | Cisco Umbrella |
| Deception | Thinkst Canary |
| Privileged access | Delinea Secret Server, Delinea Privilege Manager |
| Exposure | Rapid7 InsightVM/Nexpose, Wiz, CrowdStrike Spotlight, Defender TVM |
| Vulnerability intel | NIST NVD, FIRST EPSS, CISA KEV |
| Threat intel | VirusTotal, AbuseIPDB, OTX, URLhaus, ThreatFox, MalwareBazaar, GreyNoise, Shodan (fused) |
| ITSM / CMDB | ServiceNow (tickets + CMDB), Jira, CSV ownership mapping |
| SIEM | Microsoft Sentinel, generic webhook (`POST /api/v1/ingest/alerts`) |

**Adding a tool:** create `soc_platform/connectors/tools/<tool>.py` exporting a `ConnectorManifest`
(streams → `NormalizedRecord`s, lookups → `LookupResult`s, optional `ActionSpec`s), add a fixture file,
enable it in `connectors.yaml`. Third-party packages can register connectors through the
`soc_platform.connectors` entry-point group. When two tools provide the same action (e.g.
`endpoint.isolate` on CrowdStrike and Defender) the platform routes each target to the tool that manages it.

## Architecture

```
connectors (20 tools, live | fake)  ──►  normalisation (canonical schema)  ──►  entity resolution
        │                                                                          │
        ▼                                                                          ▼
  enrichment orchestrator (parallel, per-source timeouts, partial-result aware) ◄── context store
        │                                              (entities, provenance, relations, evidence)
        ▼
  domain agents: phishing · incident · vulnerability
        │
        ▼
  grounded reasoning (LLM optional; claims must cite evidence; figures computed in code)
        │
        ▼
  policy engine (L0–L4, VIP / destructive / blast-radius gates, kill switch)  ──►  approvals
        │
        ▼
  action layer (native tool APIs, pre-conditions, idempotency, rollback)  ──►  audit (hash chain)
```

```
soc_platform/
  core/          schema, context store, entity resolution, policy, actions, audit, auth, cases, enrichment
  connectors/    SDK (rate limits, backoff, checkpoints, reconciliation), registry, tools/
  llm/           governed LLM gateway (redaction, budget, prompt log, grounding)
  domains/
    phishing/    workflow + new agents; engine/ = the original 7-agent ML system
    incident/
    vulnerability/
  reporting/     docx / pptx reports
  api/           FastAPI service + analyst console (static/index.html)
  fixtures/      vendor-shaped fixture data for every connector (generated by scripts/build_fixtures.py)
  tests/         platform test suite
artifacts/phishing/   trained models (Git LFS), config, reference data, sample and corpus emails
config/connectors.yaml  deploy/  scripts/  docs/
```

## Tests

```bash
pytest soc_platform/tests                            # platform: core, connectors, 3 domains, API
pytest soc_platform/domains/phishing/tests/unit      # phishing ML engine (needs requirements/phishing.txt)
```

## Security notes

* Secrets are never stored in the repository. `.env` is git-ignored; use a vault in production.
* All connector write scopes should be provisioned separately from read scopes and enabled per action type.
* The attachment sandbox must run on an isolated detonation host (`SANDBOX_EXECUTOR_URL`); the Docker
  socket is mounted only by the dev-only `deploy/docker-compose.dev.yml`.
* LLM calls pseudonymise internal users before leaving the platform and are logged with token budgets.
