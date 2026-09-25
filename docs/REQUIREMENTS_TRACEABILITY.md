# Requirements traceability

Every requirement ID in *SOC – AI & Automation Consolidated Requirements* mapped to where it is implemented and how it
is verified. Test names refer to `soc_platform/tests/` unless stated.

Legend: ✅ implemented and tested · 🟡 implemented; completion or validation needs client data, environment or a decision (named in the row) · ⛔ needs client input before any build.

**Summary:** 102 requirements implemented and tested, 15 implemented but awaiting client data/environment for completion or validation, 0 blocked. Risks, assumptions, dependencies and open questions follow.

## Vulnerability management – functional

| ID | Requirement | Status | Implementation | Verified by |
|---|---|---|---|---|
| VM-F01 | Multi-source exposure ingestion | ✅ | Rapid7, CrowdStrike, Wiz, Defender connectors; `VulnerabilityService.ingest` (scheduled + on demand) | test_vulnerability, test_connectors |
| VM-F02 | Asset identity resolution | ✅ | `core/entity_resolution.py` deterministic keys → scored fuzzy → queue → override; conflict keys, provisional absorption | test_resolution_scale (400-host messy estate: 0 false merges), test_core_context |
| VM-F03 | Finding normalisation and deduplication | ✅ | `VulnerabilityService.consolidate` one record per asset×CVE, every source kept with status/link | test_vulnerability::test_four_scanners_consolidate... |
| VM-F04 | Exposure enrichment and prioritisation | ✅ | `prioritise`: CVSS + EPSS + KEV + exploit + internet exposure + criticality, explainable factors | test_vulnerability |
| VM-F05 | Affected-device consolidation | ✅ | `affected_devices(cve)` with owner/team/env/location/priority/status | test_vulnerability, test_api |
| VM-F06 | Remediation notification drafting | ✅ | `create_campaign` drafts per-team notifications (assets, rationale, fix, target date) | test_vulnerability |
| VM-F07 | Ownership routing | ✅ | `enrich_ownership` from ServiceNow CMDB / CSV mapping; unknown owner → blocked plan (exception raised) | test_vulnerability |
| VM-F08 | Action plan tracking | ✅ | `ActionPlan` per campaign/team: owner, committed date, dependencies, status, responses | test_vulnerability |
| VM-F09 | Automated follow-up | ✅ | `follow_up` escalations for unacknowledged / overdue / SLA-breached, stalled summary; scheduled job | test_vulnerability, test_jobs |
| VM-F10 | Remediation validation | ✅ | `validate` re-queries each source → verified / still present / decommissioned / unverifiable; false closures counted; ITSM-resolved tickets trigger validation | test_vulnerability (false closure, ITSM sync) |
| VM-F11 | Exception and risk acceptance | ✅ | Exceptions with justification, compensating control, approver ≠ requester, expiry → auto-reopen | test_vulnerability::test_exception_separation... |
| VM-F12 | Risk register updates | 🟡 | `propose_risk_register` + approval; format is generic until the client's register schema is supplied (A08) | test_vulnerability |
| VM-F13 | Recurring reporting | 🟡 | Daily exposure, weekly VM (docx), management deck (pptx) from one dataset; your own templates plug in (A08) | test_demo_walkthrough (all reports download) |
| VM-F14 | Trend and SLA analytics | ✅ | `metrics`: open/closed, MTTR, ageing, SLA breach, reopen/regression, per team | test_vulnerability |
| VM-F15 | Natural-language exposure query | ✅ | `query` NL → shown filter → records (no model needed; LLM optional) | test_vulnerability, test_demo_walkthrough |
| VM-F16 | New-CVE exposure assessment | ✅ | `new_cve_assessment` + `new_kev_exposure` insight; live NVD/EPSS/KEV verified | test_vulnerability, test_live_public_feeds |
| VM-F17 | Coverage and data quality reporting | ✅ | `coverage`: per-scanner gaps, single-tool assets, stale scans, match rate | test_vulnerability |
| VM-F18 | Audit trail | ✅ | Hash-chained audit on ingest, resolution, drafts, dispatch, validation, closure | test_vulnerability::test_everything_is_audited |

## Vulnerability management – technical

| ID | Requirement | Status | Implementation | Verified by |
|---|---|---|---|---|
| VM-T01 | Connectors | 🟡 | All four connectors implemented against documented APIs; verified on vendor-shaped fixtures, not yet on client tenants | test_connectors |
| VM-T02 | Ingestion mechanics | ✅ | Cursor checkpoints, delta, resumable backfill, token-bucket budget, exponential backoff, reconciliation | test_connectors, test_resilience_security |
| VM-T03 | Canonical data model | ✅ | Asset/Finding/Vulnerability(VulnIntel)/Owner/Campaign/Exception/ValidationResult with provenance & first/last seen | test_vulnerability |
| VM-T04 | Asset resolution engine | ✅ | Tunable thresholds, resolution audit, persisted overrides, match-rate metric | test_core_context, test_resolution_scale, test_identity_scale |
| VM-T05 | Storage | ✅ | Relational store (SQLite dev / Postgres prod) + raw payload store (encrypted at rest) + report store; retention job | test_access_security (encryption, retention) |
| VM-T06 | Enrichment services | ✅ | NVD, EPSS, KEV, 8 TI sources, cached with freshness and staleness shown | test_live_public_feeds, test_connectors |
| VM-T07 | Constrained LLM usage | ✅ | LLM only for narrative; all facts/counts/scores computed in code; grounded JSON claims | test_resilience_security, test_intelligence |
| VM-T08 | Reporting engine | 🟡 | Deterministic figures, LLM commentary only; client formats via template files (A08) | test_demo_walkthrough |
| VM-T09 | Notification dispatch | ✅ | `notify.email` (Graph, SOC mailbox) or `ticket.create`, behind approval, dispatch recorded | test_vulnerability |
| VM-T10 | ITSM integration | ✅ | ServiceNow & Jira: create/update + ticket state pulled back into plans; resolved → validation → false closure reopens ticket | test_vulnerability::test_itsm_bidirectional_sync... |
| VM-T11 | Workflow orchestration | ✅ | `soc_platform/jobs.py`: run records, retries+backoff, dead letter + alert, DB lease across replicas, replay API; idempotency keys on actions | test_jobs |
| VM-T12 | Access control | ✅ | Analyst/lead/admin/auditor/automation_admin roles, Entra SSO, per-tool service principals, vault `*_FILE` secrets | test_api, test_access_security |
| VM-T13 | Observability | ✅ | Connector freshness & reconciliation dashboard, job health, /metrics for Prometheus | test_demo_walkthrough |

## Incident management – functional

| ID | Requirement | Status | Implementation | Verified by |
|---|---|---|---|---|
| IM-F01 | Alert ingestion and normalisation | ✅ | Alert streams from CrowdStrike, MDE, MDO, Entra, Canary, Umbrella (lookup), Wiz, Delinea, Sentinel + webhook for any SIEM | test_incident, test_connectors |
| IM-F02 | Deduplication and clustering | ✅ | `cluster` by entity + time window + technique; repeat suppression | test_incident |
| IM-F03 | Entity extraction | ✅ | Users (UPN/SAM/aliases), hosts, IPs, domains, URLs, hashes, processes, cloud resources via `EntityRef`s; built-in accounts excluded | test_identity_scale, test_incident |
| IM-F04 | Multi-tool context enrichment | ✅ | `core/enrichment.py` parallel fan-out across 8 dimensions with per-source timeouts, cache, budget | test_incident |
| IM-F05 | Consolidated security context view | ✅ | Case view: entity cards, unified timeline, evidence by dimension, deep links; entity 360 view | test_demo_walkthrough |
| IM-F06 | AI risk assessment and summary | ✅ | Deterministic severity/confidence, MITRE with evidence, grounded summary; every claim cites evidence (E-refs resolvable in UI) | test_incident, test_demo_walkthrough |
| IM-F07 | Recommended remediation actions | ✅ | Ranked recommendations with expected impact, blast radius, reversibility, executing tool | test_incident |
| IM-F08 | Analyst decision capture | ✅ | Disposition capture (verdict, reasoning, analyst) feeding shadow metrics & tuning | test_api |
| IM-F09 | Guarded response execution | ✅ | CrowdStrike contain, MDE isolate/scan, Entra revoke/disable, Umbrella block… via policy-gated action layer with rollback | test_core_governance, test_incident |
| IM-F10 | Forensic collection on demand | 🟡 | `endpoint.collect_forensics` (CrowdStrike RTR / MDE investigation package) behind approval; artefact analysis pipeline depends on IM-T09 | test_incident |
| IM-F11 | Similar-incident retrieval | ✅ | Similar-incident retrieval with past dispositions and actions | test_incident |
| IM-F12 | Incident documentation | 🟡 | Investigation record + evidence pack (docx) from case & audit; the client's required format needs A08 | test_demo_walkthrough |
| IM-F13 | Shift handover and queue summary | ✅ | `handover` open-incident brief; intelligence situation brief | test_incident, test_intelligence |
| IM-F14 | Detection quality feedback | ✅ | `detection_quality` → tuning recommendations from dispositions | test_core_governance |
| IM-F15 | Partial-result transparency | ✅ | `completeness` names unavailable sources in every case; UI shows it | test_resilience_security |
| IM-F16 | Audit trail | ✅ | Audit of retrieval, inference, recommendation, approval, execution with actor | test_core_governance |

## Incident management – technical

| ID | Requirement | Status | Implementation | Verified by |
|---|---|---|---|---|
| IM-T01 | Connectors and authentication | 🟡 | Connectors for every named tool with correct auth (OAuth2, Entra app, Exchange-scoped token, API keys); live-tenant verification pending A01 | test_connectors |
| IM-T02 | Ingestion modes | ✅ | Polling with cursors + push webhook `/api/v1/ingest/alerts`; replay-safe dedupe | test_api, test_connectors |
| IM-T03 | Entity resolution and correlation graph | ✅ | Shared resolution engine + time-bounded relation graph with pivots (`neighbors`, `timeline`) | test_core_context, test_identity_scale |
| IM-T04 | Enrichment orchestration | ✅ | Parallel fan-out, per-source timeouts, partial tolerance, caching, per-tool rate budget | test_incident, test_resilience_security |
| IM-T05 | Grounded reasoning | ✅ | Evidence-only prompts, JSON schema, per-claim evidence ids, uncited claims dropped, insufficient-evidence flag | test_resilience_security, test_intelligence |
| IM-T06 | Action abstraction layer | ✅ | `ActionSpec` preconditions, policy binding, execution record, reverse action | test_core_governance |
| IM-T07 | Idempotency and concurrency control | ✅ | Idempotency keys + compare-and-set status transitions | test_core_governance |
| IM-T08 | Performance targets | 🟡 | Latency measured per investigation and per tool (Overview → Enrichment latency); targets to be set on client baselines (A09) | test_demo_walkthrough |
| IM-T09 | Re-platforming of forensic and containment capability | 🟡 | Collection via RTR / MDE is implemented; re-hosting the Volatility/Ghidra/YARA analysis over collected artefacts is not yet built | - |
| IM-T10 | Case and ITSM integration | ✅ | Bidirectional ITSM (create/update + state sync back); target system per Q03 | test_vulnerability |
| IM-T11 | Cost control | ✅ | Tiered routing (small/large), caching, token budget with alerting | test_resilience_security |

## Phishing – functional

| ID | Requirement | Status | Implementation | Verified by |
|---|---|---|---|---|
| PH-F01 | Reported-email ingestion | ✅ | Defender user-reported messages + SOC mailbox via Graph; upload/API submission | test_phishing |
| PH-F02 | Automated email decomposition | ✅ | `decompose`: headers, auth results, routing path, bodies, URLs, attachments, images, QR codes | test_phishing |
| PH-F03 | Multi-signal analysis | ✅ | 7-agent ML engine (+OCR, sandbox, TI) and deterministic heuristic analyser, composite fusion | test_phishing, engine unit tests (162) |
| PH-F04 | Existing-control verdict reconciliation | ✅ | `reconcile` with Avanan + MDO verdicts/actions; disagreements flagged | test_phishing |
| PH-F05 | Campaign scope determination | ✅ | `campaign_scope` via message trace / hunting + similarity | test_phishing |
| PH-F06 | User-interaction analysis | ✅ | `user_impact`: Safe Links clicks, Umbrella DNS, replies | test_phishing |
| PH-F07 | Endpoint impact assessment | ✅ | Endpoint detections for clickers (CrowdStrike, MDE) | test_phishing |
| PH-F08 | Identity impact assessment | ✅ | Entra risky sign-ins, MFA, device registration, inbox rules for affected users | test_phishing |
| PH-F09 | Consolidated investigation view | ✅ | One case record with verdict, evidence, MITRE, indicators, campaign, impact | test_demo_walkthrough |
| PH-F10 | Explainable verdict | ✅ | Counterfactual + chronological narrative; grounded claims | test_phishing |
| PH-F11 | Recommended and approved remediation | ✅ | Purge/quarantine, URL/domain block (Umbrella, MDE), sender block (Exchange admin API), session revoke — approval-gated | test_phishing, test_connectors |
| PH-F12 | Reporter feedback | ✅ | Reporter feedback drafted and sent via `notify.email` (policy-gated) | test_phishing |
| PH-F13 | Bulk triage and policy-based auto-close | ✅ | `AutoClosePolicy` for clear benign/spam with mandatory QA sampling | test_phishing |
| PH-F14 | Campaign and user-risk reporting | ✅ | Volume, verdict mix, campaigns, repeat clickers, time to containment; supplier risk | test_phishing |
| PH-F15 | Indicator propagation | ✅ | Confirmed indicators pushed to blocklists (gated) and the shared context store | test_phishing |
| PH-F16 | Audit trail | ✅ | Full audit with actor attribution | test_phishing |

## Phishing – technical

| ID | Requirement | Status | Implementation | Verified by |
|---|---|---|---|---|
| PH-T01 | Ingestion connectors | 🟡 | Graph, MDO (Threat Explorer/hunting), Exchange admin API (own token audience), Avanan; live verification pending A01/Q09/Q10 | test_connectors |
| PH-T02 | Analysis reuse and extension | ✅ | Engine swarm + LangGraph reused; campaign, user-impact and control-reconciliation agents added | test_phishing |
| PH-T03 | Campaign clustering | ✅ | Similarity over sender/display name, subject template, URL structure, attachment hash + fuzzy hash, body | test_phishing |
| PH-T04 | Sandbox hardening | ✅ | Hardened fail-closed detonation, no docker.sock, gVisor option, CAPEv2 for Windows payloads, authenticated executor | engine tests (sandbox), docs/SECURITY.md |
| PH-T05 | Action layer | ✅ | Graph soft/hard delete & quarantine, Defender indicators, Umbrella destination lists, Entra revocation | test_connectors |
| PH-T06 | Data handling | ✅ | Encrypted-at-rest .eml, retention job with legal hold, RBAC, PII pseudonymisation before any LLM call | test_access_security, test_resilience_security |
| PH-T07 | Throughput | 🟡 | Heuristic path ~1 s/message end to end on fixtures; production sizing needs client volumes (A09/Q17) | timing in docs/TEST_REPORT.md |
| PH-T08 | Shadow-mode validation | ✅ | Shadow mode by default (all actions L2 = recommend); agreement metrics vs analyst dispositions | test_core_governance |
| PH-T09 | Deployment model | ✅ | API-only alongside existing controls; no MX change | - |

## Non-functional

| ID | Requirement | Status | Implementation | Verified by |
|---|---|---|---|---|
| NFR-01 | Human-in-the-loop by default | ✅ | Autonomy L0–L4 per action type; default L2; destructive never autonomous; approvals in console | test_core_governance |
| NFR-02 | Explainability and evidence citation | ✅ | Every claim cites evidence; E-refs resolve to evidence with source + deep link in the UI; facts vs inferences separated | test_demo_walkthrough, test_intelligence |
| NFR-03 | Reversibility and evidence preservation | ✅ | Isolate/quarantine/block preferred; reverse actions; forensic collection before containment recommended | test_core_governance |
| NFR-04 | Auditability | ✅ | Append-only hash-chained audit; verify endpoint; JSONL export with chain verification | test_core_governance, test_access_security |
| NFR-05 | Resilience and partial-result tolerance | ✅ | Partial-result tolerance, circuit breakers, job retries/dead letter | test_resilience_security, test_jobs |
| NFR-06 | Performance | 🟡 | Measured per workflow and tool (dashboard); targets pending client baselines | test_demo_walkthrough |
| NFR-07 | Scalability | 🟡 | Stateless API + separate scheduler/workers + Postgres; job leases for multiple replicas. Not load-tested at client volume | - |
| NFR-08 | Platform security | ✅ | Vault secrets, least privilege, encryption at rest, CSP/headers, rate limits, bandit/pip-audit clean, hardened sandbox | test_access_security, test_resilience_security |
| NFR-09 | Identity and access management | ✅ | Entra SSO, RBAC with domain scope, step-up MFA, SoD, break-glass (sealed, audited, alerted), service-account keys, revocation | test_access_security |
| NFR-10 | Data protection and residency | 🟡 | Retention periods configurable and enforced; classification/residency are client decisions (Q21, Q24) | test_access_security |
| NFR-11 | LLM governance | ✅ | Approved endpoints, prompt/response log, pinning, redaction, grounding, budget | test_resilience_security |
| NFR-12 | Change management | ✅ | Versioned policy, propose ≠ approve, audited | test_core_governance |
| NFR-13 | Observability | ✅ | Connector freshness, job health, reconciliation, drift monitor, Prometheus metrics | test_demo_walkthrough, test_jobs, test_intelligence |
| NFR-14 | Portability and vendor neutrality | ✅ | Uniform connector SDK + manifest registry; swapping a tool is a connector change | test_connectors |
| NFR-15 | Testability and validation | 🟡 | Golden corpora, regression suites (~300 tests), shadow agreement; accuracy in the client's environment needs A07 data | all |
| NFR-16 | Documentation and handover | ✅ | README, ARCHITECTURE, CONNECTORS, OPERATIONS, SECURITY, DEMO_GUIDE, TEST_REPORT, this matrix | - |

## Use cases

| ID | Requirement | Status | Implementation | Verified by |
|---|---|---|---|---|
| U01 | Reporting-as-a-service across the SOC | ✅ | Reporting engine across VM, incident, phishing + compliance pack | test_demo_walkthrough |
| U02 | Emergency CVE exposure assessment | ✅ | New-CVE / KEV exposure assessment + insight | test_vulnerability, test_intelligence |
| U03 | Cloud misconfiguration remediation coordination | ✅ | `domains/vulnerability/misconfig.py`: Wiz issues → consolidation, ownership (CI or subscription), SLA, routing, validation, false closures | test_vulnerability::test_cloud_misconfiguration_lifecycle_u03 |
| U04 | Canary deception alert auto-triage | ✅ | Canary auto-triage + `deception_corroborated` correlation | test_incident, test_intelligence |
| U05 | Shift handover and queue briefing | ✅ | Shift handover + situation brief | test_incident, test_intelligence |
| U06 | Exposure-informed incident triage | ✅ | Exposure-informed severity + `exposed_host_under_attack` | test_incident, test_intelligence |
| U07 | Identity-centric risk view | ✅ | Identity-centric risk + entity 360 across Entra, Delinea, endpoint, phishing; exact cross-tool identity resolution | test_identity_scale, test_demo_walkthrough |
| U08 | Phishing to endpoint to identity chaining | ✅ | `phishing_compromise_chain` phishing → endpoint → identity | test_intelligence |
| U09 | Detection coverage mapping | ✅ | `intelligence/attack_coverage.py`: capability × observed ATT&CK matrix, blind spots, single-source techniques | test_demo_walkthrough |
| U10 | Continuous control validation | ✅ | `control_gap` rule: confirmed-bad destination still reachable in another control | test_intelligence |
| U11 | Shadow IT and risky destination analytics | ✅ | `intelligence/shadow_it.py`: unsanctioned services, risky destinations, per-user usage (Umbrella) | test_demo_walkthrough |
| U12 | Natural-language querying of security data | ✅ | Intelligence analyst Q&A with shown tool calls + VM NL query with shown filter | test_intelligence |
| U13 | Similar-incident retrieval | ✅ | Similar-incident retrieval | test_incident |
| U14 | Detection tuning recommendations | ✅ | Detection tuning recommendations | test_core_governance |
| U15 | Automated post-incident reporting and evidence packs | ✅ | Investigation report + evidence pack from the audit trail | test_demo_walkthrough |
| U16 | User security-risk scoring and targeted awareness | ✅ | Repeat-clicker cohorts + `repeat_clicker` insight | test_intelligence |
| U17 | Compliance and audit evidence automation | ✅ | `reporting/compliance.py`: control tests + evidence.json + chained audit export + summary.docx | test_demo_walkthrough, test_access_security |
| U18 | Third-party and vendor email risk monitoring | ✅ | `domains/phishing/supplier.py`: supplier compromise, payment diversion, impersonation, spoofing; supplier look-alikes protected in analysis | test_phishing::test_supplier_email_risk_u18 |

## Risks (R01–R16): mitigations in place

| ID | Risk | Mitigation |
|---|---|---|
| R01 | Asset identity resolution across four exposure sources proves harder than expected | Conflict keys (vendor ids), corroboration for shared hardware ids, unresolved queue + override, stress tests: 0 false merges (assets and identities) |
| R02 | LLM produces unsupported or subtly wrong claims | Grounded claims with evidence ids, uncited claims dropped, facts computed in code, deterministic fallback |
| R03 | Analyst distrust and non-adoption | Explainable evidence with deep links, shadow mode + agreement metrics, analyst stays decision owner |
| R04 | Over-automation causes business disruption | Autonomy policy, blast-radius limits, VIP gates, four-eyes, kill switch (durable), reversible actions |
| R05 | Ownership data quality is poor or absent | Ownership exceptions surfaced (blocked plans), CMDB + CSV + subscription mapping, coverage report |
| R06 | API rate limits and quota exhaustion at client volume | Per-tool token buckets sized under vendor limits, caching, backoff, reconciliation |
| R07 | The platform itself becomes a high-value target | RBAC, MFA step-up, service accounts can't approve, revocation, encryption at rest, audit, hardened sandbox |
| R08 | Tool licensing gaps block planned integrations | Connector manifests list licence-dependent capability; fake/live per connector; degraded operation |
| R09 | Scope ambiguity against existing investment | Layer orchestrates existing tools through their APIs; no displacement |
| R10 | Sensitive data exposure — email content, identity, privileged access | Encryption at rest, retention, pseudonymisation before LLM, no prompts in exports |
| R11 | LLM cost scales unfavourably with alert and email volume | Tiered routing, budget alerts, deterministic paths work without any LLM |
| R12 | Sandbox execution risk in the current email build | Fail-closed hardened sandbox; no docker.sock in base deployment |
| R13 | Forensic and evidential integrity | No destructive autonomous actions; forensic collection recommended before containment; append-only evidence |
| R14 | Model and detection drift over time | Drift monitor (agreement, PSI, confidence) raising insights; golden evaluation scripts |
| R15 | The client's tooling changes during or after the engagement | Connector SDK: tool change = connector change |
| R16 | Scope creep across three broad focus areas | Phased build tracked in the build plan; shared core across the three domains |

## Assumptions (A01–A12) and dependencies (D01–D12)

These are client-side inputs. The platform is built so each can be plugged in without code changes:

| ID | Item | How the platform is ready |
|---|---|---|
| A01 | The client will provide API access to the named security tools, with read scopes initially and dedicated service accounts per tool. | Per-tool service principals configured in `config/connectors.yaml`; read scopes first |
| A02 | The tools named in the client's tooling deck represent the complete relevant estate for these three focus areas. | New tools = new connector module (SDK + manifest) |
| A03 | Current licence tiers expose the APIs required — particularly Defender advanced hunting, Entra Identity Protection risk data, CrowdStrike exposure management, and Avanan's API. | Connectors degrade gracefully; missing licences show as unavailable sources |
| A04 | An asset ownership mapping exists in a CMDB or maintained source, or one can be established. | ServiceNow CMDB, CSV mapping, cloud-subscription mapping |
| A05 | The platform will run in an agreed environment with approved LLM endpoints and sufficient quota. | LLM optional; Azure OpenAI / Anthropic / OpenAI-compatible, approved-endpoint allow-list |
| A06 | Analysts remain the decision authority; no autonomous destructive action is required at go-live. | Default policy: every action L2 (recommend) |
| A07 | The client will provide representative historical data — alerts, reported emails with analyst dispositions, and vulnerability exports — for tuning and validation. | Evaluation scripts ready for the client's historical data (`scripts/eval_*`) |
| A08 | Existing report templates, the risk register schema and required output formats will be supplied. | Report templates (.docx/.pptx) plug in; risk-register mapping configurable |
| A09 | Volume baselines (alerts per day, reported emails per day, open findings, assets under management) will be provided. | Latency/volume metrics measured; sizing awaits baselines |
| A10 | The two existing internal systems are the delivery team's intellectual property and are reusable in a client engagement, subject to internal IP and licensing clearance. | Commercial / IP question - not a software item |
| A11 | The client's SOC operates a defined incident handling process with documented severity definitions and escalation paths. | Severity/approval routing configurable in the versioned policy |
| A12 | Network connectivity is permitted between the platform and each tool's API endpoints, including any required allow-listing. | Outbound-only HTTPS to each tool API; proxy supported by httpx env |
| D01 | API credentials and scopes | `connectors.yaml` + `*_FILE` vault secrets; per-connector Test button |
| D02 | Network access | Connector test endpoint proves reachability per tool |
| D03 | LLM provisioning | `SOC_LLM_*` settings, approved endpoints, redaction |
| D04 | Infrastructure | Docker compose / container images; Postgres |
| D05 | Identity integration | `SOC_AUTH_MODE=entra`; app roles `SOC.<Role>[.<Domain>]` |
| D06 | Asset ownership data | CMDB connectors + CSV |
| D07 | ITSM and case management integration | ServiceNow / Jira connectors |
| D08 | Named SOC subject matter expert | Disposition capture + shadow metrics built for SME feedback |
| D09 | Platform-team contacts | Team contacts per campaign; ticket routing by assignment group |
| D10 | Security review and approval | SECURITY.md, compliance pack, audit export for the review |
| D11 | Validation environment | Fake/live modes; shadow mode default |
| D12 | Sample data | Evaluation scripts + golden corpora |

## Open questions (Q01–Q28)

Answers change configuration, not code. Each row names the setting that absorbs the answer.

| ID | Question | Where the answer goes |
|---|---|---|
| Q01 | Is a SIEM in use? If so, which, and is it the primary alert aggregation point? This is our highest-priority question — it determines where our layer sits. | Sentinel or generic SIEM webhook connector |
| Q02 | Is there an existing SOAR platform or automation capability? If so, what does it currently automate, and where should the boundary with our layer sit? | Action boundary via autonomy policy per action type |
| Q03 | What case management or ticketing system does the SOC use for incidents, and what is used for vulnerability remediation tickets? | ServiceNow / Jira connector |
| Q04 | What is the documented incident handling process, and what are the severity definitions and escalation paths? | Severity mapping + policy |
| Q05 | Which team owns vulnerability remediation follow-up today, and how is it currently tracked? | VM campaign routing |
| Q06 | Who are the platform teams that receive remediation notifications, and through what channel today? | Team contacts / assignment groups |
| Q07 | What are the current SLAs for vulnerability remediation and for incident response? | SLA bands in VM prioritisation |
| Q08 | Is there a maintained VIP or critical-asset list that automated actions should honour? | VIP / critical-asset gates in policy |
| Q09 | Is Avanan's API available under the current licence, and what does it expose? This is the least certain integration in the assessment. | Avanan connector (least certain API) |
| Q10 | Which Microsoft licence tiers are in place — Defender for Endpoint, Defender for Office 365, Entra ID — and do they include advanced hunting, Safe Links click t | MDE/MDO/Entra connector capability flags |
| Q11 | Is CrowdStrike's exposure management capability licensed, and is Real Time Response enabled with an appropriate response policy? | CrowdStrike RTR / exposure scopes |
| Q12 | Is InsightVM or legacy Nexpose the authoritative vulnerability source, and is the live API available on the deployed version? | Rapid7 connector mode |
| Q13 | Is there a CMDB or authoritative asset ownership source? What is its coverage and how current is it? Critical dependency for remediation routing. | CMDB connector |
| Q14 | What retention windows apply to the data we would query — particularly Umbrella reporting data and Defender advanced hunting tables? | Lookup windows per connector |
| Q15 | Which reporting mechanism do users use to report suspicious email — a report button, a shared mailbox, or both? | Reporting-mailbox + Defender user-reported ingestion |
| Q16 | What are the current daily and peak alert volumes, and how are they distributed across the security tools? | Sizing, rate budgets |
| Q17 | How many emails are reported by users per day, and what proportion are ultimately confirmed malicious? | Throughput sizing, auto-close policy |
| Q18 | How many open vulnerability findings and how many assets are under management across the four exposure tools? | Sizing |
| Q19 | What is the current analyst headcount, shift model and typical time spent per investigation type? | Success metrics baselines |
| Q20 | Can we obtain historical alerts, reported emails and analyst dispositions for validation and tuning? | Evaluation scripts |
| Q21 | Where must the platform run — the client's tenant, a managed-service environment, or on-premise? What data residency constraints apply? | Deployment target & residency |
| Q22 | Which LLM endpoints are approved, and are there restrictions on sending email content, identity data or privileged access data to them? | LLM provider & redaction settings |
| Q23 | Is there an existing internal AI governance policy the platform must comply with? | LLM governance settings |
| Q24 | What retention is required for security evidence and for audit logs? | Retention settings (`SOC_*_RETENTION_DAYS`) |
| Q25 | Which actions may ever be executed without human approval, and which must never be? Who owns that decision? | Autonomy policy levels per action |
| Q26 | What is the change management path for introducing or modifying an automated action? | Policy propose/approve workflow |
| Q27 | Are there regulatory or audit constraints on automated security decision-making that we should design to? | Compliance pack control tests |
| Q28 | What does success look like to SOC leadership — which specific metrics, and how are they measured today? | Overview dashboard + reports |
