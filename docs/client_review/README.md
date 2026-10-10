# Agentic SOC platform - security and architecture review pack

| | |
|---|---|
| **Version** | 1.0 - 2026-10-10 |
| **Status** | For review by the organisation's security, architecture and risk teams |
| **Classification** | Confidential - prepared for the organisation's review |
| **Scope** | The Agentic SOC platform as it would run in the organisation's environment: architecture, integrations, data, AI, governance, deployment and validation |

## What the platform is, in one paragraph

An investigation and automation layer that runs **inside the organisation's own environment** and sits on top of the
security tools it already owns. It reads from those tools through their APIs (EDR, e-mail security, identity, DNS,
deception, privileged access, vulnerability scanners, cloud posture, ITSM / CMDB, SIEM), resolves every record to one
host or one person, and runs three workflows on that shared picture - reported phishing, incident management and
vulnerability management - plus a cross-domain intelligence layer. It recommends response actions; **a person approves
them by default**. An optional large language model, reached only through the organisation's own LLM gateway, writes
explanatory narrative but never produces a figure, verdict, score or decision.

## The documents

| # | Document | Answers |
|---|---|---|
| 1 | [Solution architecture](01_SOLUTION_ARCHITECTURE.md) | What runs where; high-level and detailed diagrams; hosting model; infrastructure components; network connectivity (ports, directions, allow-list) |
| 2 | [Security tool integrations](02_SECURITY_TOOL_INTEGRATIONS.md) | Each integration: what it is used for, API and authentication method, exact permissions, read vs write scope, egress hosts, licence dependencies |
| 3 | [Data flow and protection](03_DATA_FLOW_AND_PROTECTION.md) | What data is collected, how it is processed and stored, retention and deletion, encryption in transit and at rest, every transfer outside the environment |
| 4 | [AI / LLM security](04_AI_LLM_SECURITY.md) | Model hosting, what data the model sees, access restrictions, safeguards against unauthorised actions, cost and abuse controls, the offline phishing ML models |
| 5 | [Security risk and governance](05_SECURITY_RISK_AND_GOVERNANCE.md) | Risk assessment, RBAC, audit logging, monitoring, human approval controls, security testing performed |
| 6 | [Deployment and validation](06_DEPLOYMENT_AND_VALIDATION.md) | Controlled pilot, integration prerequisites, testing methodology, success criteria, rollback procedures |

Diagrams are in [`diagrams/`](diagrams/) as SVG (scalable, open in any browser). A Word edition - one independent .docx per
document, each readable on its own - is generated with `python scripts/build_review_pack.py` (it embeds the diagrams
as images).

## How to read the status statements

Each control in these documents is marked with one of three statuses:

| Status | Meaning |
|---|---|
| **Implemented** | Built, enforced in code and covered by automated tests that run on every build (SQLite and PostgreSQL) |
| **Configured at deployment** | Built, but its value is the organisation's choice or comes from the organisation's environment (identity provider, network, vault, retention periods, model choice) |
| **To validate in the organisation's environment** | Built and tested against vendor-shaped data, but not yet exercised against the organisation's real tenants, volumes or users - covered by the pilot (Deployment and validation) |

## Evidence behind these documents

Every statement here is taken from the platform's code and its engineering record; figures are measured, never
estimated. The supporting detail is in the repository:

| Topic | Source |
|---|---|
| Engineering choices, decision log | `docs/ENGINEERING.md` |
| Threat model, penetration test results | `docs/SECURITY.md` |
| Failure behaviour per dependency | `docs/FAILURE_MODES.md` |
| Settings, jobs, monitoring, access, backups | `docs/OPERATIONS.md` |
| Step-by-step deployment and per-tool onboarding | `docs/CLIENT_DEPLOYMENT_GUIDE.md`, `docs/CONNECTORS.md` |
| AI tokens, cost and budgets | `docs/LLM_TOKENS_AND_COST.md` |
| Test rounds and results | `docs/TEST_REPORT.md`, `docs/FEATURE_VERIFICATION.md` |
| Requirement-by-requirement coverage | `docs/REQUIREMENTS_TRACEABILITY.md` |

Latest verification at the time of writing (`docs/TEST_REPORT.md`): 648 platform tests passing on SQLite and on
PostgreSQL 16, 205 phishing ML engine tests, 108 of 108 features verified (including a browser tour, live public feeds
and a live LLM), static security analysis (bandit) and dependency audit (pip-audit) with no findings.

## Open items for the organisation

The questions the organisation needs to answer before or during the pilot are collected in *Deployment and validation*, section 2
(integration prerequisites) and section 8 (decisions requested).
