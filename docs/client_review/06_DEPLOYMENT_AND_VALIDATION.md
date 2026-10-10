# Deployment and validation

| | |
|---|---|
| **Document** | Deployment and validation - Agentic SOC platform |
| **Version** | 1.0 - 2026-10-10 |
| **Audience** | SOC management, change advisory board, infrastructure, tool owners, risk |

## About the platform

The Agentic SOC platform is an investigation and automation layer that runs inside the organisation's own environment,
on top of the security tools it already owns (EDR, e-mail security, identity, DNS, deception, privileged access,
vulnerability scanners, cloud posture, ITSM / CMDB, SIEM). It reads from those tools through their APIs, resolves every
record to one host or one person, and runs three workflows - reported phishing, incident management and
vulnerability management - plus a cross-domain intelligence layer. Every change it makes to a security tool is an
*action request* that passes through one governed action layer and a versioned *autonomy policy*, whose default is
**recommend**: a person approves each action. An optional large language model, reached only through the
organisation's own LLM gateway, writes explanatory narrative but never produces a figure, verdict, score or decision.

**Status terms used in this document:** *Implemented* - built, enforced in code and covered by automated tests that
run on every build; *Configured at deployment* - built, with the value chosen by or taken from the organisation's
environment; *To validate in the organisation's environment* - built and tested against vendor-shaped data, not yet
exercised against the organisation's own tenants, volumes or users (covered by the pilot).

## 1 Summary

- The platform is introduced through a **controlled pilot** that never gives it more capability than it has proven:
  first no tools, then tools **read-only one at a time**, then a **shadow period** in which it only recommends while
  analysts work as usual, then **human-approved actions** for selected action types. Automation beyond human approval
  is a separate, later decision by the organisation.
- Each phase has **entry and exit criteria** measured by the platform itself (preflight results, reconciliation
  against each tool's own totals, shadow-mode agreement with analyst decisions, health and self-check).
- **Every step can be stopped or reversed** within seconds - pause a tool, engage the kill switch, restore an earlier
  configuration version - and the deployment as a whole can be rolled back to a previous image or withdrawn cleanly.
- This document is the deployment plan and the acceptance framework; the step-by-step engineering procedure
  is provided to the deployment team with the software.

## 2 Integration prerequisites

### Infrastructure and platform

| Prerequisite | Detail | Owner |
|---|---|---|
| Hosting | Container platform or VMs in a private application subnet | Organisation |
| Database | PostgreSQL 16, dedicated database and login, TLS, backups with point-in-time recovery | Organisation |
| Storage | Persistent volume / blob for the encrypted file store | Organisation |
| Vault | Key Vault (or equivalent) mounted as files into the containers; platform keys generated (data-encryption key, break-glass secret and its hash) | Organisation |
| Edge | TLS reverse proxy / WAF in front of the API; its address listed as a trusted proxy | Organisation |
| Egress | Outbound HTTPS allow-list for the tools in scope; forward proxy and inspecting CA bundle if used | Organisation |
| Logging and monitoring | Container stdout to the log platform / SIEM; Prometheus scrape with an auditor API key | Organisation |

### Identity

| Prerequisite | Detail | Owner |
|---|---|---|
| App registration | One registration for API and console: exposed API scope, v2.0 tokens, SPA redirect URI, app roles (`SOC.Analyst`, `SOC.Lead`, `SOC.Admin`, `SOC.Automation_Admin`, `SOC.Auditor`, and domain-scoped variants) | Organisation |
| Assignment | Security groups assigned to app roles; "assignment required" on | Organisation |
| Conditional Access | MFA required for the application; optionally an authentication context for step-up | Organisation |
| People | Named holders for each role, with *propose* (automation admin / admin) and *approve* (lead) held by different people; two break-glass custodians | Organisation |

### Per tool

| Prerequisite | Detail | Owner |
|---|---|---|
| Service identity | One per tool with read permissions; certificate credentials for Microsoft app registrations recommended | Tool owner |
| Credentials | In the vault under the names the console shows | Tool owner |
| Licences | Confirmed where a capability depends on them (Entra ID P2, Defender P2 plans, CrowdStrike Spotlight, Avanan HEC API) | Tool owner |
| Reporting mailbox | User-reported mail routed to a dedicated mailbox; `Mail.Read` scoped to it | Messaging team |
| Version specifics | Delinea API paths; ServiceNow ticket table and CMDB field names; Rapid7 API or CSV export | Tool owner |

### Organisation data

| Prerequisite | Detail |
|---|---|
| Internal mail domains | Every domain the organisation uses (drives pseudonymisation, "internal" logic and threat-intel withholding) |
| Key suppliers | The organisation's suppliers and their domains (supplier impersonation and payment-diversion detection) |
| Sanctioned services | The SaaS the organisation has approved (everything else seen in DNS is reported as shadow IT) |
| Ownership | CMDB access or a maintained ownership spreadsheet |
| Retention periods | Raw data, telemetry, AI logs, access log |

### LLM (optional, can follow later)

| Prerequisite | Detail |
|---|---|
| Gateway | Endpoint, protocol, authentication method, CA certificate |
| Models | Large-tier and small-tier model names |
| Allocation | Monthly token allocation, per-person limits, concurrency allowed by the gateway |

## 3 Controlled pilot approach

```text
 Phase 0        Phase 1            Phase 2                 Phase 3               Phase 4               Phase 5 (later,
 Prepare   ->   Platform      ->   Tools read-only    ->   Shadow mode      ->   Human-approved   ->   separate decision)
                baseline           one at a time           (recommend only,      actions for          Selected actions
                (no tools)         (Recording, Read-only)   no writes)            selected types       promoted by policy
```

Durations below are proposals to agree with the organisation.

| Phase | Proposed duration | What happens | Exit criteria |
|---|---|---|---|
| **0. Prepare** | 1-2 weeks | Prerequisites in 6.2; production settings; `config check` clean | All prerequisites signed off |
| **1. Platform baseline** | 2-3 days | Platform deployed with **no tool live**. Day-one sign-in test (MFA, roles, domain scope, dev sign-in refused); `/health`, self-check, audit verification; kill switch and break-glass tested once; backup and restore drill with audit verification on the restored copy; load test with the expected number of analysts | Every check passes |
| **2. Tools read-only, one at a time** | About 1-2 weeks | Each tool: service identity → credentials in the vault → proposal in the **Recording** stage (live reads, responses saved sanitised, no actions) → preflight passes → approved → a day of syncs → **Read-only**. Order: identity, EDR, CMDB, e-mail, vulnerability and cloud, then DNS, deception, privileged access and SIEM (section 4.1). The LLM can be connected at the end of this phase | Each tool: preflight ready; reconciliation with the tool's own totals; no unexplained errors; entity resolution reviewed (section 5) |
| **3. Shadow mode** | 2-4 weeks | The platform investigates and **recommends**; nothing is written to any tool. Analysts keep working in their existing tools and record their dispositions on the platform's cases; the platform measures agreement per domain | Shadow-mode targets met (section 5); analyst feedback reviewed |
| **4. Human-approved actions** | Ongoing | For action types the organisation approves: write permissions granted to that tool's identity; tool promoted to **Recommend** (actions offered, never above L2 - a person approves each). Start with reversible, low-impact types (tagging, ticket creation, reporter feedback, sender block) | Executed actions match approvals; no unintended writes; rollback rehearsed for each reversible type |
| **5. Selected automation** | Separate decision | The change advisory board may promote individual action types (for example L3) by an autonomy-policy change - proposed by one person, approved by another - based on shadow-mode and approval history. Irreversible types can never run autonomously | Per the organisation's change process |

At every phase the analysts remain the decision owners, and the organisation can pause any tool or stop all actions
immediately (section 6).

## 4 Testing methodology

### 4.1 Tool onboarding validation (per tool, phase 2)

| Test | How | Pass condition |
|---|---|---|
| Configuration | `python -m soc_platform config check`; console validation | No errors |
| Preflight | Automatic on proposal (also `python -m soc_platform preflight <tool>`): sign-in, every stream's permission, parsing, data freshness, clock, expected volume, write scopes for the target stage | *Ready*; warnings explained |
| Data completeness | Integrations screen: records ingested per stream vs the tool's own totals (reconciliation), freshness against each stream's cadence | Within the agreed tolerance (section 5) |
| Data shape | Recording stage: real responses captured (sanitised) and replayed through the conformance suite; `connector.data_quality` log lines reviewed | No unexplained shape drift |
| Entity resolution | Review of the unresolved queue and a sample of merged hosts and people against the CMDB / directory | Section 6.5 |
| Least privilege | Confirm that write permissions are absent for read-only tools (the preflight lists write scopes found) | No unexpected write scope |

### 4.2 Functional validation (phases 2-3)

| Area | Method |
|---|---|
| Phishing | Internal simulation e-mails reported through the normal button; verdict, campaign scope and click detection compared with the security team's assessment; shadow-mode agreement on real reports |
| Incident | Recent real alerts clustered and scored; severity and recommended actions compared with analyst judgement; attack stories reviewed for completeness |
| Vulnerability | One finding per host and CVE across scanners compared with each scanner's own counts; priorities and owners checked against CMDB; SLA dates reviewed |
| Reports | Standard reports generated and figures cross-checked against the screens (the platform also does this itself hourly) |
| AI (if enabled) | Live LLM suite against the organisation's gateway; token measurement for the cost model; narratives reviewed for citations; failure behaviour confirmed (endpoint unreachable → deterministic text) |

### 4.3 Non-functional validation (phase 1, repeated before phase 4)

| Area | Method |
|---|---|
| Performance | `scripts/load_test.py` against the target environment with the expected analyst count; `scripts/measure_scale.py` with production-like volume |
| Security | The organisation's own penetration test of the deployed instance (the platform's own suite runs on every build); configuration review against the production hardening checklist (section 7) |
| Resilience | A tool made unreachable (evidence shown as unavailable, workflows continue); LLM endpoint unreachable; scheduler stopped (banner and `/health`); database failover if the managed service supports it |
| Recovery | Restore drill from backup; `GET /api/v1/audit/verify` clean on the restored copy |
| Governance | Four-eyes on a connector change and a policy change; self-approval refused; with the kill switch on, an action the policy would run autonomously waits for approval; a paused tool's actions become manual steps; break-glass use raises a critical finding |

### 4.4 Assurance already completed before deployment

| Activity | Result at the time of writing |
|---|---|
| Platform test suite on SQLite and PostgreSQL 16 | 648 tests passing on each |
| Phishing ML engine tests | 205 passing |
| Feature verification (including a real-browser tour, live public feeds and a live LLM) | 108 of 108 features verified |
| Penetration suite, input fuzzing, static analysis, dependency audit | No open findings |
| Container deployment | Built and run end to end from empty volumes (Docker), demonstration figures identical to the reference run, restart persistence verified |

## 5 Success criteria

The figures below are **proposed targets for agreement**. Each is measured by the platform (screen or API named) so
the result is objective.

| Area | Measure | Where it is measured | Proposed target |
|---|---|---|---|
| Integration | Tools in scope passing preflight | Integrations → Preflight | All in-scope tools *ready* |
| Integration | Records ingested vs the tool's own total per stream | Integrations (reconciliation) | Within 1 % or explained |
| Integration | Freshness | Integrations / `/metrics` sync age | Every stream within its cadence for 5 consecutive days |
| Entity resolution | False merges found in the sampled review | Unresolved queue, entity pages | None |
| Entity resolution | Share of hosts / people left for review | Overview → *Awaiting resolution* | Agreed threshold after the first week (tunable setting) |
| Phishing (shadow) | Agreement with analyst dispositions | `GET /api/v1/metrics/shadow?domain=phishing` (agreement, false-positive, false-negative rates, sample size) | Agreement ≥ 90 % on at least 100 reports; no malicious report the platform called safe |
| Incident (shadow) | Agreement on severity / true-positive | `GET /api/v1/metrics/shadow?domain=incident` | Agreed with the SOC lead on the sample available |
| Vulnerability | Consolidated findings vs scanner totals; owner assigned | Vulnerabilities screen | Every scanner finding accounted for; owner on ≥ 95 % of findings or listed as an ownership exception |
| Actions (phase 4) | Executed actions without an approval | Audit chain | None |
| Actions (phase 4) | Rollback of each reversible type rehearsed | Audit chain | Rehearsed and verified |
| Reliability | Dead-lettered jobs unresolved | Job history / findings | None older than 1 working day |
| Integrity | Audit chain and self-check | `/health`, self-check | Valid throughout |
| Performance | Screen response at the expected analyst count | `scripts/load_test.py` | Median below 0.5 s, no server errors |
| AI (if enabled) | Usable answers; statements removed by the guardrail | AI usage → By feature | ≥ 95 % usable; ≤ 15 % removed per feature |
| Adoption | Analyst feedback on explanations and evidence | Pilot review | Agreed qualitatively with the SOC lead |

## 6 Rollback procedures

| Situation | Action | Who | Effect |
|---|---|---|---|
| **Stop all automation immediately** | Engage the **kill switch** (Automation policy screen, or `POST /api/v1/kill-switch?on=true`) | Lead, admin or automation admin (MFA) | Durable in the database; every replica and the scheduler stop executing actions autonomously at once; every action then waits for a person's approval; survives restarts. Recommendations continue |
| **Stop every write to a tool** | Engage the kill switch **and pause** the tool(s) (Integrations) | As above | No action can reach a paused tool, approved or not; its recommendations become manual steps |
| **One tool misbehaves** | **Pause** the tool (Integrations) | Admin / automation admin, or anyone holding the kill switch | Immediate on every process within seconds; audited with a reason; its actions become manual steps. Switching it back on is a proposal approved by another person |
| **An executed action was wrong** | **Roll back** the action (reverse type: release a host, enable an account, restore mail, unblock a sender / domain / indicator, restore from Avanan quarantine) | Lead (rollback permission, MFA) | A linked reverse action, executed and audited. Irreversible types (password reset, secret rotation, confirm-compromised, a hard mail delete) cannot be undone by the platform - which is why they are never autonomous |
| **A configuration change was wrong** | **Restore** an earlier configuration version (Integrations → History), or import a previously exported configuration | Proposed by admin / automation admin, approved by a lead | Applies within seconds after approval; no restart |
| **An autonomy-policy change was wrong** | Propose the previous policy version (every version is kept) | Automation admin proposes, lead approves | The previous behaviour returns on approval; the kill switch covers the interval |
| **The AI misbehaves** | Switch the feature off on the AI usage screen, or the whole LLM (`SOC_LLM_PROVIDER=none`) | Admin (AI usage screen) / operator (setting) | Deterministic, cited text immediately; no figure or decision changes |
| **A release has a defect** | Redeploy the previous image tag | Operator | Schema changes are additive (new tables, new nullable columns, wider text columns), so the previous image runs on the upgraded database. A release needing a scripted migration must ship and rehearse its rollback script before it is deployed |
| **Data corruption or loss** | Restore the database (point-in-time) and the file-store volume | Operator | `GET /api/v1/audit/verify` proves the restored audit chain intact |
| **Withdraw the platform** | Switch every tool off; remove write scopes and disable the tools' service identities; export the audit chain for retention; stop the services; delete data per the organisation's retention policy | Organisation | No residual access to any tool; the audit record is preserved |

## 7 Production hardening checklist

Confirmed before the platform is promoted beyond the read-only stage:

- [ ] Production mode: `SOC_ENVIRONMENT=prod`, Entra sign-in (`SOC_AUTH_MODE=entra`), step-up MFA on, no development
  sign-in secret configured.
- [ ] Data-encryption key (`SOC_DATA_KEY`) from the vault; a second key added before any rotation.
- [ ] TLS at the reverse proxy; the proxy listed as the only trusted proxy; port 8080 reachable only from it.
- [ ] PostgreSQL: TLS, dedicated login, backups and a tested restore; the platform's login has INSERT / SELECT only on
  the audit table.
- [ ] Every connector credential in the vault; least privilege per tool; write permissions only for approved action
  types; certificate credentials for Microsoft app registrations.
- [ ] Break-glass secret sealed with two custodians; only its hash configured; tested once.
- [ ] Outbound allow-list enforced at the firewall / proxy.
- [ ] LLM (if used): approved endpoint set, budgets set, pseudonymisation on, no demonstration keys present.
- [ ] Monitoring: `/metrics` scraped with an auditor API key; alerts on stale connectors, dead-lettered jobs, the kill
  switch and audit-chain validity.
- [ ] Logs: container stdout (JSON) collected into the organisation's log platform / SIEM; alerts on warnings, errors,
  failed jobs and model-call errors.
- [ ] Retention periods and the legal-hold process agreed and configured.
- [ ] No demonstration data loaded; no tool the organisation owns left on sample data.
- [ ] Configuration check clean (`python -m soc_platform config check`); preflight *ready* for every tool in use; the
  configuration exported and kept with the deployment record.
- [ ] Supplier and sanctioned-service lists replaced with the organisation's own.
- [ ] Recording off for every tool after onboarding; recordings reviewed and kept only where approved.
- [ ] Capacity checked: worker processes per CPU core, database connections within the server's limit, a load test
  run with the expected number of analysts.
- [ ] A restore drill completed and the audit chain verified on the restored copy.

## 8 Decisions requested from the organisation

| # | Decision | Needed by |
|---|---|---|
| 1 | Hosting target (cluster / VMs), database service, vault, reverse proxy | Phase 0 |
| 2 | Tools in scope and their owners; licence confirmations | Phase 0 |
| 3 | Role holders (propose vs approve separated), break-glass custodians | Phase 0 |
| 4 | Retention periods per data class | Phase 0 |
| 5 | Threat-intelligence sources permitted to receive external indicators | Phase 2 |
| 6 | LLM gateway, models per tier, token allocation, pseudonymisation stays on | Phase 2 |
| 7 | Notification channels and the severity threshold | Phase 2 |
| 8 | Success-criteria targets (section 5) | Before phase 3 |
| 9 | Action types approved for human-approved execution, and their write permissions | Phase 4 |
| 10 | Whether and when any action type is promoted beyond human approval | Phase 5 |
