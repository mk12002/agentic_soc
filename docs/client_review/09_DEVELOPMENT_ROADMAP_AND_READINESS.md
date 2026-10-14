# Development roadmap and readiness

| | |
|---|---|
| **Document** | Development roadmap and readiness - Agentic SOC platform |
| **Version** | 1.0 - 2026-10-13 |
| **Audience** | Customer presentation: security leadership, SOC, project sponsors |

## About the platform

The Agentic SOC platform is a planned investigation and automation layer that runs inside the organisation's own
environment, on top of the security tools it already owns, covering phishing investigation, incident management and
vulnerability management. It recommends actions; **a person approves them**.

## 1 Current status

**The development environment is being set up**: a dedicated development VM is being provisioned and configured.
All capabilities in this document are **Planned**. Development uses synthetic, vendor-shaped sample data only - no
connection to the organisation's tools and no organisation data until the integrations are approved.

## 2 Planned capabilities

| Area | Planned capability | Status |
|---|---|---|
| Foundation | Connector framework (read-only by default, rate-limited, resumable), one picture per host and person, case management, audit trail | Planned |
| Connectors | 21 connectors: the organisation's 13 security tool families plus public vulnerability intelligence, threat-intel fusion, Jira, an ownership sheet, Sentinel and SIEM push | Planned |
| Phishing investigation | Automatic analysis of reported e-mails, campaign scope, who clicked, impact, recommended remediation | Planned |
| Incident management | Alert grouping, parallel enrichment, rule-based severity, MITRE mapping, recommended containment, ITSM tickets | Planned |
| Vulnerability management | One finding per host and CVE, risk-based priority, owners, campaigns, verified fixes, time-bound exceptions | Planned |
| Intelligence | Risk per person and host, cross-domain correlation, attack story, analyst assistant, reports | Planned |
| Governance | Roles and scope, MFA, two-person approval, autonomy policy (default: recommend), kill switch, audit, encryption, retention | Planned |
| AI (optional) | Explanations from cited evidence through the organisation's LLM gateway, with pseudonymisation and budgets | Planned |

## 3 Roadmap

The total development timeline is **4 weeks**, ending with a demonstration on synthetic data.

| Week | Planned work | Outcome |
|---|---|---|
| Week 1 | Development VM set up (**current**); build and test pipeline; synthetic vendor-shaped data; foundation (connector framework, one picture per host and person, cases, audit) | Working environment and foundation |
| Week 2 | Connectors in fixture mode; phishing investigation workflow | Phishing workflow end-to-end on synthetic data |
| Week 3 | Incident management and vulnerability management workflows; governance (roles, approvals, autonomy policy) | All three workflows with human approval |
| Week 4 | Intelligence (risk, correlation), optional AI explanations, testing, demonstration preparation | **Demonstration** of the three workflows to the SOC |

After development (dates to agree with the organisation):

| Stage | What happens | Outcome |
|---|---|---|
| Integration readiness | Security review, approved integrations, read-only access, SSO, API permissions | Approval to connect tools |
| Pilot | Tools connected read-only one at a time, then shadow mode (recommend only) measured against analyst decisions | Measured agreement and productivity against the agreed baseline |
| Approved actions | Selected low-impact, reversible actions approved by analysts | Controlled move to assisted response |

## 4 Key dependencies

| Dependency | Owner | Needed for |
|---|---|---|
| Development VM and tooling | Development team | Week 1 |
| Confirmation of tool list and representative synthetic data | Organisation SOC / development team | Weeks 1-2 |
| Agreed use cases and productivity baseline | Organisation SOC | Week 4 demonstration and pilot measurement |
| Security and architecture review sign-off | Organisation security / architecture | Integration readiness |
| Per-tool service identities, read-only API permissions, licences | Tool owners | Integration readiness |
| Entra ID app registration for sign-in, hosting environment, vault | Organisation IT | Integration readiness |
| LLM gateway access (optional) | Organisation AI governance | AI explanations |

## 5 Proposed next steps

1. Complete the development VM set-up.
2. Agree the use cases and the demonstration focus (see *Use-case mapping*).
3. Confirm the tool list and field-level sample data with the tool owners.
4. Agree the productivity baseline and pilot success measures with the SOC.
5. Confirm the week-4 demonstration date.
