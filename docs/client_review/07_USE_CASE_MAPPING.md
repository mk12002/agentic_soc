# Use-case mapping

| | |
|---|---|
| **Document** | Use-case mapping - Agentic SOC platform |
| **Version** | 1.1 - 2026-10-13 |
| **Audience** | SOC leadership, SOC analysts, security management |

## About the platform

The Agentic SOC platform is a planned AI-assisted investigation and operations layer across the security tools the
organisation already owns (CrowdStrike Falcon, Microsoft Defender for Endpoint, Rapid7 InsightVM / Nexpose, Wiz,
Avanan, Defender for Office 365, Microsoft Entra, Cisco Umbrella, Thinkst Canary, Delinea Secret Server and Privilege
Manager). It gathers, correlates, summarises, enriches, drafts and reports; **the SOC analyst validates the evidence,
determines the actual risk and approves the action**.

**Status:** every capability below is **Planned**. The development environment (a dedicated development VM) is being
set up; see *Development roadmap and readiness*.

## 1 The challenges this addresses

The SOC's three high-volume workflows - vulnerability management, incident management and reported / phishing e-mail
handling - share one operating pattern:

```text
Event / vulnerability / reported e-mail -> search multiple tools -> gather information manually
  -> correlate evidence manually -> determine actual risk -> coordinate remediation -> follow-up / validation / reporting
```

The challenge is not a lack of security tools or data; it is the manual effort to bring distributed information
together and turn it into timely, actionable decisions. Time goes on **search, gather, consolidate, correlate,
document and follow up** - the steps the platform is planned to take over, leaving the decision with the analyst.

Reductions in manual effort are not estimated here: they will be measured in the pilot against a baseline agreed with
the SOC (time per case and per report today vs. with the platform, on the same work).

## 2 Challenge 1 - Vulnerability management (Vulnerability Assistant)

Tools: Rapid7 InsightVM / Nexpose, CrowdStrike, Wiz, Microsoft Defender.

| Lifecycle step today | Planned capability |
|---|---|
| Vulnerability identified | Findings pulled from every scanner; each CVE enriched with CVSS, exploit probability (EPSS) and known exploitation (CISA KEV) |
| Gather affected devices | Affected-device list per CVE across all scanners, each device resolved to one asset |
| Consolidate and deduplicate | One finding per device and CVE, each scanner's record kept; priority from exploitability, internet exposure and asset criticality |
| Prepare remediation notification | Notification drafted per platform team with the affected devices, priority, SLA and fix text, for analyst approval |
| Platform team coordination | Owner and support group from the CMDB / ownership sheet; a remediation campaign per CVE with tickets in ServiceNow / Jira |
| Action plan and weekly follow-up | Action plans tracked; overdue and stalled items listed for follow-up; ticket status synchronised back |
| Remediation validation | The scanners re-queried: a finding is closed only when no scanner still reports it; a closed ticket with the CVE still present is flagged |
| Closure | Closure recorded with the validation evidence; time-bound exceptions approved by two people, reopened on expiry |

| Recurring SOC workload | Planned capability |
|---|---|
| Daily Exposure Report preparation | Generated daily from the consolidated findings (Word) |
| Critical vulnerability updates in the Risk Register | Risk register entries proposed for critical / known-exploited vulnerabilities, approved by the SOC, kept up to date with affected-asset counts and owners |
| Weekly Vulnerability Management reports | Generated weekly (Word) |
| Weekly management PPT preparation | Generated weekly (PowerPoint) |

Every figure in a report is computed from the data; AI, if enabled, only writes the narrative around them.

## 3 Challenge 2 - Incident management (Incident Investigation Assistant)

Tools: CrowdStrike, Microsoft Defender / MDE, Entra / Identity, Canary, Umbrella, Wiz, Rapid7, Delinea.

| Challenge today | Planned capability |
|---|---|
| A high volume of alerts makes individual handling cumbersome | Alerts grouped into incidents by the host and person they concern; one case instead of many alerts |
| An alert may not contain enough context to understand the actual risk | Each incident enriched with consolidated security context and a risk-context summary; severity from fixed rules with the reasons shown |
| User, host, IP, endpoint, identity, DNS, vulnerability and privileged-access evidence gathered from multiple portals | Multi-tool evidence gathered in parallel: endpoint (CrowdStrike, MDE), identity (Entra), DNS (Umbrella), deception (Canary), exposure (Rapid7, Wiz), privileged access (Delinea), on one timeline |
| Manual correlation before the risk decision | Cross-tool correlation (for example phishing click -> endpoint execution -> identity compromise; privileged access after compromise; exposed host under attack) |
| Remediation | Recommended containment (isolate host, revoke sessions, block indicator, ticket), each approved by an analyst |

```text
Today:    Alert -> Search tools -> Gather evidence -> Correlate -> Risk decision -> Remediate
Planned:  Alert -> Consolidated security context -> Analyst risk decision -> Remediate
```

Operating principle: AI gathers and correlates information; the SOC analyst validates the findings and makes the final
security decision.

## 4 Challenge 3 - Reported / phishing e-mail handling (Phishing Investigation Assistant)

Tools: Avanan, Defender for Office 365 / Microsoft Security Portal, CrowdStrike / MDE, Cisco Umbrella, Entra / Identity.

| Investigation step today | Planned capability |
|---|---|
| User reports e-mail | Reported e-mails picked up automatically from the reporting mailbox |
| Review sender / domain | Sender, domain, authentication results and look-alike / supplier checks done automatically |
| Analyse URLs / attachments | Links and attachments extracted and checked against threat intelligence (indicators only; no link from an e-mail is ever opened) |
| Security verdicts | Avanan and Defender verdicts consolidated with the platform's own analysis into one verdict with its evidence |
| Recipients / campaign scope | Everyone who received the same campaign found across the tenant |
| User interaction | Who clicked (allowed vs blocked) and whether the site was reached (Umbrella) |
| Endpoint / identity impact | Endpoint activity (CrowdStrike / MDE) and risky sign-ins (Entra) after the click |
| Risk and remediation | Recommended remediation (remove the campaign, block the sender, reset the account, reply to the reporter), each approved by an analyst |

All of it is presented as a single investigation view for analyst validation, so analysts focus on confirming risk,
scope and the right remediation instead of repeating the same checks.

## 5 Feedback requested

1. Does this mapping match each workflow as the SOC runs it today? Are any steps missing?
2. Which assistant should the demonstration focus on first?
3. Who will agree the productivity baseline (which cases and reports, which measures)?
