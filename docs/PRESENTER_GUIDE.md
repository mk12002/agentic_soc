# Presenter guide - explaining, demonstrating and defending the platform

This is the briefing to read before presenting the Agentic SOC platform. It covers what to say, what to click,
what to point at, how each result is produced, how to justify every design decision, the hard questions you will
get (with answers), and the limits you should state before anyone else does.

Companion documents: [FEATURES.md](FEATURES.md) (screens), [DEMO_GUIDE.md](DEMO_GUIDE.md) (short script),
[ARCHITECTURE.md](ARCHITECTURE.md), [SECURITY.md](SECURITY.md), [OPERATIONS.md](OPERATIONS.md),
[FEATURE_VERIFICATION.md](FEATURE_VERIFICATION.md) (proof per feature), [TEST_REPORT.md](TEST_REPORT.md),
[REQUIREMENTS_TRACEABILITY.md](REQUIREMENTS_TRACEABILITY.md).

---

## Contents

1. [The pitch in 60 seconds](#1-the-pitch-in-60-seconds)
2. [Six principles that answer most questions](#2-six-principles-that-answer-most-questions)
3. [Architecture in plain words](#3-architecture-in-plain-words)
4. [Before you present: setup and checklist](#4-before-you-present-setup-and-checklist)
5. [Walkthroughs (click path, what to say, what to point at)](#5-walkthroughs)
6. [How each result is produced - and how to justify it](#6-how-each-result-is-produced)
7. [The AI: what it does, what it may not do, and the guardrails](#7-the-ai-what-it-does-what-it-may-not-do-and-the-guardrails)
8. [Security, data and governance](#8-security-data-and-governance)
9. [Evidence that it works](#9-evidence-that-it-works)
10. [Limitations - say these first](#10-limitations---say-these-first)
11. [Hard questions and answers](#11-hard-questions-and-answers)
12. [Numbers to remember](#12-numbers-to-remember)
13. [If something goes wrong during a demo](#13-if-something-goes-wrong-during-a-demo)
14. [Glossary](#14-glossary)
15. [Reference: every component in depth](#15-reference-every-component-in-depth) - connectors, actions, policy, roles, jobs, data model, every screen, the workflows step by step, failures, deployment
16. [How it was tested - and how to explain it](#16-how-it-was-tested---and-how-to-explain-it)

---

## 1. The pitch in 60 seconds

**The problem.** A SOC runs 15-20 security tools. Each sees a slice: the email gateway sees the phish, the EDR sees
the PowerShell, the identity provider sees the risky sign-in, the password vault sees the secret being copied.
Nobody sees the attack. Analysts stitch it together by hand, across consoles, under time pressure, and the same
three workflows - reported phishing, incidents, vulnerabilities - consume most of the day.

**What this is.** One investigation and automation layer on top of the tools the organisation already owns. It
pulls from 20 tools through their APIs, resolves every host and person to one identity across all of them, and runs
the three workflows on that shared picture. A cross-domain intelligence layer then correlates across workflows:
one page tells the whole attack story across every tool, with the evidence for each step, what was checked and
not found, who and what was reached, and a phased response plan.

**What makes it trustworthy.**
- Every conclusion cites the stored records it rests on.
- Every figure is computed in code, never by the model.
- Nothing runs without an approval unless the organisation deliberately promotes that action type in a reviewed,
  versioned policy.
- Everything lands in a tamper-evident audit log.

**What it is not.** It is not a SIEM, SOAR or EDR replacement. It orchestrates them.

---

## 2. Six principles that answer most questions

Almost every challenge maps to one of these. Name the principle, then show where it is enforced.

| # | Principle | Where it is enforced | Say |
|---|---|---|---|
| 1 | **AI gathers and explains; the analyst decides** | Autonomy policy L0-L4, default L2 (recommend) for every action; destructive actions can never be autonomous | "Nothing you saw executed on its own." |
| 2 | **Every figure is computed in code** | Scores, verdicts, severities, counts, SLAs are deterministic functions; the LLM receives them as evidence and a statement that states a figure not in its evidence is removed | "The model can't change a number; it can only explain it." |
| 3 | **Every statement cites evidence** | Evidence ids (E#, S#, F#...) validated against what was retrieved; uncited or invented citations dropped and counted | "Hover any reference - it's a stored record from a named tool." |
| 4 | **Same code for demo and production** | Every connector has a fixture mode that feeds vendor-shaped data through the same parsing and logic as live mode | "The demo exercises the production code path." |
| 5 | **Least privilege and separation of duties** | RBAC + domain scope + step-up MFA; nobody approves their own four-eyes action, policy or access grant; service accounts can never approve | "Even an admin can't approve their own high-impact action." |
| 6 | **Prove everything** | Append-only hash-chained audit log, verified on demand; compliance evidence pack generated from it | "Every retrieval, inference, recommendation and approval is in here, and any edit breaks the chain." |

---

## 3. Architecture in plain words

Draw it as four layers (full diagram in [ARCHITECTURE.md](ARCHITECTURE.md)):

1. **Connectors (20).** One SDK: rate budgets under each vendor's limits, backoff, cursors, reconciliation,
   per-record fault isolation. Each has a *live* mode (vendor API) and a *fake* mode (vendor-shaped fixtures, same
   code). CrowdStrike, Defender for Endpoint, Defender for Office 365 (+ Exchange admin), Entra ID, Rapid7, Wiz,
   Avanan, Umbrella, Canary, Delinea Secret Server, Delinea Privilege Manager, NVD, EPSS, CISA KEV, threat-intel
   fusion (8 sources), ServiceNow, Jira, CMDB CSV, Sentinel, generic SIEM webhook.
2. **Core.**
   - Context store with entity resolution: one canonical host or person across all tools.
   - Cases and evidence.
   - Autonomy policy and the action layer: preconditions, approvals, idempotency, rollback.
   - Audit chain, encryption at rest, retention, and durable jobs.
3. **Domains.**
   - **Phishing:** reported email → verdict → campaign scope → who clicked → endpoint and identity impact →
     remediation.
   - **Incident:** alerts → clusters → parallel enrichment → deterministic severity → MITRE ATT&CK → actions.
   - **Vulnerability:** four scanners → one finding per host and CVE → priority → owner → ticket → validated fix.
     Cloud misconfigurations go through the same lifecycle.
4. **Intelligence.**
   - Explainable fused risk per user and host.
   - 12 correlation rules, plus 4 operational alerts.
   - A platform self-check that proves the same figures agree everywhere (hourly).
   - Analyst Q&A with cited answers.
   - Situation brief.
   - **Attack story** and optional **deep analysis**.
   - ATT&CK coverage, shadow IT, supplier risk, drift monitoring.
   - **Report builder.**

**Data flow, one sentence each:** ingest and normalise → resolve entities → investigate (evidence, deterministic
scoring, optional cited narrative) → recommend actions through the policy → correlate across domains → prove
(audit, reports, evidence packs).

**Deployment:** stateless API (scale horizontally), scheduler (several replicas are safe: per-job database lease),
PostgreSQL, a volume or blob store for encrypted raw payloads and reports, and an optional phishing ML engine with
an isolated detonation host.

---

## 4. Before you present: setup and checklist

Step-by-step instructions for installing, configuring, loading data and ingesting live are in
[RUN_GUIDE.md](RUN_GUIDE.md). The short version:

```bash
python -m soc_platform init-db
python -m soc_platform demo                  # load the sample organisation (below)
python -m soc_platform serve                 # http://127.0.0.1:8080 ; sign in as Lead
```

`demo` loads, through the same code as production:
- the four vulnerability scanners, with a remediation campaign for CVE-2021-44228 (Log4Shell)
- the incident alerts, clustered and investigated (3 incidents)
- the reporting mailbox (1 report), plus the six sample messages a presenter would otherwise upload: supplier bank
  change, supplier look-alike payment, CEO wire fraud, QR phishing, a genuine invoice and marketing spam
- the cloud misconfigurations, routed to their teams
- the correlation, the three standard reports, and an audit-chain check

Result: 7 phishing + 3 incident cases, 6 open vulnerabilities, 34 actions awaiting approval (incident 15, phishing 16,
vulnerability 3). It uses `SOC_ORG_DOMAINS`, `SOC_RAW_PAYLOAD_DIR` and `SOC_REPORT_OUTPUT_DIR` from settings. Running
it twice changes nothing.

To show the LLM features, the `.env` must contain an approved endpoint (already configured for Azure AI Foundry):
`SOC_LLM_PROVIDER=azure_foundry`, `SOC_LLM_ENDPOINT`, `SOC_LLM_API_KEY`, `SOC_LLM_DEPLOYMENT=gpt-4.1-mini`,
`SOC_LLM_APPROVED_ENDPOINTS` (same URL), `SOC_LLM_MODEL_VERSION=gpt-4.1-mini`. Load them into the environment (or
run with `docker compose --env-file .env`). Without them everything works and says "deterministic".

Checklist (10 minutes before):
- [ ] Data loaded: Cases shows 7 phishing + 3 incident cases; Vulnerabilities shows 6 findings.
- [ ] Intelligence → *Re-correlate* once; the situation brief is populated.
- [ ] Open the phishing case *"Action required: your password expires today"* and its **Attack story** once
      (warms the cache).
- [ ] If showing the LLM: Reports page callout says *"Narrative is written by the approved LLM (azure_foundry)"*.
      Run one deep analysis beforehand; it is cached for the demo.
- [ ] Browser zoom 100 %, window at least 1280 px wide. Light theme for projectors.
- [ ] Have a second browser profile ready as **Analyst** (for the four-eyes demo) and one as **Auditor**.

---

## 5. Walkthroughs

Each walkthrough gives the click path, the line to say, what to point at, and the justification if challenged.
The full demo takes 25-30 minutes. For a 10-minute slot, do W1 → W4 → W6 → W9.

### W1 - Overview (2 min)

**Click:** Overview.
**Say:** "This is the SOC at a glance across all three workflows. Every figure is computed from stored records -
nothing here is typed in or estimated."
**Point at:**
- Open cases split by domain.
- **Awaiting approval.** It equals the Approvals badge and the Approvals tab total: one count, one definition.
- Automation rate: 0 % by design, recommend-only.
- Open insights by severity; open vulnerabilities (past SLA, internet-exposed).
- Riskiest users and hosts.
- The data-quality panel: asset and identity match rates, unresolved queue.
- Enrichment latency; verdict quality ("needs more dispositions" until analysts have recorded enough decisions).
**If challenged ("0 % automation looks bad"):** "It's the safe default the requirements asked for. Promotion to
automation is a reviewed policy change per action type - W6 shows it."

### W2 - Intelligence and the analyst assistant (4 min)

**Click:** Intelligence. Ask: *"Is jane.doe@acme-demo.com compromised and what should we do first?"*
**Say:** "The assistant plans which read-only tools to call, calls them, and answers only from their results.
Every sentence cites the tool result it came from."
**Point at:** the evidence list under the answer (R1, R4...), "How this was answered: llm planner" with the tools
it called, the situation brief, the correlated findings with next steps, and the risk list.
**Justify:**
- The assistant can only call tools from a fixed **read-only** catalogue. It can never trigger an action.
- Unknown tool names are ignored and arguments are type-checked.
- Every question and tool call is audited.
- Without an LLM it answers deterministically from the same tools, still cited.

### W3 - A phishing case end to end (5 min)

**Click:** Cases → *"Reported: Action required: your password expires today"*.
**Say:** "A user reported this email. The platform decomposed it, analysed it, checked every tool for who else got
it, who clicked, and whether any device or account shows compromise."
**Point at, top to bottom:**
1. **Verdict and confidence.** Malicious, from the deterministic analyser: look-alike sender domain,
   DMARC fail, credential lure, threat-intel hits.
2. **Assessment.** Hover any E-number to see the exact evidence row.
3. **Facts vs inferences**, listed separately.
4. **Campaign scope:** 8 recipients across 2 message variants (Defender for Office 365 campaign search).
5. **Control disagreement:** Defender marked the mail clean while Avanan missed it. That is a finding in itself.
6. **User impact:** Jane clicked, Priya's click was blocked, and Raj's copy was already moved by the admin.
7. **MITRE ATT&CK** techniques, each with its basis.
8. **Recommended actions**, with blast radius, reversibility, autonomy level and four-eyes. *Nothing has run.*
9. The **Timeline** across tools, and the **Audit trail** for this case.
**Justify the verdict:** "It's a weighted, explainable signal model - not a black box. The score is the sum of
named signals, each with its evidence, and the thresholds are fixed (§6.3)."

### W4 - Attack story (5 min) - the headline feature

**Click:** on the case, **Attack story**.
**Say:** "No single tool can show you this. The platform reconstructed the attack from five related cases and eight
tools into one chain."
**Point at:**
- **Assessment chip:** *Confirmed compromise, high confidence - "7 kill-chain stages reached (1 more blocked),
  corroborated by 7 tools; benign explanations rejected."*
- **Kill chain row:** each ATT&CK tactic is *Observed*, *Blocked*, *Checked - none*, or *Blind*. Privilege
  escalation shows **Blocked**: the elevation attempt was denied.
- **What happened:** 12 steps in time order from 09:02 to 09:45. Each shows technique, tools, outcome, and a
  confidence with its reason ("corroborated by 2 tools", "single source"). Each step cites the stored events.
- **Benign explanations tested:** "user travelling / VPN" is rejected (anonymiser IP, normal sign-ins from India),
  and so is "legitimate admin script" (payload came from the phishing domain). "Normal duties" is *unlikely*:
  confirm with the secret owner.
- **Gaps:** "No evidence of exfiltration - checked CrowdStrike, Umbrella." That is different from "we couldn't
  see it". A stage no enabled tool can observe shows as a **blind spot**.
- **Blast radius:** 8 users received, 1 interacted, 1 host, and the privileged secret SAP-Prod-Finance-Service.
- **Response plan:** contain → preserve → eradicate → recover → communicate. Tick the actions and *Approve
  selected*. Each still goes through policy and four-eyes, and copies from related cases are merged into one row
  and approved together.

**Deep analysis (with the LLM):** click *Run deep analysis*. It is a principal-responder review of this story:
assessment, likely objective, key findings, alternative explanations, open questions and priorities.

**Point at the guardrail line:** "*N unsupported statement(s) removed*". In real runs gpt-4.1-mini produced
statements that did not cite valid evidence, and they were removed before display. That's the system working.

**Justify:** "The story is deterministic and complete without any AI. The deep analysis only sees this evidence,
with identities pseudonymised. It must cite S#/G#/H#/B#/P#/X# ids, it can only reference real pending actions, and
if its confidence disagrees with the deterministic assessment that is flagged."

### W5 - Entity 360 (2 min)

**Click:** a user link (jane.doe) → Entity 360.
**Say:** "One person, resolved across every tool - UPN, SAM account, email address, Entra object id - with one
explainable risk score."
**Point at:**
- **Why this score:** each factor has its points, source tool and time. Activity decays with age; open exposures and open incidents count in full until closed.
- A compromise found through several phishing cases counts **once** (the detail says "seen from N phishing
  cases").
- The unified timeline; related assets; per-tool attributes.
**Justify:** "The score is a formula, not a model - §6.1. You can argue with every point."

### W6 - Approvals, governance, kill switch (3 min)

**Click:** Approvals. Approve a normal action as **Lead**. In the Analyst browser, try `endpoint.isolate`: it is
refused (four-eyes needs a second, senior approver). Then Automation policy.
**Say:** "Every action is a request evaluated by a versioned autonomy policy. By default a human approves
everything. High-impact actions need four eyes; nobody can approve their own. The kill switch halts all automation
on every replica immediately and survives restarts."
**Point at:**
- The domain filter tabs (All 34 = Incident 15 + Phishing 16 + Vulnerability 3).
- The policy column (L2 recommend, four-eyes).
- On the Policy screen: levels, Reversible flags, "Pending policy changes - proposer cannot approve".

### W7 - Vulnerabilities and cloud posture (4 min)

**Click:** Vulnerabilities → ask *"which internet facing hosts have KEV vulnerabilities?"* → Cloud posture →
*Mark fixed* → *Validate*.
**Say:** "Four scanners report the same host differently. The platform resolves them to one record per host and
CVE, prioritises on exploitability and exposure - not raw CVSS - routes each to its owner with an SLA, and checks
the fix against the scanner before accepting a closure."
**Point at:**
- "Seen by rapid7, crowdstrike, wiz, defender_endpoint" on one finding.
- P1/P2 bands, the owner team and SLA dates, the asset match rate.
- **Coverage gaps**, e.g. PRIYA-LT07 has no EDR. That's a laptop seen only by DNS, and a real gap. Cloud storage
  is correctly *not* listed: it can't run an agent.
- In Cloud posture: marking an item fixed while Wiz still reports it produces a **false closure**, caught by
  validation.
**Justify the priority:** §6.2 has the formula.

### W8 - Coverage, shadow IT, supplier risk (3 min)

- **ATT&CK coverage:** what the *enabled* tools can detect (full/partial), what has fired, priority blind spots,
  and techniques that depend on a single tool ("one tool down = blind").
- **Shadow IT:** unsanctioned services from Umbrella DNS (AnyDesk high risk; WeTransfer, DeepSeek medium). The
  category counts are DNS requests. Rows are aggregated, never stored.
- **Supplier risk:** Krishna Logistics shows account compromise (a message authenticated by their real domain
  asking to change bank details), a look-alike domain `krishna-logistlcs.com` (edit distance 1), and payment
  diversion. Microsoft impersonation also appears.
**Say:** "Supplier fraud is where the money goes - the platform treats a key supplier's look-alike exactly like a
look-alike of your own domain."

### W9 - Reports: standard and described in words (3 min)

**Click:** Reports. Show the gallery of seven standard reports. Type *"A one-page board brief on phishing and
supplier risk this quarter, as slides"* → **Plan report** → review → **Generate** → download the PowerPoint.
**Say:** "Standard reports are preconfigured. Anything else can be asked for in words. The system plans sections
only from a catalogue of 16 data sources, shows you the plan first, computes every figure in code, and has the
model write the narrative from those figures. A sentence that doesn't cite a figure - or states a number that
isn't in its figures - is removed."
**Point at:**
- "planned by the LLM (catalogue sources only)".
- Each section's "Figures (F1…)" list next to the narrative.
- "Narrative: LLM (azure_foundry), grounded on computed facts".
- *Save as template*.
**Justify:**
- Reports are limited to the reader's data scope: a vulnerability-only analyst gets only vulnerability sections,
  with scoped counts.
- Reports are audited, and encrypted on disk.

### W10 - Audit, access, compliance (as Auditor) (2 min)

**Click:** Audit log ("Chain verified · N records") → Access (roles, service accounts - "can never approve
actions"; the key is shown once) → sign in as **Auditor** → Reports → *Generate pack*.
**Say:** "Here is the proof trail. The compliance pack tests the controls from the records themselves: audit
integrity, four-eyes approvals, policy change control, MFA, LLM governance, encryption and retention, kill
switch, integration freshness."

### W11 - Integrations (1 min)

**Click:** Integrations.
**Say:** "Twenty connectors, each with a Test button that authenticates and reads one page, and freshness checked
against each stream's expected cadence. Here they're in fake mode. In your environment each is switched to live
with its own least-privilege service principal."
**Point at:** the scheduled jobs (retries with backoff; dead letter after 3 failures raises an alert).

### W12 - "Is this hard-coded to the demo?" (1 min, on request)

```bash
python scripts/rename_estate.py out/          # the whole estate as "Northwind Labs"
SOC_FIXTURES_DIR=out/fixtures python -m soc_platform serve
```

**Say:** "Every workflow, the attack story and all seven standard reports produce structurally identical results on
a completely renamed organisation - different domain, people, hosts, IP plan, phishing infrastructure, secrets,
suppliers - and no original name leaks into any output. That's an automated test (§9)."

---

## 6. How each result is produced

Use these when someone asks "how do you get that number?". Every one is deterministic and reproducible.

### 6.1 Risk score per user and host

- **Formula:** score = 100 × (1 − e^(−Σ decayed weights / 60)). The score is rounded to whole points and
  saturates towards 100, so one noisy signal can't max it out.
- **Decay:** each factor halves every **7 days**: weight × 0.5^(age / 7 days).
  - **Activity** (alerts, sign-ins, clicks, DNS hits) decays.
  - **What is still open does not decay:** KEV and priority vulnerabilities and open incidents count in full until
    they are closed. An unpatched host does not "become safe" by waiting.
  - **Amplifiers** (privileged user at risk, no EDR on a host with activity) fade with the activity that triggered
    them.
  - "Now" is the latest observation in the data. If every feed stops, scores freeze rather than fall to zero, and
    the stale connectors raise the alarm.
- **Bands:** critical ≥ 80, high ≥ 60, medium ≥ 30, otherwise low.
- **Main weights:**

  | Signal | Weight |
  |---|---|
  | deception hit | 50 |
  | phishing identity compromise (once per person) | 30 |
  | risky sign-in (high / medium) | 30 / 15 |
  | alert by severity (critical / high / medium / low) | 40 / 25 / 10 / 3 |
  | phishing click | 20 |
  | privileged credential access | 15 |
  | KEV exposure | 15 |
  | malicious destination reached | 12 |
  | privileged user at risk | 10 |
  | elevation denied | 8 |
  | no EDR on a machine | 5 (machines only - never cloud storage) |
  | phishing recipient | 4 |
  | open incident | half its severity weight |

- **Rules:** each case counts once per entity, however many roles the entity has in it. Decoys (Canary devices)
  are sensors, not assets, so they're never scored.
- **Justify:** "Every point is a row in 'Why this score' with its source. It's tunable in one place and fully
  auditable. A model-based score couldn't be argued with."

### 6.2 Vulnerability priority (P1-P4) and SLA

- **Score:** 0.30 × CVSS/10 + 0.25 × EPSS + 0.20 if CISA KEV + 0.10 if internet-exposed + 0.15 × asset
  criticality. Criticality weights: critical 1.0, high 0.75, medium 0.4, low 0.1.
- **Bands:** P1 if score ≥ 0.65 **or** (KEV and internet-exposed); P2 ≥ 0.45; P3 ≥ 0.25; otherwise P4.
- **SLA:** P1 7 days, P2 15, P3 30, P4 90, counted from first seen. KEV always gets the P1 SLA.
- **CISA KEV due date:** CISA's "due date" is a US federal deadline, so it's shown for reference and never used as
  our SLA.
- **Consolidation:** one finding per host and CVE across Rapid7, CrowdStrike, Wiz and Defender, after entity
  resolution.
- **Justify:** "CVSS says how bad a bug could be; EPSS and KEV say whether it's being exploited; exposure and
  criticality say whether it matters here. Each factor is shown next to the finding."

### 6.3 Phishing verdict

- **Signals:** a sum of named, weighted signals from header, URL, content, attachment and threat intel, for
  example look-alike sender or URL domain, DMARC/DKIM failures, credential lure, urgency, bank-detail change and
  intel hits. Strong authentication or an internal authenticated sender subtract weight. The score is clamped to
  0-1.
- **Thresholds:** **malicious** if score ≥ 0.70, or intel says malicious and score ≥ 0.50. **Suspicious** if
  score ≥ 0.35. **Spam** if bulk or urgency without phishing signals. Otherwise **safe**.
- **Auto-close:** clear-safe and clear-spam reports with confidence ≥ 0.7 are closed and the reporter is answered.
  10 % are sampled for analyst QA, chosen deterministically by hashing.
- **Optional ML engine:** a 7-agent ML swarm (content, URL, header, attachment/sandbox, threat intel, user
  behaviour, and so on). Its models are verified by SHA-256 manifest before loading.
- **Labelled corpus result:** 100 % detection, 0 % false positives on 20 messages. **Say:** "That's a regression
  check, not an accuracy claim - accuracy is measured in shadow mode on your own reported mail."

### 6.4 Incident severity and confidence

- **Base:** the alert's own severity.
- **Raised to critical:** a deception hit.
- **Plus one level:** KEV exposure on the host.
- **At least high:** 3 or more corroborating dimensions (deception, identity, privileged access, endpoint, threat
  intel, DNS, exposure).
- **Confidence:** 0.35 + 0.10 per dimension, capped at 0.95.
- **Verdict:** true positive if severity ≥ high and confidence ≥ 0.6; needs review at medium; otherwise likely
  benign.
- **MITRE:** techniques come from alert metadata plus evidence rules. For example, a deception token touched maps
  to T1039, an email forwarding rule to T1114.003, a risky sign-in to T1078, and a secret copied to T1555.

### 6.5 Entity resolution (the hardest problem)

- **Deterministic keys first:** vendor ids, serial, FQDN, UPN/SAM/aliases.
- **Then a scored fuzzy match:** hostname, IP within a time window, OS.
- **Then the unresolved queue**, then an analyst override.
- **Vendor ids are conflict keys:** two different CrowdStrike AIDs are never merged. Cloned VMs share serial
  numbers, and they caused a real bug found in testing.
- **Built-in accounts** (SYSTEM, root, `HOST$`) never become people.
- **Stress tests:** 0 false merges on 400 hosts and on 300 people with 6 naming conventions in random order.
- **Justify:** "Wrong merges route alerts and tickets to the wrong people and can't be undone safely. Splits are
  recoverable. So the system prefers a split and a queue item over a guess."

### 6.6 Attack story

1. **Scope:** the principals of the case (user, host), plus related cases one hop away.
2. **Classify:** each stored event is mapped to an ATT&CK tactic, including phishing milestones (delivery, click,
   IOC activity, inbox rule, new device).
3. **Steps:** events of the same stage within 15 minutes are grouped into one step. Confidence is high when 2+
   tools corroborate or the detection is critical-severity, otherwise medium ("single source").
4. **Gaps:** for each tactic with no evidence, the tools that could have seen it are listed. If none can, it's a
   **blind spot**.
5. **Hypotheses:** benign explanations are tested against specific evidence and marked rejected, unlikely or
   plausible.
6. **Blast radius:** recipients, interacted users, hosts, secrets, related cases.
7. **Plan:** the pending actions, phased. Duplicates from related cases are merged, and approving the row
   approves them all.
8. **Assessment:**
   - *Confirmed compromise:* 3+ stages reached, a "deep" stage (persistence, privilege escalation, credential
     access, discovery, lateral movement, collection, exfiltration or impact), 3+ tools, and no benign
     explanation still plausible.
   - *Likely compromise:* a deep stage or 2+ stages.
   - *Attempt blocked:* every step was blocked.
   - Otherwise *suspicious activity*.

   "Reached" counts only stages that succeeded; blocked stages are reported separately.
9. **Fingerprint:** the same attack gives the same story from any related case, and deep analysis is cached per
   fingerprint.

### 6.7 Correlation rules (12) and operational alerts (4)

| Rule | What it raises |
|---|---|
| Phishing → endpoint → identity chain | Click followed by execution and identity compromise |
| Privileged access after compromise | Secret viewed/copied after compromise indicators |
| Deception corroborated | Canary hit plus other telemetry |
| Exposed host under attack | KEV / P1 vulnerability on an attacked host |
| Attacked host without EDR | A machine under attack with no EDR |
| Control gap | A confirmed-bad destination still reachable |
| Repeat clicker | A user clicked in more than one campaign |
| New KEV exposure | A newly KEV-listed CVE present on assets |
| Shared infrastructure | One indicator touching several users/hosts |
| High entity risk | Fused risk high/critical across 3+ dimensions |
| Supplier risk | Vendor compromise, impersonation, payment diversion |
| Model drift | Verdict quality drifting against analyst decisions |

Operational alerts:
- a scheduled job dead-lettered after 3 failures
- break-glass access used
- the platform self-check failing (§6.9)
- the monthly LLM token budget at 80 % or exhausted

### 6.8 Reports

- **Catalogue:** 16 data sources computed in code: overview, vulnerability posture, top vulnerabilities, cloud
  misconfigurations, phishing, supplier risk, incidents, attack stories, incident narrative, correlated findings,
  risk, detection coverage, shadow IT, compliance, verdict quality, integration health.
- **Standard reports (7):** board monthly (PowerPoint), CISO weekly, VM weekly, phishing monthly, post-incident
  (per case), compliance quarterly, SOC daily.
- **Prompted reports:** the planner is the LLM when configured, otherwise keyword rules. Unknown sources are
  rejected.
- **Narrative:** each section's figures are numbered F1..Fn. Uncited sentences, invented ids and unsupported
  figures are removed. With no LLM, a deterministic writer is used.
- **Output:** Word or PowerPoint, encrypted at rest, audited.
- **Access:** download re-checks that the reader's scope covers every domain in the report *and* the builder's
  scope. Case reports need access to the case. Compliance data needs the evidence-export permission.

### 6.9 Platform self-check

Every hour the platform recomputes each figure that appears in more than one place - awaiting approvals, open
cases, open findings, open vulnerabilities - through each independent code path (dashboard, database count,
analyst tool, report builder) and compares them. It also resolves every stored reference (case links, evidence,
actions, campaigns, insight entities, citations), checks nothing that must be unique is duplicated (one case per
reported email, no duplicate active campaigns), and verifies the audit chain. A failure raises a *Platform
self-check* finding. **Say:** "The platform doesn't just show numbers; it proves every hour that they agree." 

---

## 7. The AI: what it does, what it may not do, and the guardrails

**Where the LLM is used:**
- Narratives: incident summary, phishing explanation, insight narrative, situation brief, analyst answers.
- The analyst's tool *planning*.
- Deep analysis.
- Report planning and report narrative.

**Where it is never used:** verdicts, severities, scores, priorities, SLAs, counts, action decisions, approvals.

**Guardrails (each is tested):**
1. **Evidence-only prompts:** the model sees only retrieved evidence, with ids.
2. **Citation validation:** a statement without a valid evidence id is dropped. Invented ids are dropped and counted.
3. **Numeric fidelity:** a statement that states a figure (count, score, percentage, time) not present in the
   evidence it cites is dropped. Summary sentences are checked against all evidence. Identifiers - host names,
   IPs, CVE ids, dates - are not treated as figures. *Added after the real-model review found a stale "94/100".*
4. **Pseudonymisation:** internal users, names, phone numbers and national ids are replaced with tokens before the
   prompt leaves, and restored after, including when the model drops the brackets from a token (a real gpt-4.1-mini
   behaviour, now tested).
5. **Approved endpoints only:** an endpoint not on `SOC_LLM_APPROVED_ENDPOINTS` is refused (fail closed).
6. **Pinned model:** a response from a different model version is logged as a mismatch.
7. **Token budget:** monthly budget with alerts at 80 %. When exceeded, calls stop and the deterministic path takes
   over.
8. **Logging:** every prompt (redacted) and response is stored, with retention.
9. **Deep analysis specifics:** priorities may only reference real pending actions or "manual". Disagreement with
   the deterministic assessment is flagged. Cached per evidence fingerprint.
10. **The analyst's tools are read-only.** The model can never cause an action.

**The provider:** Azure AI Foundry (`azure_foundry`), gpt-4.1-mini, via the Azure OpenAI v1 API (`api-key` header).
Also supported: Azure OpenAI deployments, Anthropic Claude, any OpenAI-compatible endpoint (including self-hosted
vLLM or Ollama for tenant-resident processing).

**Cost in practice (measured, gpt-4.1-mini):** an incident summary costs about $0.002, a phishing explanation $0.001,
an analyst question $0.001 and a deep analysis $0.004. Per month that is about **$5** for a small SOC, **$26** for a
mid-size SOC and **$150** for a large one. Tokens grow with the number of incidents, reports and questions, not with
organisation size. Auto-closed benign mail costs nothing, and the brief is cached. The default budget is 50 M tokens
a month, with a finding raised at 80 % and 100 %. Full detail: [LLM_TOKENS_AND_COST.md](LLM_TOKENS_AND_COST.md).

**Say:** "The AI makes the platform easier to read, not more authoritative. Turn it off and every number, verdict
and recommendation is identical."

---

## 8. Security, data and governance

- **Identity:**
  - Entra ID SSO (RS256 against the tenant's JWKS).
  - Step-up MFA for approvals, rollback, policy, kill switch and access management.
  - Service-account keys: hashed, expiring, and never allowed to approve.
  - Sealed break-glass (only its hash is configured; every use is audited and alerted).
  - Token and session revocation.
- **Authorisation:**
  - 5 roles (analyst, lead, admin, automation admin, auditor).
  - Domain scoping (phishing / incident / vulnerability); cross-domain views need all-domain scope. Out-of-scope
    records answer 404.
  - Separation of duties: no self-approval of four-eyes actions, policies, exceptions or grants.
- **Automation safety:** L0 observe · L1 enrich · L2 recommend (default) · L3 approve · L4 autonomous. Destructive
  actions are never autonomous. VIP, blast-radius and four-eyes gates apply. The kill switch is durable. Actions
  are idempotent, pre-conditions are re-checked at execution, and actions can be rolled back.
- **Data:**
  - Raw payloads, reported emails, generated reports and evidence packs are encrypted at rest (Fernet, key
    rotation supported; mandatory in production).
  - Retention with legal hold for open cases.
  - Attack stories are rebuilt on demand, never stored.
  - Where each kind of data lives: [OPERATIONS.md](OPERATIONS.md).
- **Audit:**
  - Append-only (the ORM refuses update/delete) and SHA-256 hash-chained; `/api/v1/audit/verify`.
  - Grant the database role INSERT/SELECT only.
  - An access log in addition.
- **Web:** strict CSP (no inline script), security headers, per-client rate limiting, request-size cap on the
  byte stream, input validation.
- **Code:** bandit 0 high / 0 medium, pip-audit clean, secret scan before every push.

---

## 9. Evidence that it works

| Check | Result |
|---|---|
| Platform test suite | 264 passed on SQLite (with PostgreSQL's rules enforced) and 265 on PostgreSQL 16 (one test runs on PostgreSQL only), plus opt-in live tests |
| Live LLM suite (Azure AI Foundry, gpt-4.1-mini) | 9 passed: incident summaries, phishing explanations, analyst answers, deep analysis, all 7 standard reports, planner, every call OK on the pinned model, no pseudonym tokens reaching analysts |
| Live public feeds (NVD, EPSS, CISA KEV) | passed |
| Phishing ML engine suite | 205 passed |
| Feature → test mapping | **89 of 89** features verified, each mapped to the tests that prove it, run with the live LLM and live feeds ([FEATURE_VERIFICATION.md](FEATURE_VERIFICATION.md)) |
| Generalisation | whole platform on a renamed organisation: identical results, 0 leaked names |
| Browser tour | real server + Chrome, 4 roles, every screen, light and dark, layout audited at 1440/1280/1024/768 px: 0 errors, 0 clipped or overflowing elements, no table needing sideways scroll at desktop width; axe-core accessibility scan (WCAG 2.1 A/AA) with 0 findings; stored-XSS probe with nothing executed |
| Stress tests | 0 false merges (400 hosts; 300 people) |
| Output review | every model output of a full run audited for figures not in its evidence (see below) |
| Consistency suite | the same figure compared across every surface (dashboards, lists, badges, brief, analyst tools, report facts, generated Word documents); every pipeline and job run twice with zero change; LLM on vs off with identical figures; every GET route × 7 roles (no errors, no leaks, explicit UTC); every write route fuzzed; every stored reference resolved |
| Screen vs API | the browser tour reads every KPI, badge and tab count off the rendered screens and compares it with the API |
| Penetration tests | 17 attack groups (authentication, privilege, cross-domain, injection, prompt injection, traversal, uploads, leakage, brute force, races, production surface, Entra token forgery): all refused (§16) |
| Property-based fuzzing | 11 rules checked against thousands of generated inputs (redaction, guardrail, timestamps, e-mail parser) |
| Time-travel tests | clock moved forward on 3 estates: SLAs, budget roll-over, retention, risk decay all correct |
| Code quality | ruff: 0 findings across the repository; bandit: 0 medium/high; pip-audit and npm audit: no known vulnerabilities |

**The output review, and what it caught.** All screens and model outputs from a full run with the real LLM were
reviewed and cross-checked against the database. Every issue was fixed with a regression test:

- **Stale figure:** an insight titled 100/100 carried a narrative written when the score was 94/100. The model is
  no longer given the time-decayed score, and narratives are rewritten when the finding's evidence or severity
  changes.
- **Capped count:** the situation brief said "30 pending approvals" when 34 were open (a 30-row list was being
  counted). All counts are now true totals, and the same was fixed for insight and case counts.
- **Ambiguous label:** a report said "seven phishing emails" because the fact was labelled "Reported emails". The
  labels are now unambiguous ("all verdicts, not all phishing"), and the numeric-fidelity guardrail was added.
- **Placeholder leak:** "User USER_1…" appeared because the model dropped the brackets of a pseudonym token, so it
  wasn't restored. It's fixed; zero placeholders in a full run.
- **Double-counted risk:** "identity compromise" was counted 3×, and some cases twice. Each case now counts once,
  and one compromise counts once.
- **Storage bucket as an EDR gap:** a storage account was listed as "No EDR" and scored for it. Only machines are
  expected to run an agent now.
- **Two readings of one count:** the kill-chain count differed between the header (7) and a tile (8), because one
  counted blocked stages. Both now say "7 reached · 1 blocked".
- **Rows vs actions:** "19 actions awaiting approval" counted rows, not actions. It now counts actions.
- **Presentation:** a secret shown as "42" now shows its name. Action buttons were clipped at desktop widths.
  Category counts were unlabelled.
- **Live NVD returned nothing:** found by the live public-feed test during final verification. NVD now answers
  single-CVE lookups with an empty page unless the page size is explicit, so live mode would silently have lacked
  NVD scores (prioritisation falls back to scanner CVSS). The connector now requests the page explicitly.

**Consistency round (testing from every angle).** A second review compared every figure across every surface,
re-ran every pipeline, swept every route as every role and fuzzed every write. It found and fixed:
- **Duplicates on re-run:** pulling the reporting mailbox again created a second case for the same email (so
  recipients' risk doubled), and a second campaign for the same CVE notified owners twice. Both are idempotent now,
  and the self-check watches for it.
- **Cross-domain exposure:** a phishing-only analyst could read the whole audit log and the access log, including
  other domains' case ids. Both are scoped now.
- **Crashes on bad input:** an unknown incident or campaign id answered a server error instead of 404, and the
  incident endpoint accepted a phishing case.
- **Same data, different values:** a case page listed 9 actions while the actions API listed 4 (shared actions).
  Badge and tab counts were derived from a 500-row list, and timestamps carried no timezone.
- **Run-to-run differences:** the QA sample of auto-closed reports changed between runs; it is stable now.
- **An intermittent guardrail hole:** digits inside random ids could make an invented number look "supported".

**Say, if asked "how do you know the AI isn't making things up?":** "We audited every model output of a full run
against its evidence, found the discrepancies above, traced each to our code - not the model - fixed them, and
added a guardrail that removes any sentence stating a figure that isn't in its evidence."

---

## 10. Limitations - say these first

1. **Not yet run against the client's tenants.** Connectors are built to each vendor's documented API and
   exercised on vendor-shaped fixtures through the same code. Live behaviour needs credentials: each is connected
   and tested (Integrations → Test) in the client's environment.
2. **Accuracy and latency are not proven on the client's data.** The corpus and stress tests are regression
   checks. Real accuracy comes from shadow mode against the client's own analyst decisions, which the platform
   records automatically (agreement, drift).
3. **Volumes.** The architecture scales horizontally (stateless API, leased jobs, Postgres), but it has not been
   load-tested at the client's volumes.
4. **Detonation** needs an isolated analysis host (or CAPEv2 for Windows payloads). The hardening and fail-closed
   behaviour are tested; actual detonation is not run in the demo.
5. **SSO** needs an Entra app registration; token validation is tested with signed tokens.
6. **Other LLM providers:** Azure AI Foundry is verified live. Azure OpenAI deployments, Anthropic and self-hosted
   providers are tested against their request shapes with stubbed responses.
7. **Templates:** reports use generic layouts until the client's Word and PowerPoint templates are supplied (they
   plug in).
8. **Security testing is internal.** The automated penetration tests, fuzzing and XSS probe pass, but an independent
   third-party penetration test should be run in the client's environment before go-live.
9. **Accessibility** is checked automatically (WCAG 2.1 A/AA, 0 findings); a manual screen-reader review has not been
   done.
10. **Needed from the client:** API access per tool (read scopes first, dedicated service principals), an Entra app
   registration, a CMDB/ownership source, representative historical data for tuning and validation, and decisions
   on residency/deployment target. Full list: A/D/Q items in
   [REQUIREMENTS_TRACEABILITY.md](REQUIREMENTS_TRACEABILITY.md).

---

## 11. Hard questions and answers

### About the AI

| Question | Answer |
|---|---|
| What if the AI is wrong? | It doesn't decide anything. Verdicts, scores and priorities are deterministic; the model explains them and must cite evidence. Uncited statements and unsupported figures are removed, and the removal count is shown. Drift monitoring compares verdicts with analyst decisions. |
| Can it hallucinate a number into a board report? | No. Figures are computed in code and shown next to the narrative. A narrative sentence stating a figure that isn't in its cited figures is dropped. |
| Can a prompt injection in an email make it do something? | The model's output can never trigger an action; the analyst assistant can only call read-only tools. The worst case is a bad narrative, and that narrative must still cite evidence. |
| What data goes to the model? | Only the evidence needed for that task, with internal identities pseudonymised and restored afterwards. Only to an approved endpoint (fail closed), on a pinned model, every prompt logged. Nothing leaves without an LLM configured. |
| Why gpt-4.1-mini, not a bigger model? | It's cheap and fast, and the guardrails do the heavy lifting on trust. A bigger model can be used per tier (small/large) by changing a deployment name. The platform is provider-agnostic. |
| Could we run the model inside our tenant? | Yes: Azure AI Foundry in the client's subscription, or an OpenAI-compatible self-hosted model (vLLM, Ollama). |
| What does it cost? | Measured: about $5 / month for a small SOC, $26 mid-size, $150 large at gpt-4.1-mini (LLM_TOKENS_AND_COST.md). A cheaper small-tier model cuts another ~25 %. A monthly token budget with findings at 80 % and 100 % caps spend; beyond it the platform falls back to deterministic output. |

### About automation and control

| Question | Answer |
|---|---|
| Can it take actions on its own? | Only if the organisation promotes an action type in the versioned policy. That is a reviewed change, and the proposer can't approve it. Destructive actions can never be autonomous. |
| What stops a rogue admin? | Separation of duties (no self-approval of four-eyes actions, policies or grants), step-up MFA, the audit chain and the access log. |
| How do we stop everything? | The kill switch: durable, shared by every replica, audited. |
| What if an action fails half-way? | Actions are idempotent; pre-conditions are re-checked at execution; failures are recorded; reversible actions roll back through their reverse action. |

### About data, security and compliance

| Question | Answer |
|---|---|
| Where is data stored? | Postgres for records; an encrypted volume/blob store for raw payloads and reports. See OPERATIONS.md. |
| Is data encrypted? | Raw payloads, emails, reports and evidence packs are encrypted at rest (Fernet, rotation). TLS in transit. Database encryption is per the hosting platform. |
| How long is data kept? | Configurable: raw 180 days, LLM logs 180 days, access log 400 days. Open cases are on legal hold. The audit log is never pruned by the platform. |
| Can we prove to an auditor what happened? | Yes: the hash-chained audit log (verify endpoint), the audit export, and the compliance evidence pack with control tests. |
| Who can see what? | Role plus domain scope. A phishing analyst can't read incident or vulnerability data, including inside reports. |

### About integration and fit

| Question | Answer |
|---|---|
| Does it replace our SIEM/SOAR/EDR? | No. It orchestrates them through their APIs. |
| What if we change a tool? | A tool change is a connector change; the SDK makes a new connector a single module plus a manifest. |
| We don't have tool X. | Coverage and the attack story adapt: stages that no enabled tool can see show as blind spots rather than "clear". |
| Will it overload our tools' APIs? | Per-tool request budgets sized under vendor limits, caching, backoff and reconciliation. |
| How long to go live? | Per tool: provision a read-scoped service principal, configure, press Test. Governance, audit and the workflows are already built; the work is integration and validation on real data. |

### About quality and generality

| Question | Answer |
|---|---|
| Is it hard-coded to the demo data? | No. The generalisation test renames the entire organisation and requires identical results and zero leaked names (W12). |
| How was it tested? | See §16. In short: 264 platform tests, 205 engine tests, run on both SQLite and PostgreSQL; live tests (public feeds, the LLM); penetration tests; property-based fuzzing; time-travel tests; a consistency suite; a browser tour with an accessibility scan and an XSS probe; stress tests; and a feature-by-feature verification report. The platform also self-checks hourly. |
| What happens if the LLM or a tool goes down? | Nothing breaks. Connecting to the model gives up after 10 s; reading an answer after 30 s (short answers) or 120 s (long reviews). After 3 failures a circuit breaker answers from the deterministic path instantly for 60 s. Throttling is retried once. A stopped scheduler shows a banner on every screen. Every case is in FAILURE_MODES.md. |
| Is it tuned to your demo data? | No. Seeded variants (different organisations, people, machines, volumes) run through the same tests, the browser tour and the live LLM; no output mentions the demo organisation. |
| Do the numbers agree everywhere? | Yes, and it is proven continuously: the self-check recomputes each shared figure through every code path every hour, and the test suite compares them across dashboards, lists, briefs, answers, reports and the rendered screens. |
| What didn't you test? | Section 10. |

### About security testing

| Question | Answer |
|---|---|
| Has it been penetration-tested? | Internally, yes, and automatically on every test run: 17 attack groups against a local instance, plus a stored-XSS probe in a real browser (§16, SECURITY.md). It has not had an independent third-party test; that should be done in the client's environment before go-live. |
| What if someone steals a token? | Tokens expire (a token without an expiry is refused). Logout revokes the token server-side, and an admin can revoke every session of a user at once. High-impact decisions need MFA on the token. |
| Could someone forge an Entra token? | No. Production tokens are verified with RS256 against the tenant's published keys, with audience, issuer and expiry enforced. The tests try another signing key, the wrong audience or issuer, `alg: none` and the classic algorithm-confusion attack; all are refused. |
| Can a phishing analyst see incident data? | No. Every list, record, report, audit entry and access-log entry is scoped. Asking for another domain's record by id answers "not found", which is tested for every id route. |
| Could two analysts approving at once run an action twice? | No. Tested with six simultaneous approvals: it executed once. Actions are idempotent, and the database enforces one execution. |
| Could a malicious e-mail attack the analyst's browser? | No. Everything shown is escaped. The test puts script in the subject, sender, body, link and attachment name and views it on 8 screens with the browser's CSP turned off: nothing runs. The CSP (no inline script) is a second layer in production. |
| Could a malicious e-mail make the server fetch internal URLs (SSRF)? | No. The platform never fetches links taken from e-mail content; outbound calls go only to configured vendor endpoints. |
| Could a malicious e-mail crash the analysis? | Fuzzing found three ways, and all are fixed: a hostile `From:` header (a bug in Python's own parser, now worked around), hostile MIME, and NUL characters. The parser is now fuzzed with arbitrary bytes on every run. |
| Do you depend on vulnerable packages? | pip-audit and npm audit report no known vulnerabilities. bandit reports no medium or high findings. |
| Is it accessible? | Every screen passes an automated WCAG 2.1 A/AA scan in both themes. A manual screen-reader review has not been done. |

### About the database and scale

| Question | Answer |
|---|---|
| Does it run on PostgreSQL? | Yes, that is the production engine, and the full suite runs on it. The faster SQLite runs enforce PostgreSQL's rules too, which found several production-only bugs, all now fixed (§16). |
| How big can it get? | Measured at 20,000 entities: risk ranking 0.06 s, correlation 0.09 s, a case's actions 0.005 s. The API is stateless and scales out; jobs are leased. It has not been load-tested at the client's volumes (§10). |
| What happens during an upgrade? | Start-up creates new tables and widens text columns a new release has made longer. It never narrows or drops anything automatically. |

---

## 12. Numbers to remember

| Item | Value |
|---|---|
| Connectors | 20 (live + fake mode each) |
| Workflows | 3 (phishing, incident, vulnerability) + intelligence layer |
| Correlation rules | 12 + 4 operational alerts |
| Action types under the autonomy policy | 25, default L2 (recommend) |
| Roles | 5 |
| Report data sources / standard reports | 16 / 7 |
| ATT&CK techniques in the coverage model | 56 |
| Requirements | 102 implemented and tested + 15 implemented, awaiting client data/environment, 0 blocked |
| Platform tests / engine tests | 264 SQLite, 265 PostgreSQL / 205 |
| Penetration test groups / fuzzing properties | 17 / 11, all passing |
| Features verified | 89 of 89 |
| Live LLM tests | 9, all passing on Azure AI Foundry gpt-4.1-mini |
| Stress tests | 0 false merges (400 hosts, 300 people) |
| Risk half-life / bands | 7 days / critical ≥ 80, high ≥ 60, medium ≥ 30 |
| VM SLAs | P1 7 d, P2 15 d, P3 30 d, P4 90 d (KEV → P1 SLA) |
| Phishing thresholds | malicious ≥ 0.70 (≥ 0.50 with malicious intel), suspicious ≥ 0.35; auto-close ≥ 0.7 confidence, 10 % QA sample |
| LLM cost | ~$0.002 per incident summary, ~$0.001 per question; ~$5 / $26 / $150 a month (small / mid / large SOC) |

---

## 13. If something goes wrong during a demo

| Symptom | What to do / say |
|---|---|
| A page shows a skeleton for a long time with the LLM on | The model is writing (deep analysis or report). Wait 10-20 s. Or say "this is the optional narrative - the deterministic view is already complete" and show the story. |
| Deep analysis says unavailable | No LLM configured in this session: "the story is complete without it". Or the budget is exhausted: "the platform falls back automatically". |
| An approval is refused | Probably four-eyes or self-approval: "that's the control working". Approve as a different, senior user. |
| Numbers differ from the screenshots | Time has passed: risk decays with age and SLA dates fall due. Loading the data again changes nothing (every pipeline is idempotent). Uploading extra emails adds real reports. To reset: `init-db` then `demo`. |
| A connector shows stale or error | In fake mode, re-run the jobs from Integrations. In live mode it's the monitoring working: "freshness is checked against each stream's cadence". |
| The server won't start | Check `.env` values (a mistyped LLM endpoint fails closed by design). Remove `SOC_LLM_*` to run deterministic. |

---

## 14. Glossary

| Term | Meaning |
|---|---|
| Evidence ids (E#, S#, F#, R#, G#, H#, B#, P#, X#) | References to stored records: evidence, story steps, report figures, tool results, gaps, hypotheses, blast radius, plan actions, exposure |
| Fact / inference | A fact is directly supported by a record; an inference is a conclusion from several facts, labelled as such |
| Four-eyes | A second, suitably senior person must approve |
| L0-L4 | Autonomy levels: observe, enrich, recommend, approve, autonomous |
| Blind spot | An ATT&CK stage that no enabled tool can observe (different from "checked, nothing found") |
| KEV | CISA Known Exploited Vulnerabilities catalogue |
| EPSS | Exploit Prediction Scoring System: probability of exploitation in the next 30 days |
| Fake mode | Connector runs on vendor-shaped fixtures through the same code as live mode |
| Shadow mode | The platform's verdicts are compared with analysts' decisions to measure agreement before any automation |
| Fingerprint | Hash of a story's evidence: the same attack gives the same story and cached deep analysis |
| Pseudonymisation | Internal identities replaced with tokens before a prompt leaves the platform, restored in the answer |

---

## 15. Reference: every component in depth

Use this section when someone drills into a detail. Every fact here is taken from the code.

### 15.1 The 20 connectors

Every connector runs on the same SDK:
- per-tool request budgets under the vendor's rate limits
- backoff and retry
- cursors, and reconciliation of counts against the source
- per-record fault isolation: one malformed record is set aside, the rest of the page is kept
- freshness checked against each stream's expected cadence

Each connector has a *live* mode (the vendor API) and a *fake* mode (vendor-shaped fixtures through the same parsing
code).

| Connector | Category | What it pulls | What the platform uses it for | Actions it can perform |
|---|---|---|---|---|
| CrowdStrike Falcon | EDR | alerts, hosts, Spotlight vulnerabilities | Endpoint detections; host identity (agent id, serial, IP); vulnerability findings | Network containment and release; read-only forensic collection |
| Microsoft Defender for Endpoint | EDR | alerts, machines, vulnerabilities | Same as CrowdStrike, second source | Isolation and release; antivirus scan; investigation package; custom indicators (block and unblock) |
| Microsoft Defender for Office 365 (+ Exchange admin) | Email | user-reported messages, email alerts; campaign search, clicks and post-delivery events through advanced hunting | The phishing intake, campaign scope, who clicked, what the admin already did | Tag; tenant-wide purge and restore; block and unblock sender; reporter feedback; notification e-mail |
| Check Point Avanan | Email | security events | A second email-control verdict ("control disagreement") | Quarantine and restore |
| Microsoft Entra ID | Identity | users, sign-ins, risky users, risk detections, directory audits | Identity resolution; risky sign-ins; MFA methods; inbox rules; devices | Revoke sessions; force password reset; disable and re-enable; mark compromised |
| Cisco Umbrella | DNS | DNS activity | Malicious destinations reached; shadow IT | Block and unblock a domain |
| Thinkst Canary | Deception | incidents, devices | High-fidelity deception hits (decoys are sensors, never scored as assets) | Acknowledge |
| Delinea Secret Server | PAM | secret audit events | Privileged credential viewed or copied | Rotate a secret |
| Delinea Privilege Manager | PAM | elevation events | Elevation allowed or denied | - |
| Rapid7 InsightVM | Vulnerability | assets, findings (API or CSV export) | Findings and asset inventory | - |
| Wiz | Cloud | resources, vulnerabilities, issues | Cloud vulnerabilities, internet exposure, misconfigurations | - |
| NVD | Intel | recent CVEs; per-CVE lookup | CVSS and description | - |
| FIRST EPSS | Intel | per-CVE lookup | Probability of exploitation in 30 days | - |
| CISA KEV | Intel | catalogue | Known-exploited flag | - |
| Threat-intel fusion | Intel | lookups against VirusTotal, AbuseIPDB, AlienVault OTX, URLhaus, ThreatFox, MalwareBazaar, GreyNoise, Shodan | One fused verdict per indicator, with each source's answer attributed | - |
| ServiceNow | ITSM / CMDB | tickets, CMDB | Owners, support groups, criticality; ticket status | Create and update tickets |
| Jira | ITSM | tickets | Ticket status | Create and update tickets |
| CMDB CSV | CMDB | CSV file | Owners where there is no CMDB API | - |
| Microsoft Sentinel | SIEM | incidents | An additional alert source | - |
| Generic SIEM webhook | SIEM | alerts pushed to `POST /api/v1/ingest/alerts` | Any other tool that can send a webhook | - |

**Say, if asked "what if a tool is down?":** "The lookup reports the source as *unavailable* - never as clean - and
the investigation continues with the others. The Integrations screen shows it as stale."

### 15.2 The action catalogue and the autonomy policy

Every change to a tool is an **action request**. It is evaluated by the active, versioned autonomy policy, then
recommended, sent for approval or blocked, and recorded in the audit log. Defaults as shipped:

| Action | Tool | Default level | Blast-radius limit | Four-eyes | Reverse action |
|---|---|---|---|---|---|
| `email.tag` | Defender for Office 365 | L2 | 25 | - | - |
| `email.campaign_purge` | Defender for Office 365 | L2 | 200 | - | `email.restore` |
| `email.block_sender` | Defender for Office 365 | L2 | 25 | - | `email.unblock_sender` |
| `email.gateway_quarantine` | Avanan | L2 | 25 | - | `email.gateway_restore` |
| `email.reporter_feedback` | Defender for Office 365 | L2 | 25 | - | - |
| `notify.email` | Defender for Office 365 | L2 | 25 | - | - |
| `identity.revoke_sessions` | Entra ID | L2 | 10 | - | - |
| `identity.reset_password` | Entra ID | L2 | 10 | - | - |
| `identity.disable_account` | Entra ID | L2 | 3 | **yes** | `identity.enable_account` |
| `identity.confirm_compromised` | Entra ID | L2 | 25 | - | - |
| `endpoint.isolate` | CrowdStrike / Defender | L2 | 5 | **yes** | `endpoint.release` |
| `endpoint.scan`, `endpoint.collect_forensics` | Defender / CrowdStrike | L2 | 25 | - | - |
| `dns.block_domain` | Umbrella | L2 | 25 | - | `dns.unblock_domain` |
| `indicator.block` | Defender for Endpoint | L2 | 25 | - | `indicator.unblock` |
| `pam.rotate_secret` | Secret Server | L2 | 5 | - | - |
| `ticket.create`, `ticket.update` | ServiceNow / Jira | L2 | 25 | - | - |
| `canary.acknowledge` | Canary | L2 | 25 | - | - |

**Levels:** L0 observe · L1 enrich · **L2 recommend (default for every action)** · L3 approve · L4 autonomous.

**How a request is decided, in order:**
1. A failed pre-condition blocks it (for example, isolating a host with no EDR agent).
2. More targets than the hard limit (5,000) blocks it.
3. The kill switch caps it at L3: approval required.
4. A destructive action type is capped at L3, so it is never autonomous.
5. Any VIP or critical-tagged target caps it at L3 and marks it high-impact.
6. More targets than the action's blast-radius limit caps it at L3 and marks it high-impact.
7. Four-eyes: a second person must approve, and it must be someone with `approve_high_impact` (a lead).

The reasons are always shown next to the action, even when no cap applied.

**At execution** the pre-conditions are re-checked, the action is idempotent (the same request never runs twice),
and the result is recorded.
- A reversible action can be rolled back through its reverse action. Rollback needs the `rollback_action` permission.
- Nobody approves their own request.
- API-key (service) principals can never approve.

**Changing the policy:** an automation admin *proposes* a new version, and a different person with `approve_policy`
(a lead) *approves* it. Every version is kept.

### 15.3 Roles and permissions

| Role | Permissions |
|---|---|
| Analyst | read, investigate, request actions, approve (non-high-impact) actions, resolve entities, read audit |
| Lead | everything an analyst has, plus approve high-impact actions, approve policy, roll back actions, kill switch, export evidence |
| Automation admin | read, read audit, manage connectors, propose policy, kill switch |
| Admin | read, read audit, manage access (roles, service accounts, session revocation), manage connectors, kill switch, export evidence |
| Auditor | read, read audit, export evidence |

- **Domain scope:** any role can be limited to phishing, incident and/or vulnerability data. Records outside the
  scope answer "not found", including inside reports, the audit log and the access log.
- **Step-up MFA:** approvals, rollback, policy approval, the kill switch and access management need a token that
  shows MFA. This is on by default in production.
- **Service accounts:** API keys that can hold only analyst, auditor or automation-admin roles and can never approve.
  They are hashed at rest, shown once, and expire.
- **Break-glass:** a sealed emergency credential. Only its SHA-256 is configured. Every use is audited and raises a
  critical finding.

### 15.4 Scheduled jobs

| Job | Default interval | What it does |
|---|---|---|
| `phishing` | 2 minutes | Pull newly reported e-mails and analyse them |
| `incident` | 5 minutes | Ingest alerts, cluster them into incidents, investigate |
| `intelligence` | 10 minutes | Re-correlate: risk, 12 rules, brief |
| `vulnerability` | 6 hours | Refresh the four scanners, prioritise, update SLAs |
| `self_check` | 1 hour | Prove every shared figure agrees everywhere; check the LLM budget |
| `follow_up` | daily | Chase unacknowledged remediation plans; sync tickets; catch false closures |
| `daily_report` | daily | The SOC daily report |
| `retention` | daily | Prune old raw payloads, closed-case e-mails and LLM prompt text; keep legal holds |

Every run is recorded. A run that fails is retried with backoff; after 3 failed runs it is **dead-lettered** and a
finding is raised. Any job can be replayed from Integrations. Several scheduler replicas are safe, because each job
takes a database lease. If the scheduler stops, every screen shows a "Scheduler stopped" banner.

### 15.5 The data model in one paragraph

Tools send **source records** (the raw payload is kept encrypted, for evidence).
- Records resolve into **entities**: hosts, people, indicators and events. Each entity has all its **identifiers**
  from every tool, linked by **relations**.
- A **case** (phishing, incident or vulnerability) links to entities with a role, and holds **evidence** rows (E#).
- Recommended changes are **action requests**, decided by the **policy version** in force.
- Analyst **dispositions** feed shadow-mode agreement and drift monitoring.
- Cross-domain **insights** come from the correlation rules.
- The vulnerability domain adds consolidated **findings**, **remediation campaigns** with per-team **action plans**,
  **exceptions**, a **risk register** and **cloud misconfigurations**.
- Reported e-mails are **submissions**.

Everything that changes state writes an **audit record** in a hash chain. Every request writes an **access-log** row,
and every model call writes an **LLM call** row.

### 15.6 Screen by screen

| Screen | What it shows | Where the numbers come from | Who |
|---|---|---|---|
| **Overview** | Open cases, awaiting approval, automation rate, median time to close, open insights, open vulnerabilities; new cases per day; open cases by severity; top insights; riskiest users and hosts; data quality; integrations; enrichment latency; verdict quality | Cases, actions, insights and findings counted in the database. Awaiting approval counts the whole backlog, not a time window. Scoped to the viewer's domains. | All |
| **Intelligence** | Situation brief; ask the analyst; risk by user and host; correlated findings with next steps | Brief facts computed in code (cached while unchanged); answers from read-only tools; risk from the engine (§6.1) | All-domain scope (it spans every domain) |
| **Cases** | Every case with domain, severity, verdict, status; domain tabs with true totals | Cases table; tab counts from the summary endpoint | All (scoped) |
| **Case** | Assessment with E# citations, facts vs inferences; evidence; cross-domain context; entities; recommended actions with policy reasons; analyst decision; timeline; audit trail; links to the Attack story and a case report | Evidence rows and the case assessment | All (scoped) |
| **Attack story** | Kill-chain stages, steps, users reached, hosts, privileged secrets, gaps checked; kill-chain row; what happened; response plan (bulk approve); blast radius; benign explanations; gaps; exposure; deep analysis | Rebuilt on demand from stored records (§6.6), never stored | All (scoped) |
| **Entity 360** | Why this score; timeline across tools; identifiers; cases; insights; vulnerabilities; related entities; per-tool attributes | The context store and the risk engine | All (records outside the viewer's scope answer 404) |
| **Approvals** | Every action awaiting a decision, with targets, rationale and policy; domain tabs | Action requests, scoped to the viewer | All can view; approving needs `approve_action` (high-impact: `approve_high_impact`) |
| **Phishing** | Reported, auto-closed, campaigns, repeat clickers, median time to containment; verdict mix; users who clicked; analyse a message (upload) | Submissions. Time to containment runs from report to the first executed purge, isolation or session revocation. | Phishing scope |
| **Suppliers** | Supplier account compromise, look-alike domains, payment diversion, impersonation | Reported mail matched against the supplier register (`config/suppliers.yaml`) | Phishing scope |
| **Vulnerabilities** | Open findings, KEV, internet-exposed, past SLA, asset match rate; ask about exposure; coverage gaps; findings list | Consolidated findings (§6.2); the natural-language question shows the filter it generated | Vulnerability scope |
| **Cloud posture** | Open, past SLA, false closures, teams involved; misconfigurations with route / mark fixed / validate | Wiz issues through the same lifecycle as findings | Vulnerability scope |
| **ATT&CK coverage** | Weighted coverage, priority blind spots, single-source techniques, firing; the matrix; blind spots to close | The enabled tools' detection capabilities (56 techniques) and what has fired | All |
| **Shadow IT** | Unsanctioned services, high-risk services, users involved, risky sites; by category; risky destinations | Umbrella DNS against `config/sanctioned_services.yaml`; aggregated, never stored | Incident scope |
| **Integrations** | Each connector's freshness and a Test button; platform self-check; scheduled jobs with history and replay | Connector checkpoints; job runs; the self-check | All can view; Test, Sync and job replay need `manage_connectors` |
| **Automation policy** | Every action type with level, limits, four-eyes, reversible; kill switch; pending policy changes | The active policy version | All; changes by role |
| **Reports** | Seven standard reports; describe a report in words; compliance evidence pack; audit export | The 16-source catalogue (§6.8) | All (scoped); evidence exports need `export_evidence` |
| **Access** | Your access; role assignments; service accounts; role permissions | Role grants and API keys | Admin (manage), all (own access) |
| **Audit log** | Chain status and records | The hash-chained audit log | All roles have audit read (scoped to the viewer's domains) |

Every screen works in light and dark themes and at 768 px and above. All times are shown in UTC.

### 15.7 The three workflows, step by step

**Phishing: from a reported e-mail to remediation**
1. **Intake.** Reports come from the Defender *Report* button (reporting mailbox), Avanan, or an upload in the
   console. The original message, headers included, is stored encrypted under its content hash. The same report is
   never processed twice.
2. **Decompose.**
   - Sender, reply-to and return-path.
   - SPF/DKIM/DMARC results.
   - The received path and origin IP.
   - Text and HTML bodies.
   - Every URL, including links whose text differs from their target.
   - Attachments: hash, fuzzy hash, risky extension, macro hints.
   - QR codes in images.

   Malformed or hostile MIME is tolerated, never fatal.
3. **Analyse.** The deterministic signal model (§6.3) produces the verdict, score and named signals. The optional
   ML engine can take this step instead.
4. **Enrich.** Threat-intel fusion on the URLs, domains, hashes and origin IP. A source that fails is reported as
   unavailable.
5. **Campaign scope.** Defender advanced hunting finds similar messages: recipients and variants.
6. **Control reconciliation.** Defender's and Avanan's verdicts are compared, and a disagreement is a finding.
7. **User impact.**
   - Who clicked, and whether the click was blocked.
   - What the admin already moved.
   - Endpoint activity after the click.
   - Identity compromise indicators: risky sign-ins, a new MFA method, inbox rules.
8. **Case.** Evidence (E#), MITRE techniques, and a cited explanation.
9. **Recommendations.** Purge the campaign, block the sender, block the domain/URL, revoke sessions or reset
   passwords for clickers, isolate an endpoint if code ran, tell the reporter, open a ticket. All go through the
   policy.
10. **Auto-close.** Clear-safe and clear-spam reports with confidence ≥ 0.7 are closed with a reply to the reporter.
    10 % are sampled for QA, chosen deterministically.

**Incident: from alerts to an investigated case**
1. **Ingest.** Alerts arrive from both EDRs, Entra risk, Canary, the Delinea tools, Umbrella and the SIEMs. Each
   becomes an event linked to the resolved host and person.
2. **Cluster.** Alerts that share a user or host within 24 hours are merged into one incident. Detections with a
   poor track record are flagged.
3. **Investigate.**
   - Extract the users, hosts and indicators.
   - Query every relevant tool in parallel, each lookup with its own timeout.
   - Add any KEV-listed vulnerabilities on the involved hosts.
4. **Assess.** Severity, confidence and verdict (§6.4); MITRE techniques; a cited summary.
5. **Recommend.** Actions through the policy.
6. **Also:** similar past incidents, and a shift handover report of the last N hours.

**Vulnerability: from four scanners to a validated fix**
1. **Consolidate.** Rapid7, CrowdStrike Spotlight, Defender and Wiz findings are resolved to one record per host and
   CVE, listing every scanner that sees it.
2. **Enrich.** CVSS (NVD), EPSS, KEV, internet exposure (Wiz), and criticality and owner (CMDB/ServiceNow).
3. **Prioritise.** Band P1-P4 and an SLA (§6.2).
4. **Campaign per CVE.** Draft → notifying → in progress → validating → closed. Each owning team gets an action
   plan: awaiting notification → notified → acknowledged → in progress → done or blocked. Notifications and tickets
   are actions, so they need approval.
5. **Follow-up (daily).** Plans unacknowledged after 3 days are chased. Tickets are synced both ways, and a ticket
   marked done while a scanner still sees the vulnerability is a **false closure**, reopened.
6. **Validate.** Every scanner is asked again. The result per source is *still present*, *not present* or
   *unverifiable*, and a fix is never accepted on an unverifiable answer.
7. **Exceptions and risk register.** An exception needs a justification, a compensating control and an expiry, and
   a different person approves it; expiry reopens the finding. Findings past SLA are proposed for the risk register.
8. **Cloud misconfigurations** (Wiz) follow the same route → fix → validate lifecycle.
9. **New KEV exposure:** when CISA adds a CVE, the affected assets are found immediately.

### 15.8 What happens when things fail

| Failure | What the platform does |
|---|---|
| LLM slow or down | 10 s connect limit; 30 s / 120 s read limit; one retry on throttling; after 3 failures, deterministic answers for 60 s |
| LLM budget reached | Findings at 80 % and 100 %; deterministic output until the month rolls over |
| A tool's API down or rate-limited | Backoff and retry; the source shows as *unavailable* in investigations and *stale* on Integrations |
| A malformed vendor record | Set aside; the rest of the stream continues |
| A job keeps failing | Retried; dead-lettered after 3 runs with a finding; replayable |
| Scheduler stopped | "Scheduler stopped" banner on every screen; `/health` reports it |
| Two schedulers | A database lease means each job runs once |
| Something ran twice | Every pipeline is idempotent; the self-check watches for duplicates |
| Figures drift between screens | The hourly self-check recomputes them and raises a finding (only if confirmed on a re-run) |
| Hostile input | NUL characters stripped; over-long free text kept to width; malformed ids refused with 400; malformed e-mail headers read raw |
| Automation misbehaves | The kill switch: durable, on every replica |

Full detail: [FAILURE_MODES.md](FAILURE_MODES.md).

### 15.9 Deployment and configuration

- **Components:**
  - `platform-api` (stateless; scale out behind a load balancer)
  - `platform-scheduler` (one or more)
  - PostgreSQL
  - a volume or blob store for encrypted raw payloads and reports
  - optionally the phishing ML engine with RabbitMQ and Redis, and an isolated detonation host

  `deploy/docker-compose.yml` has all of them.
- **Settings that matter in production:**

  | Setting | Purpose |
  |---|---|
  | `SOC_ENVIRONMENT=prod` | Turns on production defaults: MFA required, no API docs, no dev sign-in, test clocks ignored |
  | `SOC_DATABASE_URL` | PostgreSQL |
  | `SOC_AUTH_MODE=entra`, `SOC_ENTRA_TENANT_ID`, `SOC_ENTRA_AUDIENCE` | Single sign-on |
  | `SOC_DATA_KEY` | Encryption key(s), comma-separated for rotation; mandatory in production |
  | `SOC_REQUIRE_MFA`, `SOC_MFA_AUTH_CONTEXT` | Step-up rules |
  | `SOC_BREAKGLASS_SHA256` | Hash of the sealed emergency credential |
  | `SOC_ORG_DOMAINS` | What counts as internal (for redaction and look-alike detection) |
  | `SOC_CONNECTOR_MODE`, `config/connectors.yaml` | Live or fake mode per tool, with credentials from vault-mounted files |
  | `SOC_LLM_*` | Provider, endpoint, key, deployment, approved endpoints, pinned model version, monthly token budget |
  | `SOC_RAW_RETENTION_DAYS`, `SOC_LLM_LOG_RETENTION_DAYS`, `SOC_ACCESS_LOG_RETENTION_DAYS` | Retention (180 / 180 / 400 by default) |
  | `SOC_KILL_SWITCH` | Start with automation halted |
  | `SOC_JOB_*_SECONDS` | Job intervals |
- **Upgrades:** on PostgreSQL, start-up widens any text column a newer release has made longer. Nothing is ever
  narrowed or dropped automatically.
- **Operations:** health at `/health` (database, scheduler heartbeat, kill switch); Prometheus metrics at `/metrics`
  (auditor API key); backups, key rotation and connector changes in [OPERATIONS.md](OPERATIONS.md).

---

## 16. How it was tested - and how to explain it

**The one-line answer:** "Every feature is mapped to the automated tests that prove it. The suite runs on both
database engines, attacks itself, fuzzes its parsers, moves its own clock forward, and checks every screen in a real
browser."

| Kind of testing | What it proves | Result |
|---|---|---|
| **Unit and workflow tests** | Every workflow, rule and formula behaves as specified | 264 platform tests (265 on PostgreSQL), 205 engine tests |
| **Two database engines** | The same suite on SQLite and on PostgreSQL 16, the production engine. SQLite runs are held to PostgreSQL's rules (text length, 32-bit integers, NUL characters), so production-only bugs fail in every run | Both green |
| **Consistency** | The same figure agrees on every surface (dashboards, lists, badges, brief, analyst tools, reports, generated documents, the rendered screen); re-running every pipeline changes nothing; LLM on or off gives identical figures | Green on 3 estates |
| **Generalisation** | Seeded variant organisations (different people, machines, volumes, suppliers) give correct results, and no output mentions the demo organisation | Green |
| **Time travel** | The test clock is moved forward: SLAs fall due and every screen agrees at each point; the token budget resets at month end; retention prunes old mail but keeps open cases; open exposures keep their risk while activity fades | Green on 3 estates |
| **Penetration testing** | 17 attack groups against a local instance: forged, expired and unsigned tokens; algorithm confusion on production tokens; privilege escalation; cross-domain access by id; SQL and prompt injection; path traversal; upload abuse; information leakage; brute force; races (six simultaneous approvals execute once); production mode exposes no developer surface | All refused |
| **Stored XSS** | Script in an e-mail's subject, sender, body, link and attachment name, viewed on 8 screens with the browser's CSP switched off | Nothing executed or injected |
| **Property-based fuzzing** | Rules checked against thousands of generated inputs: redaction round-trips exactly and never leaks an internal address or card number; attacker indicators are kept; the numeric guardrail accepts supported figures and rejects invented ones; every vendor timestamp format parses to the same instant; the e-mail parser survives arbitrary bytes and hostile MIME | 11 properties hold |
| **Accessibility** | axe-core (WCAG 2.1 A/AA) on every screen, both themes | 0 findings |
| **Layout** | Every screen at 1440, 1280, 1024 and 768 px, light and dark: nothing clipped, overflowing or squeezed | 0 problems |
| **Live** | The real LLM (Azure AI Foundry), NVD, EPSS and CISA KEV | Green |
| **Stress** | 400 hosts and 300 people with messy naming: no false merges; 20,000-entity scale benchmarks | 0 false merges |
| **Static analysis** | ruff (whole repository), bandit, pip-audit, npm audit, type checking of the platform core | 0 findings / 0 medium-high / no known vulnerabilities |

**What the testing found, and why that is good news.** Each round of testing from a new angle found real problems.
Each was fixed with a regression test that keeps it fixed. Examples to quote:
- **Running on PostgreSQL:**
  - a manual job by a user with a long e-mail address failed
  - `%00` in an id crashed 20 routes
- **Moving the clock:**
  - approvals older than 14 days disappeared from the dashboard
  - open vulnerabilities faded from risk while still open
- **Penetration testing:** a token without an expiry would have been valid forever.
- **Fuzzing:**
  - redaction could crash on hostile mail
  - a card pattern could corrupt an IP address used as evidence
  - a malformed `From:` header crashed the e-mail parser (a bug in Python's own library, now worked around)
- **The accessibility scan:** 18 serious issues.
- **Code review and lint:** a "warning banner" action that reported success without changing anything.

**Say:** "We didn't just write tests that pass. We kept attacking the platform from new directions until they stopped
finding anything - and every finding is now a permanent test."

**Be honest about the limits:** passing tests show the absence of the bugs they look for, not of every bug. What
remains unproven needs the client's environment (§10).
