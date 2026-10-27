# Live demo notes - every page, every section, every question

Personal notes for whoever runs the platform live in front of an audience. For each page they cover:
- what it is for
- how to drive it
- what each section means and how its numbers are made
- the values a freshly reset demo shows
- the questions people ask, with answers that hold up

Use them next to the recorded [Demo_Video_Script.md](client_review/Demo_Video_Script.md) (what to say, in order) and
[PRESENTER_GUIDE.md](PRESENTER_GUIDE.md) (formulas and the long Q&A).

Every value marked **demo** was read from a freshly reset demo with the current code on 2026-10-27. Every rule and
formula was read from the code. Values that change with the day (risk decay, SLA ages, enrichment timings, the
audit-record count) or with the AI's wording are marked *read it off the screen*.

---

## Contents

0. [Before you start](#0-before-you-start)
1. [The story you are telling](#1-the-story-you-are-telling)
2. [The shell: sign-in, sidebar, top bar](#2-the-shell-sign-in-sidebar-top-bar)
3. [Overview](#3-overview)
4. [Intelligence](#4-intelligence)
5. [Cases](#5-cases)
6. [Case detail - phishing](#6-case-detail---phishing)
7. [Case detail - incident](#7-case-detail---incident)
8. [Attack story](#8-attack-story)
9. [Entity 360 (a person or a host)](#9-entity-360-a-person-or-a-host)
10. [Approvals](#10-approvals)
11. [Phishing](#11-phishing)
12. [Supplier risk](#12-supplier-risk)
13. [Vulnerabilities](#13-vulnerabilities)
14. [Cloud posture](#14-cloud-posture)
15. [ATT&CK coverage](#15-attck-coverage)
16. [Shadow IT](#16-shadow-it)
17. [Integrations](#17-integrations)
18. [Automation policy](#18-automation-policy)
19. [AI usage & limits](#19-ai-usage--limits)
20. [Reports](#20-reports)
21. [Access](#21-access)
22. [Audit log and Trace](#22-audit-log-and-trace)
23. [Search](#23-search)
24. [Questions that cut across every page](#24-questions-that-cut-across-every-page)
25. [Cheat sheet: formulas and numbers](#25-cheat-sheet-formulas-and-numbers)
26. [When something goes wrong live](#26-when-something-goes-wrong-live)
27. [Claims you must not make](#27-claims-you-must-not-make)

---

## 0. Before you start

**Start clean, with `.env` loaded.**
- From Command Prompt: `scripts\serve_with_env.cmd reset`.
- From PowerShell: `.\.venv\Scripts\Activate.ps1`, `. .\scripts\load_env.ps1`, `python -m soc_platform reset-demo --yes`,
  `python -m soc_platform serve`.
- The first log lines must say `sign-in: development sign-in on`. If they say *OFF*, `.env` was not loaded and the
  sign-in page will fail.

**Check these before the audience arrives.**
- [ ] **Cases** shows *All 10 · Phishing 7 · Incident 3*; **Approvals** shows 37 waiting; **Vulnerabilities** shows
  6 findings.
- [ ] **Intelligence** loads, and the brief chip says *AI narrative* (the AI is on) or *Platform summary* (the AI is
  off). Both are fine; know which one you have.
- [ ] Open *Reported: Action required: your password expires today* and its **Attack story** once. This warms it.
  If the AI is on, run the **Deep analysis** once; it is then cached.
- [ ] Have three browser profiles signed in (tabs of one browser share a sign-in):
  - **Lena**: Lead, all domains. Your main window.
  - **Alice**: Lead, all domains. The second approval for four-eyes.
  - **Ada**: Admin, all domains. Integrations, AI usage and Access.
- [ ] Approve nothing before the demo. Every approval changes the counts on several pages.
- [ ] Have `artifacts/phishing/corpus/html_attachment_phish.eml` ready to upload.
- [ ] Use a 1920 × 1080 window at about 90 % zoom, in the light theme for projectors.

**What the demo set-up staged.** Be ready to say this if asked:
- A demo analyst (`demo.analyst@acme-demo.com`) uploaded six of the seven reported e-mails as samples. That is why
  that address tops *Most active reporters*.
- The same analyst opened the Log4Shell campaign and routed the two cloud findings to their teams.
- Everything else - every verdict, case, correlation, score, severity, story and recommendation - was computed by
  the platform from the tools' data.

**Data timing.** The sample tool data is dated (August to October 2026). That is why every vulnerability is past
its deadline, and why the risk scores can drift slightly from day to day. It is real computation on old data, not a
bug.

---

## 1. The story you are telling

**One sentence:** one investigation and automation layer over the security tools the organisation already owns. The
AI gathers and explains, code computes every figure and verdict, and a person approves every change.

**Three rules.** Repeat them; most questions come back to one of them.
1. **Every figure, score, verdict and severity is computed in code.** The same evidence always gives the same answer.
2. **The AI only explains.** It writes from evidence it is handed, every sentence must cite that evidence, and the
   platform works fully with the AI off: same numbers, same verdicts, same actions.
3. **Nothing changes in a security tool until a person approves it.** The default autonomy level for every action
   type is L2 (recommend).

**What it is not:** it does not replace the SIEM, the SOAR or the EDR. It sits on top of them and calls their APIs.

**Scale of what was built.** Use these if asked "how much is there?":
- 21 connectors
- 3 workflow domains (phishing, incident, vulnerability) plus an intelligence layer
- 13 correlation rules plus 4 operational alerts
- 26 action types in the catalogue
- 5 roles
- 17 report data sources and 7 standard reports
- 56 ATT&CK techniques in the coverage model
- 11 scheduled jobs
- 14 self-checks
- 820 platform tests on SQLite, 819 on PostgreSQL, and 205 phishing-engine tests

**Say these limits first, before anyone asks.** It buys credibility.
1. It has not yet run against a real tenant. Every connector is built to the vendor's documented API and is
   exercised on vendor-shaped sample data, through the same code. Going live is per tool: the preflight check, then
   staged rollout.
2. Accuracy on the organisation's own mail and alerts is not proven yet. It is measured in shadow mode against
   analysts' decisions, and the platform records those automatically.
3. No independent third-party penetration test has been done yet. The internal one has 24 automated attack tests.

---

## 2. The shell: sign-in, sidebar, top bar

### Sign-in page
- **Demo:** development sign-in. Pick a role and a domain scope, then Continue. It exists only for local demos.
  While it is on, every live tool is isolated, so a development sign-in can never drive a real tool.
- **Production:** Entra ID single sign-on with MFA. Roles come from Entra app roles, plus time-bound grants made on
  the Access page.
- **If asked "could someone mint an admin token?":** only on a development server, where every live tool is
  isolated. A production server (`SOC_ENVIRONMENT=prod`) requires Entra sign-in and refuses development secrets.

### Sidebar (left)
Four groups:

| Group | Pages |
|---|---|
| Operate | Overview, Intelligence, Cases, Approvals |
| Domains | Phishing, Vulnerabilities, Cloud posture |
| Insight | ATT&CK coverage, Shadow IT, Supplier risk |
| Govern | Integrations, Automation policy, AI usage, Reports, Access, Audit log |

- **The menu depends on your scope.**
  - Intelligence needs all-domain scope.
  - Phishing and Supplier risk need the phishing domain.
  - Vulnerabilities and Cloud posture need the vulnerability domain.
  - Shadow IT needs the incident domain (DNS is incident telemetry).
  - A phishing-only analyst simply doesn't see the other pages, and the API answers *404 not found* for their data.
- **The badge on Approvals** is the live count of actions waiting for a decision (37 in the demo).
- **The footer** shows your roles, your data scope and *All times UTC*. Every timestamp on every page is UTC.

### Top bar
- **Breadcrumb**, for example *Cases / Detail*.
- **Search box**: global search over cases, people, hosts, indicators, findings and CVEs ([§23](#23-search)).
- **Red *Scheduler stopped* pill.** It appears only if the background job runner has stopped or is stuck. A stopped
  scheduler can't raise an alert of its own, so every screen says so instead.
- ***Automation active* / *Automation halted* pill.** This is the kill switch's state ([§18](#18-automation-policy)).
- **Light / dark toggle.**
- **User menu**: number of permissions, data scope, *Access & roles*, *Sign out*. Sign-out revokes the token on the
  server, not just in the browser.

---

## 3. Overview

**Who sees it:** everyone. The *Riskiest users and hosts* card needs all-domain scope.

**What it is for (say this):** the shift lead's first screen: what's open, what's waiting for a person, whether the
platform is delivering value, and whether its own data can be trusted. *"Every figure is computed from stored
records."*

### Section by section

| Section | What it shows | How it is made | Demo |
|---|---|---|---|
| **Open cases** | Open cases, split by domain | Count of cases not closed | **8** (Incident 3 · Phishing 5) - 2 of the 10 were auto-closed |
| **Awaiting approval** | Actions waiting for a person; links to the queue | Recommended + pending-approval actions | **37** (highlighted) |
| **Automation rate** | Share of actions that ran under the policy without a person | autonomous ÷ actions in the window | **0 %** - "0 of 37 actions ran under policy" |
| **Median time to close** | Median time from opening to closing a case in the window | From the cases' own timestamps | **1 min** - only the 2 auto-closed reports have closed |
| **Open insights** | Open correlated findings, by severity | Count of open insights | **20** (critical 14 · high 3 · medium 3) |
| **Open vulnerabilities** | Open host + CVE findings; how many are past their deadline; how many are internet-exposed | Vulnerability service | **6** - "6 past SLA · 3 exposed" (highlighted) |
| **Value scorecard** | 8 benefit KPIs: baseline, now, target, status | `reporting/value.py`, from timestamps | see below |
| **New cases per day** | 14-day stacked bars by domain | Case creation dates | all on the load day |
| **Open cases by severity** | Donut | | critical 3, high 4, medium 1 |
| **Highest-priority insights** | Top correlated findings | Severity order | the Jane Doe chain first |
| **Riskiest users and hosts** | Top 6 risk scores, with their dimensions | Risk engine ([§9](#9-entity-360-a-person-or-a-host)) | Jane 100, jane-lt01 98, web01 71, db01 46... |
| **Data quality** | Asset and identity match rate, unresolved queue, hosts / users, records correlated | Entity resolution | 100 % / 100 %, queue 0, 8 hosts / 9 users |
| **Integrations** | Only tools in *error*, *stale* or *misconfigured*; otherwise "All N enabled connectors healthy" | Connector freshness | "All 21 enabled connectors healthy" |
| **Enrichment latency** | Median and p95 of an investigation's tool look-ups | Measured per investigation | *read it off the screen* - fake-mode timings, not vendor timings |
| **Verdict quality** | Platform verdicts against analysts' decisions, recent window against baseline | Drift (PSI) per domain | "Needs more dispositions" - no analyst decisions yet |

### Value scorecard (explain it well; leadership cares)
**The 8 KPIs:**
1. Phishing handling time per reported e-mail
2. Time to contain a clicked phishing e-mail
3. Incident: alert to analyst decision
4. Time to a validated fix for critical / known-exploited vulnerabilities
5. Critical findings past SLA
6. Analyst hours on recurring reports per week (from a time study)
7. Tier-1 analyst capacity freed (derived)
8. Agreement with analyst decisions in shadow mode

**Rows and gate:**
- Each row says where its figure comes from: *measured by the platform*, *time study* or *derived*.
- The status is *On target*, *Improving*, *Not improved*, *Awaiting baseline* or *No data yet*.
- Under the table is the **automation quality gate**: agreement ≥ 90 % **and** missed threats ≤ 2 %. In the demo it
  is *not yet met*. This is the evidence you would want before promoting any action to automatic.

**The form.** A lead with all-domain scope opens *Enter a baseline, target or time-study figure* and enters:
- a **baseline**: from before go-live, for example from ServiceNow tickets for January to March;
- a **target**;
- a **measured** figure: for things software can't see, such as report hours.

The form records the source text too.

**Say:** *"It never invents a saving. Until there's a baseline, it says 'awaiting baseline'."*

### Likely questions
- **"Why is automation 0 %?"** By design. Every action type starts at L2 (recommend). Automation is switched on per
  action type, by a recorded two-person policy decision, when the quality gate says it is safe.
- **"Median time to close is 1 minute - that's fake."** It is the two auto-closed benign reports (spam and a genuine
  invoice), which close as soon as they are judged. The real cases are still open, which is correct.
- **"What does 'records correlated' mean?"** Every entity in the shared context store: hosts, people, alerts,
  e-mails, indicators, sign-ins, findings and so on, after resolution to one record each.
- **"Match rate 100 % - is that realistic?"** On the demo data, yes. On a real estate it will be lower. Ambiguous
  matches go to the resolution queue (the *Awaiting resolution* figure) rather than being guessed. A wrong merge
  routes alerts to the wrong person; a split can be fixed safely.
- **"Enrichment latency looks random."** In demo mode the tools are simulated, so the timing is not a vendor's.
  Measured with every vendor call taking 400 ms, an incident investigation takes about 2-3 s and a phishing analysis
  about 3 s, because the tools are asked in parallel.

---

## 4. Intelligence

**Who sees it:** all-domain scope (it crosses every domain).

**What it is for (say this):** attacks show up across tools: a click in one, a process in another, a sign-in in a
third. This page looks across every tool and every domain at once.

### Section by section

**Situation brief.** A paragraph on what matters now: top threats, riskiest people and hosts, approvals waiting,
exposure.
- The chip says **AI narrative** (the model wrote the prose from the platform's figures) or **Platform summary** (the
  AI is off or over budget, so the platform's own template is used).
- It is prepared in the background and cached, so the page can take a few seconds the first time.

**Ask the analyst.** A free-text question, for example
`Is jane.doe@acme-demo.com compromised and what should we do first?`. How it works - tell it in this order:
1. The question is turned into **look-ups from a fixed, read-only list**. Here they are `find_entity`,
   `entity_risk` and `entity_context`; the tags appear under *How this was answered*.
2. With the AI on, the model *plans* which look-ups to run (*AI-planned look-ups*). With it off, rules plan them
   (*rule-based look-ups*).
3. The platform runs the look-ups against its own data.
4. Only then does the model write the answer from the results, with internal names replaced by placeholders.
5. Every sentence must cite a result. A sentence without a valid citation, or with a number that isn't in its
   evidence, is **removed** before display.

*Evidence behind the answer* lists the claims, as facts or inferences, each with its evidence references.

**Demo answer (AI off):** *"jane.doe@acme-demo.com is at CRITICAL risk (100/100)..."*, with the drivers, 3 open cases,
5 correlated findings and the first step: rotate every secret the account accessed after the first risk signal. With
the AI on, the wording differs; the facts don't.

**Correlated findings (20).**
- Filter by *All / Critical / High / Medium*. Eight are shown, then *Show all 20*.
- Each finding has:
  - severity and title
  - the rule name and *last confirmed* time; hover the rule line for the requirement ids it satisfies
  - a narrative (AI or template)
  - numbered **Next steps**
  - **Evidence (n)**: source, summary and time for each record
- **Acknowledge** or **Dismiss**: an analyst decision, audited.
- **Re-correlate** (top right) runs the rules now. They also run every 10 minutes. Re-running never duplicates a
  finding: each one has a de-duplication key and is updated in place.

**Risk by user and host.** The top 10 risk scores with their dimensions. Click a name for Entity 360.

### The 13 correlation rules (know them by name)

| Rule | Raises | Fires in the demo? |
|---|---|---|
| Phishing compromise chain | click → endpoint execution → identity compromise for one person | yes (Jane) |
| Consent after phishing | an application consent within a week of a phishing click; flagged to verify, never called a compromise on its own | no |
| Privileged access after compromise | a vault secret viewed or copied after compromise signs | yes (Jane) |
| Deception corroborated | a decoy touched, plus other telemetry on the same person or host | yes ×2 |
| Exposed host under attack | attack activity on a host with KEV-listed vulnerabilities | yes ×3 (jane-lt01, web01, db01) |
| Attacked host without EDR | a machine under attack with no EDR agent | no |
| High entity risk | risk high or critical across several dimensions | yes ×3 |
| Repeat clicker | one person clicked in two or more campaigns | yes (Jane, 2 campaigns) |
| Control gap | a security-categorised destination still allowed | yes (login.micros0ft-helpdesk.com allowed 2 times) |
| New KEV exposure | a newly KEV-listed CVE present on assets | yes (CVE-2024-21412 on 2 assets) |
| Shared infrastructure | one indicator touching several people or hosts | yes ×2 |
| Supplier risk | supplier impersonation, account compromise, payment diversion | yes ×5 |
| Model drift | platform verdicts drifting away from analysts' decisions | no (no decisions yet) |

**Plus 4 operational alerts:**
- a scheduled job dead-lettered after 3 failed runs
- break-glass access used
- the platform self-check failing
- the monthly AI token budget at 80 % or exhausted

### Likely questions
- **"Is the AI deciding these findings?"** No. Each finding is a fixed rule in `intelligence/correlation.py`. The AI
  may write the narrative paragraph and nothing else.
- **"Can the assistant do anything - isolate a host?"** No. Its tools are read-only. The model's output can never
  cause an action.
- **"What if I ask about someone who doesn't exist?"** It says it can't find them. It never answers "no evidence",
  which would read as "clean".
- **"Can a malicious e-mail inject instructions into the assistant?"** The worst it can do is produce a bad
  paragraph. That paragraph must still cite evidence or it is removed, and nothing the model says can trigger an
  action.
- **"Why are 14 of 20 critical?"** One real attack (Jane) produces several findings from different angles: the chain,
  privileged access, deception, exposure, risk. Supplier fraud adds five critical ones. Each finding is a distinct
  question an analyst would ask.

---

## 5. Cases

**Who sees it:** everyone, filtered to their domains.

**What it is for (say this):** every investigation in one queue, whatever its domain, with an owner, severity,
verdict and confidence.

### Section by section
- **Domain filter:** *All 10 · Phishing 7 · Incident 3 · Vulnerability 0*.
  - Why vulnerability shows 0: vulnerability work is tracked as findings and campaigns on its own page, not as
    cases.
- **Owner filter:** *Everyone 10 · Mine 0 · Unassigned 10*.
- **Columns:** severity, case (title and domain), verdict, confidence, status, owner, opened.
- **Paging:** 500 rows a page, with *Newer* / *Older* beyond that (built for real volumes).
- **Run incident pipeline.** Pulls new alerts now, groups them into incidents and investigates them. Without the
  button it runs every 5 minutes. The toast says how many new incidents were found, or "No new alerts since the
  last run".
- **Pull reported email.** Reads the reporting mailbox now. Without the button it runs every 2 minutes.

### The 10 demo cases (know each one)

| Case | Domain | Severity / verdict / confidence | What it is |
|---|---|---|---|
| Action required: your password expires today | phishing | critical · malicious · 95 % | **The headline case.** Credential phish → Jane clicked → laptop, sign-in and vault activity. 9 actions |
| Action required: confirm your 2026 benefits enrolment | phishing | critical · malicious · 84 % | A second campaign Jane clicked (that makes her a repeat clicker). 8 actions |
| Urgent wire transfer - confidential | phishing | high · malicious · 89 % | CEO wire fraud; no link. T1656 (impersonation). 2 actions |
| RE: Invoice KL-4471 - payment today | phishing | high · malicious · 95 % | Look-alike supplier domain (krishna-logistlcs.com). 2 actions |
| Updated bank details for remittance | phishing | medium · suspicious · 70 % | The **real** supplier domain, passes every authentication check, asks to change bank details → supplier mailbox likely compromised. 1 action |
| Your Azure invoice for September 2026 | phishing | informational · safe · 85 % · closed | Genuine. Auto-closed |
| 70% off laptops this weekend only! | phishing | low · spam · 95 % · closed | Marketing. Auto-closed |
| Deception alert: PowerShell downloaded and executed a remote payload | incident | critical · true positive · 95 % | Jane's laptop; a decoy touched; 7 corroborating areas. 12 actions |
| Unusual outbound connection from web server | incident | high · needs review · 55 % | A *low* alert raised to *high* because web01 is internet-facing and business-critical, with Log4Shell |
| Exchange Server exploitation attempt blocked | incident | high · needs review · 55 % | A *medium* alert raised to *high*: db01 is business-critical, with a KEV vulnerability |

### Likely questions
- **"How does a closed report get checked?"** Clear spam and clearly safe reports with confidence ≥ 0.7 are closed and
  the reporter is answered. **10 %** of those are sampled for analyst QA. The sample is chosen by a stable hash, not
  at random, so it is reproducible. In the demo neither of the two fell in the sample.
- **"What stops a re-run creating duplicates?"** Every pipeline is idempotent:
  - one case per reported message (a unique source reference)
  - one action per idempotency key
  - one active campaign per CVE

  The test suite runs every pipeline twice on four different estates and requires zero change.
- **"How do alerts become one incident?"** Alerts are grouped by host and person within a 30-day window that ends at
  the newest alert. One attack is one case, not twenty alerts.

---

## 6. Case detail - phishing

Open **Reported: Action required: your password expires today**.

### Header
- Severity chip, verdict chip, domain · status · opened.
- **Confidence · automation mode** (*Recommend*) **· owner**.
- **Take case** assigns it to you, audited. **Unassign** is offered to the owner, or to a lead for anyone's case.
  Only a lead can take a case off someone else.
- **Attack story** opens [§8](#8-attack-story).
- **Investigation record** downloads the case as a Word document.
- An **Incomplete picture** callout appears when a tool did not answer: "Unavailable sources: X. Conclusions below
  exclude them." An unavailable tool is never treated as "nothing found". In the demo nothing is unavailable.

### Left column
**Assessment.**
- The summary (written by the AI if on, else a template). *"The written explanation is being prepared"* means the
  verdict, evidence and actions are already final and the prose is still being written in the background.
- **Facts** (directly supported by a record) and **Inferences** (a conclusion from several facts), kept apart.
- Each statement carries references (E1, E2...).
  - **Hover** a reference: a popover shows the tool, the time and the record.
  - **Click** a reference: the page scrolls to that evidence row and highlights it.
- **MITRE ATT&CK** tags, with names: **T1566.002** spearphishing link, **T1598.003** spearphishing for information,
  **T1656** impersonation, **T1078** valid accounts. They come from vendor alert metadata plus fixed evidence rules.

**Analysis** (phishing only). Two independent verdicts side by side:
- **ML models:** verdict + score. Seven trained models, one per e-mail component: header, content (a text
  classifier), URLs, attachments, sandbox, threat intel, user behaviour. Each has a score bar and a reliability tag
  (hover it for the measured note).
- **Rules:** verdict + score. Fixed, named, weighted signals: look-alike domains, DMARC/DKIM/SPF failures, credential
  lure, urgency, bank-detail change, threat-intel hits. Strong authentication subtracts.
- **The more severe verdict counts.** *Confirmed by* lists the models that agreed. *Did not answer* lists any that
  failed. The fusion note explains special handling.
- **Special handling:** the content and user-behaviour models may not decide alone. A models-only alarm on a properly
  authenticated sender needs the header, URL, attachment or threat-intel model, or the rules, to agree. Otherwise the
  case goes to an analyst as *suspicious*.
- **The sandbox model** runs only with an isolated detonation host configured. It is not part of the demo.

**Recommended actions (9).**
- **#** is the recommended order: contain first, communicate last.
- **Action and rationale:** the action type, why it is recommended, and the level (L2), blast radius, *not
  reversible* and the policy reasons. For example: *"four-eyes: two different people must approve"*.
- **Targets:** up to 3 shown, then "+N more".
- **Status:** *Recommended*, *Awaiting second approval*, *Executed*, *Rejected*, *Failed* or *Rolled back*, with the
  approver.
- **Approve / Reject** (for people allowed to approve). **Roll back** on an executed reversible action, for leads.
- **The demo's 9:** campaign purge, block sender, ticket, reporter feedback, isolate the laptop, revoke sessions,
  reset password, block the domain, block indicator.
  - Four-eyes: purge, isolate, reset password, block domain.
  - Destructive, so never automatic: purge, reset password.

**Evidence.**
- Grouped by area: email (30), dns (1), endpoint (2), identity (1).
- Each row has a reference id, the source tool, a summary, an *inference* chip if applicable, and **open in tool**
  (the vendor console's deep link).

### Right column
- **Cross-domain context:** risk scores of the people and hosts involved, and the correlated findings that touch
  them.
- **Entities:** every person, host, indicator and e-mail in the case, with its role and *seen by* (which tools
  reported it). People and hosts link to Entity 360.
- **Analyst decision:** true positive / malicious / suspicious / false positive / benign, with reasoning. It is
  stored as a disposition, which feeds *Verdict quality* (drift) and the value scorecard's agreement KPI.
- **Analyst notes:** append-only. Author and time are kept and notes are never edited; a correction is a new note.
- **Timeline:** the last 30 events from every tool about the case's people, hosts and indicators, newest first.
- **Audit trail:** every audited event about this case, with the sequence number and actor.

### What the platform did by itself (tell it as a story)
1. **Verdict:** a sender domain imitating Microsoft (micros0ft, a zero for the "o"), failed DMARC, a display name that
   doesn't match the sender, pressure language, and a link domain rated malicious by three intelligence sources.
2. **Campaign scope:** found every recipient of the same campaign (8).
3. **Who clicked:** Jane clicked through. Another person's click was **blocked by Safe Links**, and a blocked click
   is not counted as a click.
4. **Impact on Jane:** queried the EDRs, Entra and DNS. It found PowerShell on her laptop reaching the phishing
   domain, a sign-in from an anonymising network, a new inbox forwarding rule and a new device.
5. **Control disagreement:** both e-mail security tools had passed the message. That disagreement is itself
   recorded as evidence, which is useful for tuning them.

### Likely questions
- **"Does the e-mail go to the cloud / OpenAI?"** The ML models run **offline** inside the platform. A test blocks
  all network access and requires zero connection attempts. The AI narrative (if on) gets only the evidence, with
  identities pseudonymised, sent only to the approved endpoint.
- **"Do you click the links?"** No. Nothing ever fetches a URL taken from an e-mail, so there is no SSRF surface. URL
  verdicts come from threat intelligence and from the URL's structure.
- **"How accurate are the models?"**
  - On 46 labelled test messages: the models alone caught 89 % with no false alarms; combined with the rules, 100 %,
    with every verdict exactly right.
  - The content model is a text classifier trained on public phishing and spam data: 99 % on held-out data.
  - **Then say:** this is a regression check on a small synthetic set, not an accuracy claim. Real accuracy is
    measured in shadow mode on the organisation's own reported mail.
- **"Why two analyses?"** Independence. On the test data the rules catch two kinds the models miss: an HTML
  attachment carrying a login form, and a bank-detail change with no link. The models catch wording the rules don't
  know.
- **"Why is isolation recommended for a phishing case?"** Because Jane clicked and her laptop then ran PowerShell
  reaching the phishing domain. The action exists because of evidence; it is not a fixed playbook step.

---

## 7. Case detail - incident

Open **Exchange Server exploitation attempt blocked**. Then, if there is time, open **Unusual outbound connection
from web server** and the **Deception alert**.

### What is different from a phishing case
- **No *Analysis* card.** Instead, **Why <severity>** is inside the Assessment. It lists every fixed rule that
  applied, then *"Result: severity high, confidence 55 %"*.
- **Evidence** comes from **parallel enrichment**: for every host, user, IP and hash, every relevant tool is queried
  at the same time.
  - Up to 16 workers, a 20-second deadline per look-up, and results cached for 30 minutes.
  - A tool that misses the deadline shows as *unavailable*.

### The severity rules (`IncidentService._score`) - know them cold
1. **Start** from the alert's own severity (the tool's rating).
2. **A decoy touched** (deception hit) → **raised to critical**. Decoys have no business use.
3. **A host in the case carries a CISA KEV vulnerability** → **one level up**.
4. **That host is internet-facing or business-critical** (from the CMDB) → **at least high**.
5. **Three or more corroborating areas** (deception, identity, privileged access, endpoint, threat intel, DNS,
   exposure) → **at least high**.
6. **Confidence** = 35 % + 10 % per corroborating area, at most 95 %.
7. **Verdict:** *true positive* when severity ≥ high **and** confidence ≥ 60 %. *Needs review* when severity is
   medium or higher but that test fails. Otherwise *likely benign*.

### Apply them to the demo cases (this is the "exposure-informed triage" point)

| Case | Start | Rules that applied | Result |
|---|---|---|---|
| Exchange exploitation attempt blocked | medium | KEV on db01 → high; db01 business-critical → at least high; 2 areas (endpoint, exposure) | **high, 55 %, needs review**. MITRE T1190 |
| Unusual outbound connection from web server | **low** | KEV (Log4Shell) → medium; web01 internet-facing **and** business-critical → at least high; 2 areas | **high, 55 %, needs review** |
| Deception alert: PowerShell... | critical | decoy touched; risky sign-in, mailbox rule, privileged credential access, malicious intel, destination reached; 7 areas | **critical, 95 %, true positive**. 9 MITRE techniques (T1039, T1059.001, T1078, T1087.002, T1098.005, T1105, T1114.003, T1555, T1566.002) |

**Say:** *"The same low alert on a patched laptop would stay low. On an internet-facing, unpatched, business-critical
server it's high - and the platform knows that because it holds the vulnerability and CMDB data too."*

### Likely questions
- **"Why 'needs review' if it's high?"** Confidence is 55 %: only two independent areas agree. The platform is
  honest that a person should look. It still recommends containment.
- **"What if two tools disagree - one closed the alert as a false positive?"** The case shows the conflict and holds
  every action for a person.
- **"Do internal IPs go to VirusTotal-style services?"** No. Internal addresses and the organisation's own domains
  are never sent to outside threat-intelligence services. The evidence says so ("not sent to outside sources").
- **"Where does MITRE come from?"** Vendor alert metadata, plus fixed rules on evidence. For example: a decoy touched
  → T1039, a mail forwarding rule → T1114.003, a risky sign-in → T1078, a vault secret copied → T1555.

---

## 8. Attack story

From the phishing case, click **Attack story**.

**What it is for (say this):** the analyst's hardest job is the narrative: what happened, in what order, how far it
got. The platform reconstructs it from every tool and every related case, and argues against itself before
concluding.

### Header and tiles
- **Verdict:** *Confirmed compromise*, high confidence.
- **Reason (computed):** *"8 kill-chain stage(s) reached (1 more blocked), corroborated by 9 tools (1 more blocked a
  step); benign explanations rejected."*
- *Reconstructed from N case(s), 10 tools · 43 min from first to last step.*
- **Tiles:**
  - *Kill-chain stages* (reached · blocked)
  - *Steps*: 14
  - *Users reached*: 1 / 8 (interacted / received)
  - *Hosts*: 1
  - *Privileged secrets*: 1, with its name
  - *Gaps checked*: 3, with 0 blind spots

**The assessment rule:**
- **Confirmed compromise:** 3+ stages reached, including a "deep" one (persistence, privilege escalation,
  credential access, discovery, lateral movement, collection, exfiltration or impact), seen by 3+ tools, and no
  benign explanation still plausible.
- **Likely compromise:** a deep stage, or 2+ stages.
- **Attempt blocked:** every step was blocked.
- **Suspicious activity:** anything else.
- *"Reached"* counts only stages that succeeded.

### Section by section
**Kill chain.** The 12 ATT&CK tactics, each in one of five states:
- *Observed*
- *Blocked*
- *Checked - none*: tools that could see it found nothing
- *Blind spot*: no enabled tool can see it
- *before scope*

In the demo:
- **Observed:** Initial Access, Execution, Persistence, Credential Access, Discovery, Lateral Movement, Collection,
  Command and Control.
- **Blocked:** Privilege Escalation (the privilege manager denied an elevation).
- **Checked - none:** Defense Evasion, Exfiltration, Impact.

**What happened.**
- The steps in time order. Events of the same stage within 15 minutes form one step.
- Each step shows the time, the stage, the title, a *blocked* or *succeeded* chip, its techniques, the tools that saw
  it, a confidence with its reason, and references (hover for tool · time · title).
- **Confidence** is *high* when 2+ tools corroborate or the detection is critical; otherwise *medium (single
  source)*.

**Response plan.**
- Pending actions in five phases: **Contain** (isolate, revoke sessions) → **Preserve evidence** (forensics) →
  **Eradicate** (block domains and indicators, purge, block sender) → **Recover** (reset password, rotate the secret)
  → **Communicate** (ticket, reporter feedback).
- Contain and Preserve are pre-ticked. **Approve selected** approves them as a bundle, and *each action is still
  checked by the policy and four-eyes*.
- The same action from several related cases is merged: *"×N (one per related case, approved together)"*.

**Blast radius.** Grouped lists:
- **At the centre:** Jane and her laptop.
- **Privileged secrets** accessed after the compromise.
- **Also received the phishing e-mail:** the other recipients. Highlighted ones interacted.
- **Related cases.** Cases the platform judged benign (the spam and the genuine invoice Jane also received) are left
  out.
- **Indicators involved**, grouped by type: domains, URLs, IPs, sender addresses, file hashes. Five are shown, then
  "and N more".

**Benign explanations tested.** Each is tested against specific evidence:

| Explanation | Result |
|---|---|
| The reported e-mail was legitimate | **Rejected**: the verdict and its signals |
| The risky sign-in was travel or a VPN | **Rejected**: an anonymising network; her normal sign-ins are from India |
| The script was legitimate IT work | **Rejected**: it reached the phishing domain |
| The decoy was touched by an authorised scanner | **Rejected** |
| The privileged secret access was normal duty | **Unlikely**: confirm with its owner |

**Gaps.** *What we looked for and did not find*, for example *"No evidence of exfiltration - checked crowdstrike,
umbrella"*. "Not found" is always stated with which tools looked; it is never assumed. A stage no tool can see would
say *Blind spot*.

**Exposure on affected assets.** Vulnerabilities and posture issues on the hosts involved.

**Deep analysis** (optional; needs the AI). A second opinion on exactly this evidence, with identities pseudonymised.
- **Sections:** assessment, likely objective, key findings (fact / inference), alternative explanations, priorities
  and open questions.
- Every statement must cite. The count of removed statements is shown.
- Priorities may reference only real pending actions, or "manual".
- If the model disagrees with the platform's assessment, a red callout says so. **The platform's verdict does not
  change.**
- Cached per evidence fingerprint. **Re-run** forces a fresh one.

### Likely questions
- **"Is the story written by the AI?"** No. The story - steps, kill chain, hypotheses, gaps, blast radius and plan -
  is computed (`intelligence/story.py`) and identical with the AI off. Only the optional deep analysis is the model.
- **"Is it stored?"** It is rebuilt from stored records on demand. Its fingerprint (a hash of its evidence) means the
  same attack gives the same story from any related case.
- **"What if we don't have tool X?"** Stages that no enabled tool can see appear as **blind spots**, never as "clean".
- **"Why 'confirmed' and not 'likely'?"** Because the computed rule above was met. Read the reason line aloud.

---

## 9. Entity 360 (a person or a host)

Click **jane.doe@acme-demo.com** anywhere.

**What it is for (say this):** the shared picture everything is built on: one person assembled from every tool, so
the "jane.doe" in the EDR and the "ACME\\jane.doe" in the vault are known to be the same person.

### Section by section
- **Header:** kind (identity / asset), risk band chip, name, *seen by* (10 tools for Jane), and the **Risk score**
  tile: 100/100 with its dimensions.
- **Why this score:**
  - Every signal that adds points: +points, signal, detail, source tool and time.
  - The intro line gives the points total (*read it off the screen*; about 376 on the reset day) and the formula.
  - The last row, *Other factors*, sums the smaller signals so the list stays readable.
  - Jane's main rows: deception hit +50 (Canary), endpoint alert +40 (CrowdStrike), risky sign-in +30 (Entra),
    phishing identity compromise +30, Sentinel alert +25, Defender alert +25, open incident +20, two phishing clicks
    +20 each, two privileged credential accesses +15 each, malicious destination reached +12 ×2.
- **Timeline across tools:** the last 40 events from every tool, newest first.
- **Identifiers:** every strong key that resolved this person: Entra object id, UPN, e-mail, Windows SID, SAM name.
- **Cases, Insights, Vulnerabilities** (hosts), **Related** (up to 15 linked hosts, people and indicators per type,
  with the relation).
- **Per-tool attributes:** what each tool says about the entity (up to 14 fields each).

### The risk score - be ready to defend it
- **Score = 100 × (1 − e^(−points ÷ 60)).** Every signal raises it, each by less as the total grows.
  - 60 points give 63.
  - It never passes 100, so one noisy alert can't make someone critical alone.
  - **The +50, +20... add up to far more than 100; that's expected.** The curve maps them onto 0-100.
- **Decay:** activity halves every **7 days**. Open exposures and open incidents **do not decay** until resolved: an
  unpatched host doesn't become safe by waiting.
- **"Now"** is the latest event in the data, not the wall clock. If feeds stop, scores freeze; they don't fall.
- **Bands:** critical ≥ 80, high ≥ 60, medium ≥ 30, else low.
- **Weights** (one place, tunable):

  | Signal | Points |
  |---|---|
  | deception hit | 50 |
  | alert by severity: critical / high / medium / low | 40 / 25 / 10 / 3 |
  | risky sign-in: high / medium | 30 / 15 |
  | phishing identity compromise (once per person) | 30 |
  | phishing click | 20 |
  | privileged credential access | 15 |
  | KEV exposure | 15 |
  | malicious destination reached | 12 |
  | privileged user at risk | 10 |
  | elevation denied | 8 |
  | no EDR on a machine | 5 |
  | phishing recipient | 4 |
  | open incident | half its severity weight |

- Each case counts once per entity. Decoys are sensors and are never scored.

### Likely questions
- **"How do you know they're the same person?"** Strong identifiers first: device ids, UPN/SAM/SID, Entra object id.
  Then weaker hints, with a score. A match is automatic only at ≥ 0.85 *and* clearly ahead of the runner-up (by a 0.1
  margin). From 0.55 it goes to the review queue; below that it stays separate. Built-in accounts (SYSTEM, root,
  `HOST$`) never become people.
- **"Ever merged two different people?"** Stress-tested: 0 false merges on 400 hosts and 300 people with 6 naming
  conventions in random order. Two different vendor device ids are never merged.
- **"Why is a host 98 when the user is 100?"** The curve: both have many signals; the host's points total is a
  little lower.

---

## 10. Approvals

**Who sees it:** everyone with request or approve permission, in their domains.

**What it is for (say this):** every write the platform wants to make to a tool arrives here as a request - what, on
which targets, why, under which policy. There is no other path to a tool.

### Section by section
- **Waiting by domain** (donut): **37** = incident 18 · phishing 16 · vulnerability 3.
- **Waiting by action type** (bars): ticket.create 8, email.reporter_feedback 7, indicator.block 6,
  email.block_sender 4, endpoint.collect_forensics 3, endpoint.isolate 3, dns.block_domain 2, and 1 each of
  email.campaign_purge, identity.reset_password, identity.revoke_sessions and pam.rotate_secret.
- **Filter** by domain, with counts.
- **The table:**
  - action type, domain and level
  - targets
  - rationale
  - **Policy**: the policy reasons, or *recommend (L2)*. A four-eyes action after its first approval shows *"First
    approval by X - a second lead must approve"*.
  - **Approve / Reject**, and **Case** (opens the case)

### Who may approve what (this is asked every time)
- **A routine action:** anyone with *approve_action* in that domain (analyst or lead), signed in with MFA.
- **High-impact action:** four-eyes, a VIP or critical target, or more targets than the limit. It needs
  *approve_high_impact* (**lead**).
- **Four-eyes action recommended by the agent:** **two different leads**. The first approval is recorded (*Awaiting
  second approval*); the same person cannot give the second.
- **Service accounts (API keys) can never approve,** whatever role they hold.
- **Default four-eyes action types:** endpoint.isolate, endpoint.release, identity.reset_password,
  identity.disable_account, email.campaign_purge, dns.block_domain, pam.rotate_secret.
- **Target limits:**
  - per action type: isolate 5, disable account 3, reset password 10, revoke sessions 10, rotate secret 5, soft delete
    50, campaign purge 200;
  - default 25 for the rest;
  - above the limit, a lead must approve;
  - above 5,000 targets the request is refused outright.

### Demo it
1. Approve an `email.reporter_feedback` row: it runs (in the demo, against the simulated mail system).
2. Approve an `endpoint.isolate` row: toast *"First approval recorded - a second lead must approve before it runs"*.
   The row shows *First approval by lena@...*.
3. In **Alice's** window, open Approvals and approve the same row: it runs.

### What protects every action (say three of these)
- **Preconditions are re-checked at the moment it runs**, in case something changed since the recommendation.
- **A unique idempotency key:** a retry or a double click can never isolate a host twice. This was tested with six
  simultaneous approvals: one execution.
- **The decision is committed before the tool is called, and the outcome after.** If the server dies mid-call, the
  action is flagged "verify in the tool", never re-run.
- **Reversible actions record their reverse** (isolate ↔ release, block ↔ unblock). The reverse goes through the same
  policy; releasing a host is itself four-eyes.

### Likely questions
- **"Can I approve my own request?"** Not a four-eyes one, and not a policy or access grant you proposed.
- **"An analyst and a lead both have approve - what's the difference?"** Leads can approve high-impact (four-eyes,
  VIP, over the limit) and roll back. Analysts approve routine actions only.
- **"What happens after approval if the tool is down?"** The action fails and is recorded as failed, with the error.
  The `actions` job (every minute) is the safety net for approvals made inside a larger transaction.

---

## 11. Phishing

**Who sees it:** the phishing domain.

**What it is for (say this):** the phishing programme at a glance - volume, outcomes, who clicked, who reports, and
how fast clicks are contained.

### Section by section
- **Tiles:**
  - **Reported:** 7
  - **Auto-closed:** 2 ("0 sampled for QA")
  - **Campaigns:** 5. A campaign is the malicious or suspicious messages sharing a sender domain and link domains;
    here that is the 4 malicious reports and the 1 suspicious one.
  - **Repeat clickers:** 1 (highlighted)
  - **Time to containment:** *–*, "no containment executed yet". It is the median from report to the first executed
    containment action, so it appears after you approve one.
- **Verdict mix** (donut): malicious 4, suspicious 1, spam 1, safe 1.
- **Users who clicked:** Jane, 2 campaigns. *"1 clicked more than one campaign."*
- **Analyse a message:** upload a `.eml`. The original is stored **encrypted**, the same pipeline runs, and a case
  opens. Demo: `html_attachment_phish.eml` → *Reported: Jane, please review and sign: Q3 Vendor Agreement.html*,
  **malicious**: a sender imitating DocuSign, with an HTML attachment.
- **Most active reporters:** demo.analyst 6 (the uploaded samples), bob.lee 1. *"People who report suspicious
  e-mail - worth recognising."*
- **How reports were handled:** closed automatically (QA-sampled) / analysed by the platform / part of a campaign.
- **Buttons:** **Pull reporting mailbox** (same as on Cases) and **Supplier risk**.

### The verdict thresholds (rules)
- **malicious** ≥ 0.70, or ≥ 0.50 with threat intel saying malicious
- **suspicious** ≥ 0.35
- **spam:** bulk or urgency without phishing signals
- otherwise **safe**
- auto-close at confidence ≥ 0.7, with a 10 % QA sample

### Likely questions
- **"Is a blocked click counted?"** No. Safe Links blocking the click means the user did not reach the site. It is
  recorded, not counted as a click.
- **"Can it purge the whole campaign?"** It recommends `email.campaign_purge` (soft delete, reversible). That is
  four-eyes and destructive, so it is never automatic.
- **"Does the reporter get feedback?"** Yes: `email.reporter_feedback` is recommended on every report. It is routine,
  needing one approval.

---

## 12. Supplier risk

**Who sees it:** the phishing domain.

**What it is for (say this):** business e-mail compromise through suppliers is where phishing costs real money.

### Section by section
- *"... signals for 3 key suppliers over 90 days."* Suppliers are configured on **Integrations → Suppliers &
  sanctioned services**, or in `config/suppliers.yaml`.
- **One card per supplier:** status chip (*Ok / Watch / At risk / Critical*), domains, criticality, findings.
- **Demo:**
  - **Krishna Logistics** (high criticality) → **Critical**, 4 findings:
    - **Impersonation:** `krishna-logistlcs.com`, one letter away (edit distance 1) from `krishna-logistics.com`
    - **Payment diversion**, on that look-alike
    - **Account compromise:** a suspicious message from the **real** domain, passing SPF, DKIM and DMARC → the
      supplier's own mailbox or tenant is likely compromised
    - **Payment diversion**, on the real-domain message
  - **Microsoft (cloud provider)** → **Critical**: impersonation from `micros0ft-helpdesk.com`.
  - **Global Freight Ltd** → **Ok**: no findings.
- Each finding links to its case.

**Say:** *"Authentication checks alone would never flag the second one - it's genuinely from their domain. The advice
in both cases: never change payment details on an e-mail; call the supplier on a number you already hold."*

---

## 13. Vulnerabilities

**Who sees it:** the vulnerability domain.

**What it is for (say this):** four scanners report the same flaw on the same server under different names. The
platform keeps one record per host and CVE, prioritises by real risk, routes it to the owner, and closes it only when
a scan proves the fix.

### Section by section
- **Tiles:** Open findings 6 · CISA KEV 5 · Internet-exposed 3 · Past SLA 6 · Asset match rate 100 %.
- **Open by priority:** P1 3, P2 3.
- **Open findings by team** (past SLA / within SLA): Web Platform 3, End User Computing 2, Windows Server Team 1.
- **Age of open findings:** all 6 in 31-90 days. The sample data is dated.
- **Ask about exposure:** type `which internet facing hosts have KEV vulnerabilities?` → *"2 finding(s) on 1
  asset(s) match"* (web01: Log4Shell and HTTP/2 Rapid Reset).
  - **Filter used:** `{"kev": true, "internet_exposed": true, "status": ["open","reopened"]}`, shown so anyone can
    check it.
  - The question becomes a structured filter, which runs on the database. The answer is never generated text about
    data.
- **Coverage gaps:**
  - *No EDR*: PRIYA-LT07 (seen only in DNS)
  - *Not in CMDB*: PRIYA-LT07, acmebackups
  - *Resolution queue*: 0
- **Findings table:** priority, CVE, asset (+ "internet-exposed"), owner team, SLA due, **seen by** (which scanners),
  status, **Start campaign** / *In campaign*.

| Priority | CVE | Asset | Team | Seen by |
|---|---|---|---|---|
| P1 | CVE-2021-44228 (Log4Shell) | web01 (internet-exposed) | Web Platform | rapid7, crowdstrike, wiz, defender_endpoint - **in campaign** |
| P1 | CVE-2023-44487 (HTTP/2 Rapid Reset) | web01 (internet-exposed) | Web Platform | crowdstrike, wiz, defender_endpoint |
| P1 | CVE-2022-41082 | db01 | Windows Server Team | rapid7, defender_endpoint |
| P2 | CVE-2023-38408 | web01 (internet-exposed) | Web Platform | rapid7, wiz, defender_endpoint |
| P2 | CVE-2024-21412 | jane-lt01 | End User Computing | rapid7, crowdstrike, defender_endpoint |
| P2 | CVE-2024-21412 | bob-lt02 | End User Computing | crowdstrike, defender_endpoint |

- **Buttons:**
  - **Refresh from scanners.** Also runs every 6 hours.
  - **Sync tickets.** Compares the remediation tickets with the scanners. A ticket closed while the vulnerability is
    still there is a **false closure**, and the finding reopens. Toast: *checked · verified · false closures*.
  - **Start campaign.** Takes one CVE to every owner at once. The notifications are actions waiting for approval.
  - **Cloud posture.**

### The priority formula (`domains/vulnerability/service.py`)
- **score** = 0.30 × CVSS/10 + 0.25 × EPSS + 0.20 if CISA KEV + 0.10 if internet-exposed + 0.15 × asset criticality.
  - Asset criticality: critical 1.0, high 0.75, medium 0.4, low 0.1.
- **P1** if score ≥ 0.65 **or** (KEV and internet-exposed); **P2** ≥ 0.45; **P3** ≥ 0.25; else **P4**.
- **SLA from first seen:** P1 7 days, P2 15, P3 30, P4 90. CISA's own KEV due date is a US federal deadline: it is
  shown for reference and never used as the SLA.

**Say:** *"CVSS says how bad a bug could be; EPSS and KEV say whether it's actually being exploited; exposure and
criticality say whether it matters here."*

### Likely questions
- **"Why is everything past SLA?"** The sample scanner data first saw these findings in August and September 2026.
  The SLA counts from first seen. On live data it counts from the scanners' real dates.
- **"Who is the owner?"** The host's support group from the CMDB (ServiceNow, or the ownership CSV), mapped to a team.
- **"Do you open tickets automatically?"** `vm.create_ticket` / `ticket.create` are actions like any other:
  recommended, then approved.

---

## 14. Cloud posture

**Who sees it:** the vulnerability domain. Reach it from **Vulnerabilities → Cloud posture** or the sidebar.

**What it is for (say this):** Wiz misconfigurations go through the same lifecycle - owner, deadline, ticket - and
**closure is proved by the tool, never claimed**.

### Section by section
- **Tiles:** Open 2 · Past SLA 2 · False closures 0 · Teams involved 2.
- **Open by severity; Open by owner** (overdue / on time).
- **Table:**
  - *Publicly exposed VM with critical vulnerability and high-privileged identity*: web01, **high**, Web Platform. A
    Wiz "toxic combination".
  - *Storage account allows public blob access*: acmebackups, **medium**, Cloud Platform.
- **Route to owners:** creates a ticket action per team, waiting for approval. In the demo both are already routed.
- **Mark fixed:** the owner claims the fix. **Validate:** asks Wiz whether it still sees the problem.

**Demo it:** on acmebackups, **Mark fixed** → **Validate** → *"Validation: Still present (false closure - reopened)"*.
*False closures* becomes 1, and the row shows *reopened 1*.

---

## 15. ATT&CK coverage

**Who sees it:** everyone.

**What it is for (say this):** which attacks would we actually see, with the tools we have switched on? A planning
tool for licences and gaps, not a slide.

### Section by section
- **Tiles:**
  - **Weighted coverage:** 93.8 %, "56 of 56 techniques". *Full* coverage counts fully; *partial* counts part.
  - **Priority blind spots:** 0.
  - **Single-source:** 4 ("one tool down = blind"): Password Spraying (T1110.003), MFA Request Generation (T1621),
    DNS as an application-layer protocol (T1071.004), Exfiltration to Cloud Storage (T1567.002).
  - **Firing:** 11, observed in alerts and cases.
- **The subtitle** names the enabled detection tools (10).
- **Matrix:** one column per tactic with its coverage %.
  - Demo: Initial Access 87.5, Credential Access 87.5, Exfiltration 50, Impact 83.3; the rest 100.
  - Each cell is a technique, coloured *Full* / *Partial* / *Priority blind spot*, with **●N** for times observed.
  - **Hover** a cell for which tools detect it, and how strongly.
- **Blind spots to close:** appears only when there are any.

### Likely questions
- **"Where does the mapping come from?"** A catalogue of 56 priority techniques in `intelligence/attack_coverage.py`,
  each mapped to the tool categories that can detect it. It is maintained in code, so it can be reviewed.
- **"What if we switch a tool off?"** Its techniques drop immediately; uniquely covered ones become blind spots, and
  the attack story starts showing *Blind spot* for those stages.

---

## 16. Shadow IT

**Who sees it:** the incident domain (DNS telemetry).

**What it is for (say this):** what people use that nobody approved, and risky destinations that were reached.

### Section by section
- From Umbrella DNS activity over the last 7 days. Sanctioned services are kept on Integrations, or in
  `config/sanctioned_services.yaml`. **Rows are aggregated, not stored**: no per-person browsing history is kept.
- **Tiles:** Unsanctioned services 5 · High-risk services 1 · Users involved 4 · Risky sites reached 1.
- **Unsanctioned services:**

  | Service | Category | Risk |
  |---|---|---|
  | anydesk.com | remote access | high |
  | wetransfer.com | file storage | medium |
  | deepseek.com | generative AI | medium |
  | nordvpn.com | personal VPN | low |
  | mega.nz | file storage | low |

  Each row has users (hover for names), requests and blocked counts.
- **By category:** DNS requests per category.
- **Risky destinations:**
  - `login.micros0ft-helpdesk.com`: **Reached**. Phishing category, yet allowed.
  - `update-flash-player.xyz`: **Blocked**. Malware / newly seen.

**Say:** *"The phishing site was reached even though DNS had it categorised as phishing - the block policy has a gap.
That's also raised as a 'control gap' finding on Intelligence."*

---

## 17. Integrations

**Who sees it:** everyone can see the connector list. The rest depends on role:
- *Self-check* and *Notifications* need *read_audit* and all-domain scope.
- **Preflight / Configure / Pause** need *manage_connectors* (Admin, Automation admin).
- **Approving** a configuration change needs *approve_policy* (a **Lead**) and someone other than the proposer.

**What it is for (say this):** this is how the platform goes into a real environment safely: tool by tool, stage by
stage, with checks and two-person changes.

### Section by section
- **Pill:** *Configuration version N* (or "file only"). The configuration in force is `config/connectors.yaml` plus
  the latest approved console change.
- **Configuration changes awaiting approval:** proposals with their changes (from → to), their preflight results and
  the note. *Approve / Reject* for someone else; *Withdraw* for the proposer. A newer approved change makes older
  proposals stale.
- **Platform self-check:** *Consistent - 14 of 14 checks pass*. It runs hourly; a failure raises a finding. The 14
  checks:
  1. actions awaiting approval
  2. open cases
  3. open correlated findings
  4. open vulnerability findings

     (each of 1-4 computed independently by several code paths and compared)
  5. case links resolve
  6. evidence belongs to a case
  7. actions belong to a case or campaign
  8. findings reference existing campaigns
  9. insights reference existing users and hosts
  10. every cited evidence id exists
  11. one case per reported e-mail
  12. reported e-mails point at existing cases
  13. no duplicate active remediation campaigns
  14. the audit chain verifies
- **Connectors (21 enabled):**
  - Tool, internal name and category.
  - **Stage** chip; hover for its meaning. All are *Fixtures* in the demo.
  - **State:** *Healthy* (synced streams fresh), *On demand* (queried during investigations, nothing scheduled),
    *Stale*, *Error* or *Misconfigured*, with the problem and the last preflight result.
  - **Streams · age / expected:** each scheduled stream's last sync age against its expected cadence, for example
    "alerts: 2.0 h / within 1 h" with a *stale* chip.
  - **Actions:** **Preflight**, **Configure**, **Pause**.
- **Configuration:** *Export configuration* (one YAML file) · *Import...* (becomes one proposal) · *History* (every
  version, with **Restore**) · *Suppliers & sanctioned services* (edit both lists; the change is proposed and
  approved the same way) · the stage legend.
- **Notifications:** *"Findings rated high or higher are sent to ... - once per channel, again if a finding
  escalates"*. In the demo there are no channels: *"Set SOC_NOTIFY_WEBHOOKS (Teams, Slack or JSON webhooks)"*. With
  channels, there is a delivery log and *Send test message*. Up to 5 attempts.
- **Scheduled jobs:** last run, outcome, attempts, duration, detail, and **Run now**. Retried with backoff;
  dead-lettered after 3 failed runs (which raises an operational alert).

### The five stages (the rollout story - tell it)

| Stage | What happens |
|---|---|
| **Fixtures** | Sample data, no credentials |
| **Record** | Live reads; responses saved with every identity removed, to test against; no actions |
| **Read** | Live reads; recommendations appear as manual steps for a person to do in the tool |
| **Recommend** | Actions offered; a person approves every one (capped at L2 whatever the policy says) |
| **Automate** | Actions follow the automation policy |

### Preflight (what it checks - click it on CrowdStrike)
- the settings, against a strict schema ("did you mean...?")
- start-up
- sign-in
- **each data stream:** permission, that records parse, freshness, the clock, volume
- write scopes

Each failure names its **fix**. Nothing is written to the tool or the context store. A proposal that moves a tool to
a live stage runs the preflight automatically.

### Configure (walk through the 4 steps on screen)
1. **Secrets** go in the vault or environment, under the variable names shown. The screen only says *Set* / *Not
   set*; **it never asks for, stores or shows a secret**.
2. **Settings:** URLs, tenant ids, mailboxes, field mappings. Advanced settings are folded.
3. **Stage**, and switched on / off.
4. **Propose**, with a reason. Another person approves; it applies within seconds, with **no restart**.

### Pause
Asks for a reason, then stops the tool syncing and offering actions **at once**. Switching it back on needs an
approved change.

### The 21 connectors

| Category | Tools |
|---|---|
| E-mail | Defender for Office 365, Avanan |
| EDR | CrowdStrike Falcon, Defender for Endpoint |
| Identity | Entra ID, Defender for Identity |
| DNS | Cisco Umbrella |
| Deception | Thinkst Canary |
| PAM | Delinea Secret Server, Delinea Privilege Manager |
| Vulnerability / cloud | Rapid7 InsightVM, Wiz |
| Intel | NVD, FIRST EPSS, CISA KEV, threat-intel fusion (8 sources) |
| ITSM / CMDB | ServiceNow, Jira, ownership CSV |
| SIEM | Microsoft Sentinel, generic SIEM/SOAR webhook |

### Likely questions
- **"How long to connect a tool?"** Per tool:
  1. Create a read-scoped service principal and put its secrets in the vault.
  2. Configure it here and run the preflight.
  3. Approve, then move through the stages on evidence.

  Every tool's permissions and egress hosts are in CLIENT_DEPLOYMENT_GUIDE.md.
- **"What if one tool's configuration is broken?"** That tool is isolated and the others keep working. The server
  refuses to start on a broken configuration file, and the console refuses to accept one.
- **"We have a tool you don't support."** One new module: `connector new` generates it with the platform's rules
  built in, and `connector check` runs the same conformance suite as the 21 built in.
- **"Will you hammer our APIs?"** Every tool has a request budget sized under the vendor's limits, plus backoff,
  caching and `Retry-After` handling. Syncs resume from a watermark and never re-read everything.
- **"How do we get alerted?"** Teams, Slack or a JSON webhook (for a SIEM or SOAR), within a minute, for findings
  rated high or above (configurable). Each finding is sent once per channel, and again only if it escalates. Webhook
  URLs are secrets: only the host is ever shown.

---

## 18. Automation policy

**Who sees it:** everyone. Approving a policy change needs *approve_policy* (Lead) and someone other than the
proposer.

**What it is for (say this):** autonomy is not on or off. It is set per action type, as a versioned two-person
decision, with a durable off switch.

### Section by section
- **Subtitle:** *active version* and the levels:
  - **L0 observe:** analysed and recorded only (shadow mode)
  - **L1 enrich:** context assembled, no recommendation surfaced
  - **L2 recommend:** the default for every action
  - **L3 approve:** queued for approval
  - **L4 autonomous:** runs within the policy and can be rolled back

  *Destructive actions are never autonomous.*
- **Actions (26 rows):** action type, *executes via* (which tool), level (all **L2** by default), properties:
  - **destructive** (4): email.campaign_purge, identity.reset_password, identity.confirm_compromised,
    pam.rotate_secret
  - **reversible** (7): dns.block_domain, email.block_sender, email.campaign_purge, email.gateway_quarantine,
    endpoint.isolate, identity.disable_account, indicator.block
- **Kill switch:** status and **Engage kill switch**.
  - Lead, Automation admin and Admin can engage it.
  - **Releasing it needs a lead**, because it re-enables automation.
- **Pending policy changes:** proposals with author and note, and *Approve* (Lead). The proposer cannot approve.
  - Proposals are made through the API by someone with *propose_policy* (the Automation admin role). The screen is
    where they are reviewed and approved.

### Limits no policy can lift (say them)
- **Destructive actions are capped at L3:** never autonomous, whatever the policy says.
- **VIP or critical targets** (the asset tags `critical`, `crown_jewel`, or listed VIP identities and assets) → at most
  L3, and a lead approves.
- **More targets than the action's limit** → at most L3, and a lead approves. **More than 5,000 targets** → refused.
- **A tool in the *Recommend* stage** → capped at L2.
- **Kill switch engaged** → everything capped at L3: nothing runs on its own.

### Likely questions
- **"What does the kill switch actually stop?"** Every *automatic* execution, on every server at once. It is stored in
  the database, so it survives restarts. An action a person explicitly approves still runs. **To stop every write to
  one tool, pause that tool on Integrations.** Describe it exactly this way.
- **"What would you automate first?"** Low-blast-radius, reversible, high-confidence actions, for example blocking a
  known-malicious file hash, once the quality gate on the value scorecard is met. That is a recommendation for the
  organisation to make; nothing is automated by default.

---

## 19. AI usage & limits

**Who sees it:** anyone with *read_audit* can read it. **Only an Admin** (*manage_access*) can change it. Use Ada.

**What it is for (say this):** the AI is optional, bounded and measured, and when it fails nothing that matters
changes.

### Section by section
- **This month / Today:** tokens used against the caps. Demo defaults: **50 M a month**, **5 M a day**; the day
  resets at midnight UTC.
- **Cost, last 30 days:** at the prices set below.
- **By feature:** the 11 features that use the model:
  - incident summary
  - phishing explanation
  - insight narrative
  - situation brief
  - analyst answer
  - analyst planning
  - deep analysis
  - report planning
  - report sections
  - daily exposure report
  - weekly VM report

  Each row shows:
  - calls (refused by limits / not answered)
  - tokens in and out
  - cost, and what it would cost on the other tier
  - **usable %**, and the share of statements the evidence check removed
  - p95 latency
  - **Advice**: *try small*, *use large*, *keep* or *not enough data*, computed from those figures
  - for admins: tier, answer cap, on / off
- **Budgets:** monthly and daily tokens, a warning at 80 %, the longest answer per tier (small 1,500 / large 3,000
  tokens), and the price per million tokens per tier.
- **Limits per person:** everyone 100,000 tokens / hour and 400,000 / day by default. Overrides per role and per
  person; **0 = no model text for them**. Scheduled work counts only against the budgets, so one person can't starve
  it.
- **Who used it** (30 days), **Recent model calls** (filter by feature and outcome; each opens its **Trace**),
  **History** (every version of this policy, with who and why).

### Likely questions
- **"What happens over a limit, or if the model is down?"** The call is not sent. The person gets the platform's own
  cited answer, plus a note saying why. Every figure, verdict and action is identical.
  - Timeouts: 10 s to connect; 30 s to read a short answer, 120 s for long reviews.
  - After 3 failures a circuit breaker uses the deterministic path for 60 s.
- **"Which model?"** Configurable. In the demo it is Azure AI Foundry, gpt-4.1-mini. In production, the endpoint the
  organisation approves - including **the client's in-house LLM gateway**, through the OpenAI-compatible or Anthropic
  provider. Endpoints not on the approved list are refused (fail closed); the model version is pinned and a mismatch
  is logged.
- **"What does it cost?"** Measured at gpt-4.1-mini: about $0.002 per incident summary, $0.001 per phishing
  explanation or question, $0.004 per deep analysis. About **$5 / $26 / $150 a month** for a small / mid / large SOC.
  Auto-closed benign mail costs nothing.
- **"What data does the model see?"** Only the evidence for that task. Internal users, names, phone numbers and
  national ids are **pseudonymised** before the prompt leaves and restored after. Every prompt (redacted) and answer
  is stored for 180 days.

---

## 20. Reports

**Who sees it:** everyone. Exports are filtered by domain scope; the compliance pack and audit export need
*export_evidence* (Lead, Admin, Auditor).

**What it is for (say this):** reporting whose numbers can't drift from the data, and audit evidence on demand.

### Section by section
- **Callout:** *"Narrative is written by the approved LLM (azure_foundry) from computed figures; every sentence must
  cite a figure or it is removed"*, or, with no AI, *"deterministic templates ... the figures are identical either
  way"*.
- **Describe a report:**
  1. Type, for example, `A one-page board brief on phishing and supplier risk this month, as slides`.
  2. Click **Plan report**. The plan shows the title, audience, format, period, *planned by the LLM (catalogue sources
     only)* or *keyword rules*, and the sections, each tied to a data source.
  3. **Review it**, then **Generate**, or **Save as template**.

  Sections can come only from the **17-source catalogue**; an unknown source is rejected.
- **The generated report card:** each section shows its narrative with a *writer* tag, and **Figures (n)**: the
  F1..Fn facts it was allowed to cite. Then **Download PowerPoint / Word**.
- **Standard reports (7):**

  | Report | Format | Audience | Period |
  |---|---|---|---|
  | Monthly security report to the board | PowerPoint | board | 30 d |
  | CISO weekly brief | Word | CISO | 7 d |
  | Weekly vulnerability management report | Word | platform teams and IT leadership | 7 d |
  | Monthly phishing and awareness report | Word | security awareness and HR | 30 d |
  | Post-incident report | Word | incident review board | 30 d (pick an open critical / high case) |
  | Quarterly control assurance report | Word | audit and risk committee | 90 d |
  | SOC daily situation report | Word | SOC team | 1 d |

- **Exports:**
  - Daily exposure report (Word)
  - Weekly vulnerability report (Word)
  - Management deck (PowerPoint, all-domain scope only)
  - **Compliance evidence pack:** a ZIP of control tests, evidence JSON, the chained audit export and a summary. The
    screen says "N of M control tests passed".
  - **Audit export:** the full hash-chained log as JSON Lines, with verification, for archiving or a SIEM.

### The 17 data sources
SOC overview, vulnerability posture, top vulnerabilities, cloud misconfigurations, reported phishing, supplier e-mail
risk, incidents, attack stories, incident narrative, correlated findings, highest-risk users and hosts, detection
coverage, shadow IT, control evidence, verdict quality, integration health, value scorecard.

### Likely questions
- **"Could the AI put a wrong number in the board deck?"** No. Every figure is computed in code and given to the
  writer as F1..Fn. A sentence stating a figure not in its cited facts is removed. The figures appear in the document
  alongside the prose.
- **"What does the compliance pack test?"**
  - the audit chain is intact
  - four-eyes actions had two different approvers
  - no policy was approved by its author
  - MFA is enforced
  - retention ran
  - and the other controls
- **"Who can download a report?"** The download re-checks that the reader's scope covers every domain in the report,
  and the builder's scope. Case reports need access to the case.
- **"Our own templates?"** The house style is generic until the organisation's Word and PowerPoint templates are
  supplied; they plug in.

---

## 21. Access

**Who sees it:** everyone sees *Your access*. Only an **Admin with MFA** (*manage_access*) sees the rest. Use Ada.

### Section by section
- **Your access:** signed in as, roles, data scope, MFA (*"No - approvals are disabled"* without it), permissions.
- **Role assignments:** platform grants on top of Entra roles. Each shows the principal, reason, granted by, role,
  scope and expiry. A grant waiting for approval shows *Awaiting a second admin*, with **Approve** for another admin.
  **Revoke** on each.
  - **Grant form:** user, role, domain scope, days (blank = no expiry), justification (required).
- **Service accounts:** API keys for integrations.
  - Create one with a name and a role (Auditor / Analyst / Automation admin). It expires in 90 days.
  - **The key is shown once.**
  - Last used, Revoke. *"Can never approve actions."*
- **Role permissions:** the matrix, including the row *Never granted to service accounts*: approve_action,
  approve_high_impact, approve_policy, manage_access, propose_policy, rollback_action.

### The five roles

| Role | Can | Cannot |
|---|---|---|
| **Analyst** | read, investigate, request and approve routine actions, resolve entities, read audit | approve high-impact, roll back, policy, kill switch |
| **Lead** | analyst's rights + approve high-impact, roll back, approve policy and configuration, kill switch, export evidence | manage access, manage connectors |
| **Automation admin** | propose policy, manage connectors, kill switch, read audit | approve any action or its own policy (separation of duties) |
| **Admin** | manage access, manage connectors, kill switch, export evidence, read audit | approve actions, approve policy |
| **Auditor** | read everything in scope, read audit, export evidence | change anything |

### Rules to quote
- **Nobody can change their own access.**
- A **lead, admin or automation admin** grant needs **a second administrator** and lasts **at most 90 days**.
- **Each role acts only inside its own scope.** Someone who is a phishing lead and an all-domain auditor reads
  everything, but approves phishing actions only. A pen test found this merged once; a test pins it now.
- **MFA is required** (step-up) for approving, rolling back, policy, the kill switch and access management.
- **Break-glass:** a sealed emergency credential (only its hash is configured), exchanged for a 15-minute session.
  Every use is audited and raises an alert; guesses are throttled.

---

## 22. Audit log and Trace

### Audit log
**Who sees it:** *read_audit*. Domain-scoped users see only the records about their domains.

- **Pill:** *Chain verified · N records in the full log* (81 right after a reset; it grows with every action). If
  anything were altered: *Chain broken at #N*.
- **Table:** the latest 300 records: sequence, time, actor (agent or person), event (`action.requested`,
  `case.assessed`, `action.first_approval`...), subject, and **Trace** (all-domain only).

**How it works (say this):**
- **Append-only:** the application, a database trigger and the database role's grants all refuse update and delete.
- **SHA-256 hash-chained:** each record carries the hash of the one before, so changing or deleting any record breaks
  the chain.
- The chain's head is shipped to the log platform hourly. Even a database owner can't rewrite history unnoticed;
  `python -m soc_platform audit verify --anchor SEQ:HASH` proves it against a shipped head.
- Every successful write request is guaranteed at least one audit record, even from a route whose code forgot one.

**After your four-eyes demo:** point at the two approval records of the isolation, with two different actors.

### Trace
Click **Trace** on an audit row: everything that one request or job run caused, in order.
- **Job run:** job, outcome, attempts, trigger, error.
- **Request:** who, method and path, status, latency.
- **Audit events:** with their payloads.
- **Model calls:**
  - feature, tier, tokens, latency, model
  - *"N statements kept, M removed by the evidence check"*, with each removed statement quoted and its reason
    ("cites no evidence", "states a figure its evidence doesn't contain")
  - **the prompt as sent, with identities pseudonymised, and the answer**

**Say:** *"When an auditor or a regulator asks 'why did the platform recommend this?', this page is the answer -
including exactly what the AI was shown and what was thrown away."* The same trace id is on every log line sent to the
SIEM.

---

## 23. Search

The box in the top bar takes at least 2 characters and is scoped to what your role may see. It searches four groups:

| Group | What it matches |
|---|---|
| **Cases** | title or id |
| **People, hosts and indicators** | any identifier from any tool: a hostname, UPN, SAM, device id, IP, hash, domain |
| **Correlated findings** | finding titles |
| **Vulnerabilities** | CVE or asset |

**Demo searches:**
- `jane-lt01` → the host, 3 correlated findings, 1 vulnerability finding.
- `CVE-2021-44228` → the Log4Shell finding.

The typed text is always treated literally (no injection).

---

## 24. Questions that cut across every page

**"Is this hard-coded to the demo?"**
- No. The test suite renames the entire organisation into three other generated estates - different people,
  machines, volumes and messy real-tenant data. It requires the same results and **zero leaked demo names**.
- Pipeline code contains no demo values. The connectors read vendor-shaped data through the same parsers as live.

**"Will it work with our real data?"**
- It is built to each vendor's documented API, with paging, resume, throttling, token renewal and missing or
  malformed fields all tested per connector.
- It has not yet run on a real tenant. The *Record → Read → Recommend* stages and the preflight exist precisely to
  catch vendor differences safely before anything acts.

**"What happens when a tool is down?"**
- That source shows as *unavailable* on the case, and on Integrations as error or stale. Everything else keeps
  working.
- A reported e-mail is still judged from its own content. Reports leave out only the unavailable section. A feed
  outage never clears KEV flags.
- Tested with every tool down at once.

**"Where does it run? Where does our data go?"**
- In the organisation's own environment: its Azure tenant (Kubernetes, PostgreSQL) or on-prem.
- Stored e-mails, reports and raw payloads are encrypted at rest (Fernet, rotatable).
- The only outbound destinations are the configured tool endpoints, the approved LLM endpoint and HTTPS webhooks.

**"How long is data kept?"**
- Raw payloads 180 days; model-call logs 180 days; the access log 400 days; event telemetry 400 days.
- Open cases are on legal hold. The platform never prunes the audit log.

**"Is it highly available?"**
- Two or more API and scheduler replicas, HA PostgreSQL holding all state (stored e-mails and reports included), and
  leased jobs.
- A dead scheduler's job is taken over within about two minutes. Liveness never restarts pods during a database
  outage. (HIGH_AVAILABILITY.md has the designs.)

**"How fast is it?"**
- With every vendor call at 400 ms: a reported e-mail is fully analysed in about 3 s (9-12 s with the AI
  explanation); an incident investigation takes 2-3 s.
- Analysis runs in the background as data arrives. Opening a case takes under 0.1 s.

**"How big can it get?"**
- Measured at 20,000 entities: risk ranking 0.06 s, correlation 0.09 s.
- 100 concurrent analysts at 150 requests/s with no errors, on four server processes.
- The organisation's own volumes are first seen in its environment.

**"How was it tested?"**
- 820 platform tests (SQLite, with PostgreSQL's rules enforced) and 819 on PostgreSQL; 205 engine tests.
- 108 of 108 features verified feature by feature.
- 24 penetration tests and 11 fuzzing properties.
- Time-travel tests (0 / 45 / 400 days).
- A consistency suite: the same figure on every surface, every pipeline run twice, AI on vs off identical.
- A real-browser tour with an accessibility scan (WCAG 2.1 A/AA, 0 findings) and a stored-XSS probe.

**"Can an analyst's browser be attacked through a malicious e-mail?"**
- Everything shown is escaped, and the strict Content-Security-Policy allows no inline script.
- The browser tour puts script in the subject, sender, body, link and attachment name, and views it on 8 screens:
  nothing runs.

**"What do you need from us?"**
- API access per tool (read scopes first, dedicated service principals)
- an Entra app registration
- a CMDB / ownership source
- representative historical data for tuning
- decisions on hosting and residency
- the LLM endpoint to use

---

## 25. Cheat sheet: formulas and numbers

| Thing | Value |
|---|---|
| Risk score | 100 × (1 − e^(−points/60)); half-life 7 d; open exposure / incidents don't decay; bands 80 / 60 / 30 |
| Vulnerability priority | 0.30·CVSS/10 + 0.25·EPSS + 0.20 KEV + 0.10 exposed + 0.15·criticality; P1 ≥ 0.65 or KEV + exposed; P2 ≥ 0.45; P3 ≥ 0.25 |
| Vulnerability SLA | P1 7 d · P2 15 d · P3 30 d · P4 90 d, from first seen |
| Phishing verdict | malicious ≥ 0.70 (≥ 0.50 with malicious intel); suspicious ≥ 0.35; auto-close ≥ 0.7 confidence; 10 % QA sample |
| Incident severity | tool's rating → decoy = critical → KEV +1 → exposed / critical host with KEV ≥ high → 3+ areas ≥ high |
| Incident confidence | 35 % + 10 % per area, max 95 %; true positive = ≥ high and ≥ 60 % |
| Entity resolution | auto ≥ 0.85 with a 0.1 margin; review queue ≥ 0.55 |
| Story step | same stage within 15 min; high confidence = 2+ tools or a critical detection |
| Enrichment | 16 parallel workers, 20 s deadline, 30 min cache |
| Autonomy | L0 observe · L1 enrich · L2 recommend (default) · L3 approve · L4 autonomous |
| Jobs | phishing 2 min · incident 5 min · intelligence 10 min · vulnerability 6 h · self-check 1 h · notify 1 min · actions 1 min · follow-up, daily report, retention daily · weekly reports weekly |
| AI defaults | 50 M tokens / month, 5 M / day, warn at 80 %; 100 k / hour and 400 k / day per person; answers ≤ 1,500 (small) / 3,000 (large) tokens |
| Retention | raw 180 d · model logs 180 d · access log 400 d · events 400 d · audit never pruned |

**Demo figures after a reset:**
- Cases: 10 (7 phishing, 3 incident), 8 open, 2 auto-closed.
- Approvals: 37 (incident 18, phishing 16, vulnerability 3).
- Correlated findings: 20 (14 critical, 3 high, 3 medium).
- Vulnerabilities: 6 open, all past SLA (P1 3, P2 3; 5 KEV; 3 exposed).
- Cloud: 2 misconfigurations.
- ATT&CK: 93.8 % coverage, 0 blind spots, 4 single-source, 11 firing.
- Shadow IT: 5 unsanctioned services.
- Self-check: 14 / 14.
- Risk: Jane 100, jane-lt01 98, web01 71, db01 46.
- Story: confirmed compromise, 14 steps, 10 tools, 43 min.

---

## 26. When something goes wrong live

| Symptom | Do / say |
|---|---|
| The sign-in page fails or says dev sign-in is off | `.env` wasn't loaded in the shell that started the server. Restart with `scripts\serve_with_env.cmd` |
| A page spins for 10-20 s | The model is writing (brief, deep analysis, report). *"This is the optional narrative - the computed view is already complete."* |
| *Deep analysis unavailable* | No AI configured, or the budget is exhausted: *"the platform falls back automatically; the story is complete without it."* |
| An approval is refused | Four-eyes, self-approval or a missing role: *"that's the control working."* Approve from Alice's window |
| A four-eyes action didn't run after your approval | Correct: it needs a second, different lead |
| Numbers differ from these notes | Time has passed (risk decay, SLA ages) or you approved something. Stop the server, `python -m soc_platform reset-demo --yes`, start again |
| A connector shows *stale* | The sample data is dated, or the scheduler hasn't run yet. *"Freshness is checked against each stream's cadence - that's the monitoring working."* Run the job from Integrations |
| *Scheduler stopped* banner | The background job runner isn't running in this process. Restart the server; the banner exists so this can't go unnoticed |
| A question you can't answer | *"I'll confirm that from the code and come back to you."* Never guess a number |

---

## 27. Claims you must not make

- ❌ "It's running in production / on a real tenant." → ✅ "It runs on vendor-shaped data through the production code;
  live connection is per tool, through preflight and staged rollout."
- ❌ "The AI decides / detects / scores." → ✅ "Code decides; the AI explains, with citations, and can be switched off."
- ❌ "99 % / 100 % accurate." → ✅ "On our small labelled test set, combined detection was 100 %; real accuracy is
  measured in shadow mode on your data."
- ❌ "It isolated the laptop." → ✅ "In this demo, against the simulated tool, after two approvals."
- ❌ "The kill switch stops everything." → ✅ "It stops automatic execution; pausing a tool stops every write to it."
- ❌ "Pen-tested." → ✅ "Internally pen-tested with 24 automated attack tests; an independent test is recommended
  before go-live."
- ❌ Any number not on the screen or in these notes. Read it off the screen, or offer to confirm it.
- ❌ Naming the real client or the client's in-house LLM platform. Say "your organisation" and "your in-house LLM
  gateway".
