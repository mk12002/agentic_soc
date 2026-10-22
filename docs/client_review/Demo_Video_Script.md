# Demo video script - Agentic SOC platform, every screen in 15 minutes

A screen recording with voice-over that shows **every screen of the platform** on the built-in demo organisation
(`acme-demo.com`, fictional, vendor-shaped data from 21 tools). Every screen and figure below was read from that
demo. Voice-over about 1,300 words - about 9-10 minutes of speech; with 21 screens of clicks, hovers and page
loads the video runs about 15 minutes. Keep clicks brisk and narrate while pages load.

Each scene: **ON SCREEN** is what to click; **VOICE-OVER** is read as written.

---

## Before you record

1. **Same-day reset.** Server stopped: `python -m soc_platform reset-demo --yes`, then `python -m soc_platform serve`
   and open `http://127.0.0.1:8080`. Risk scores decay with time - record on the day you reset.
2. **AI on.** Load the LLM settings (`. .\scripts\load_env.ps1`) before `serve`. Without them every screen still
   works with the platform's own text; skip the deep-analysis line in scene 6.
3. **Two sign-ins:** **Lead** (`lena@acme-demo.com`) for scenes 1-17, **Admin** (`ada@acme-demo.com`) for scenes
   18-20 (AI usage and Access need it). Open the Admin session in a second browser profile before recording, and
   switch windows at scene 18 instead of signing out on camera.
4. **Prepare two inputs:** keep `artifacts/phishing/corpus/html_attachment_phish.eml` ready for the upload in scene 10 (the demo
   has not used it yet, so it opens a new case),
   and the report request text for scene 19 in your clipboard.
5. **Browser:** 1920 x 1080, zoom 90 %, clean profile, light theme.
6. **Rehearse the clicks once** - first page loads are slower. Read any number you add off your screen.

---

## Every screen, and where it appears

| Screen | Scene | | Screen | Scene |
|---|---|---|---|---|
| Sign-in (roles, domain scope) | 1 | | Cloud posture | 12 |
| Overview (+ value scorecard) | 2 | | ATT&CK coverage | 13 |
| Intelligence (brief, ask, findings) | 3 | | Shadow IT | 13 |
| Cases list | 4 | | Search | 14 |
| Phishing case | 5 | | Integrations (preflight, configure, approval, pause) | 15 |
| Attack story + deep analysis | 6 | | Automation policy + kill switch | 16 |
| Entity 360 | 7 | | Audit log + trace view | 17 |
| Incident case | 8 | | AI usage & limits | 18 |
| Approvals | 9 | | Reports (plan, generate, compliance pack) | 19 |
| Phishing screen (+ upload) | 10 | | Access | 20 |
| Supplier risk | 10 | | Dark mode | 21 |
| Vulnerabilities | 11 | | | |

| Scene | Time | Scene | Time | Scene | Time |
|---|---|---|---|---|---|
| 1 Opening, sign-in | 0:35 | 8 Incident case | 0:40 | 15 Integrations | 0:55 |
| 2 Overview | 0:45 | 9 Approvals | 0:35 | 16 Automation policy | 0:25 |
| 3 Intelligence | 1:00 | 10 Phishing, suppliers | 0:50 | 17 Audit, trace | 0:30 |
| 4 Cases | 0:15 | 11 Vulnerabilities | 0:50 | 18 AI usage | 0:35 |
| 5 Phishing case | 1:30 | 12 Cloud posture | 0:20 | 19 Reports | 0:45 |
| 6 Attack story | 1:30 | 13 Coverage, shadow IT | 0:40 | 20 Access | 0:25 |
| 7 Entity 360 | 0:25 | 14 Search | 0:15 | 21 Closing | 0:30 |

---

## 1. Opening and sign-in (0:35)

**ON SCREEN:** the sign-in page; pick **Lead**, all domains; **Continue**. Land on the Overview.

**VOICE-OVER:**
> Every security team has good tools. The problem is the time between them: one alert, five consoles, then the
> write-up. This is the Agentic SOC platform: one layer over the tools you already own that gathers and correlates
> the evidence and hands the analyst one view. The analyst decides - nothing changes in a security tool until a
> person approves it.
>
> In production, analysts sign in with Entra ID and MFA; their role and domain decide what they see and approve.
> Everything here runs on a fictional company, Acme, with data from twenty-one security tools.

---

## 2. Overview (0:45)

**ON SCREEN:** the KPI tiles, the riskiest users and hosts, then scroll to *Data quality*, *Integrations*, the value
scorecard.

**VOICE-OVER:**
> The overview: open cases, actions awaiting approval, and an automation rate of zero - by default nothing runs
> without a person. Every figure is computed from stored records and drills down to them. Each risk score shows
> which tools contribute.
>
> The platform checks itself - record matching across tools, integration health. And the value scorecard measures
> each benefit against your own baseline: measured by the platform, never by the AI.

---

## 3. Intelligence (1:00)

**ON SCREEN:** **Intelligence**. Pause on the brief. Ask `Is jane.doe@acme-demo.com compromised and what should we do
first?` → **Ask**; hover a reference. Scroll *Correlated findings*.

**VOICE-OVER:**
> Intelligence correlates across every domain. The situation brief summarises what matters for the shift lead.
>
> I ask: is Jane Doe compromised, and what should we do first? The answer cites its evidence, shows which read-only
> lookups it used, and names the first step - revoke her sessions and reset her credentials.
>
> The facts and scores are computed by the platform; the AI only writes the explanation, and any statement without
> valid evidence is removed. Switch the AI off: same facts, same first step.
>
> Below, findings from fixed rules: a phishing click, then a suspicious command on her laptop, then a sign-in from
> an anonymising network - one chain across three tools, with next steps.

---

## 4. Cases (0:15)

**ON SCREEN:** **Cases**; click the domain filter, then *Mine / Unassigned*.

**VOICE-OVER:**
> Every investigation in one list - phishing, incidents, vulnerabilities - with owners and filters. Clear spam and
> safe reports were closed automatically, with a sample kept for quality review.

---

## 5. Phishing case (1:30)

**ON SCREEN:** open **Reported: Action required: your password expires today** → **Take case**. Hover two
E-references; point at the *Analysis* panel, *MITRE ATT&CK*, *Recommended actions*, the *Timeline*.

**VOICE-OVER:**
> The report that started it. I take the case - that is recorded.
>
> Every statement carries a reference: a look-alike Microsoft domain, failed authentication, a link rated malicious
> by three intelligence sources. Facts are kept apart from inferences.
>
> It went far beyond one report: eight people received the campaign; Jane clicked through; another click was
> blocked - and a blocked click is never counted. Then it checked her laptop and account. A report became a
> compromise investigation in seconds.
>
> The verdict combines trained models for each part of the e-mail with fixed rules, offline inside the platform,
> mapped to MITRE ATT&CK. No link from an e-mail is ever opened.
>
> The recommended actions show blast radius and reversibility; isolating the laptop needs a second approver. None
> has run. The timeline orders every tool's events: e-mail, click, PowerShell, risky sign-in, privileged secret.

---

## 6. Attack story and deep analysis (1:30)

**ON SCREEN:** **Attack story**: *Confirmed compromise*, the *Kill chain*, two steps, *Benign explanations tested*,
*Gaps*, *Blast radius*, *Response plan*. Click **Run deep analysis**.

**VOICE-OVER:**
> The attack story reconstructs the incident across tools: confirmed compromise, from the e-mail to credential
> access in about three quarters of an hour, seen by ten tools. The kill chain shows what was observed, what was
> blocked - a privilege-escalation attempt - and what was checked and clean.
>
> It tests the other explanations - legitimate e-mail, travel, normal IT work - and rejects or keeps each, with the
> reason. The gaps show what was looked for and not found. The blast radius maps every person, host and secret; the
> response plan is phased, and several actions can be approved together, each still checked.
>
> The optional deep analysis is a second opinion from the AI on this evidence alone, identities pseudonymised.
> Uncited statements are removed; the analyst decides.

---

## 7. Entity 360 (0:25)

**ON SCREEN:** click **jane.doe@acme-demo.com**: risk factors, per-tool identifiers, timeline.

**VOICE-OVER:**
> One person across every tool: mailbox, account, laptop, privileged vault - linked by strong identifiers. An
> ambiguous match is never guessed; it goes to an analyst.

---

## 8. Incident case (0:40)

**ON SCREEN:** back to **Cases** → **Exchange Server exploitation attempt blocked**. Point at the severity factors,
evidence by source, the ticket action.

**VOICE-OVER:**
> Incidents work the same way. Related alerts are grouped by host and person. For every host, user, address and
> hash, all tools are queried in parallel within a time limit; a tool that does not answer is shown as unavailable,
> never as clean. Severity comes from fixed rules - every factor shown, the same evidence always the same result.
> If two tools disagree, the conflict is shown and actions are held.

---

## 9. Approvals (0:35)

**ON SCREEN:** **Approvals**; **Approve** `email.reporter_feedback`.

**VOICE-OVER:**
> Every recommended action lands here. I approve one - in this demo it runs through the simulated tool, and the
> request, approval and result are recorded. Nobody approves their own request; high-impact actions need a lead;
> irreversible actions - removing mail, resetting passwords - never run automatically. Every action is idempotent.

---

## 10. Phishing screen and supplier risk (0:50)

**ON SCREEN:** **Phishing**: the tiles, *Users who clicked*; in *Analyse a message* choose the prepared `.eml` →
**Analyse**. Then **Supplier risk** → **Krishna Logistics**.

**VOICE-OVER:**
> The phishing screen: reports, auto-closed, campaigns, repeat clickers, time to containment. Reports arrive from
> the report button every couple of minutes - or I upload a message, and its verdict and actions open as a case.
>
> Supplier fraud: one e-mail from a domain one letter away from a real supplier; another from the supplier's real
> domain asking to change bank details - their mailbox is probably compromised. The advice: call a number you
> already have.

---

## 11. Vulnerabilities (0:50)

**ON SCREEN:** **Vulnerabilities**: tiles; *Ask about exposure* `which internet facing hosts have KEV
vulnerabilities?` → **Query**; *Coverage gaps*; the findings.

**VOICE-OVER:**
> Four scanners name the same server differently; seventeen raw findings became six, one per device and
> vulnerability. Priority is computed and explained - severity, EPSS, the CISA known-exploited catalogue, exposure,
> criticality - with a deadline each.
>
> Questions are answered from the data, with the filter shown. Owners come from the CMDB; Log4Shell got a campaign.
> Coverage gaps show a laptop with no EDR. A finding closes only when a new scan confirms the fix - a falsely closed
> ticket is caught.

---

## 12. Cloud posture (0:20)

**ON SCREEN:** **Cloud posture**: the two findings and **Validate**.

**VOICE-OVER:**
> Cloud misconfigurations - a toxic combination on an exposed VM, a public storage account - are routed to owners
> and closed only when the cloud tool confirms.

---

## 13. ATT&CK coverage and shadow IT (0:40)

**ON SCREEN:** **ATT&CK coverage**, then **Shadow IT**.

**VOICE-OVER:**
> Which attacks can you see? Every ATT&CK technique mapped to your enabled tools - switch one off and the blind
> spots appear.
>
> Shadow IT from DNS: remote access, file sharing, an unsanctioned AI service - and a phishing site reached despite
> its category, raised as a control gap.

---

## 14. Search (0:15)

**ON SCREEN:** type `jane-lt01` in the top search, Enter; then `CVE-2021-44228`.

**VOICE-OVER:**
> One search across cases, people, hosts, every tool's identifiers and CVEs.

---

## 15. Integrations (0:55)

**ON SCREEN:** **Integrations**: the self-check line, the connector list, the stages legend. **Preflight** on one tool;
**Configure** on one tool, change a setting, propose; show it awaiting approval. Point at *Pause*, *Notifications*,
*Scheduled jobs*.

**VOICE-OVER:**
> Twenty-one connectors, each with its own least-privilege identity, connected read-only first. Every tool moves
> through stages - fixtures, recording, read-only, recommend, and automate only by a separate decision.
>
> A preflight checks sign-in, permissions and data before a tool is trusted, naming the fix for anything that fails.
> A configuration change is proposed by one person and approved by another. Pausing a tool stops every write at
> once. Notifications go to Teams or Slack, and every scheduled job is visible. The platform checks itself hourly.

---

## 16. Automation policy (0:25)

**ON SCREEN:** **Automation policy**: the levels, *Reversible*, the kill switch card.

**VOICE-OVER:**
> Every action has a level, from observe to autonomous; the default is recommend. Changes need two people,
> irreversible actions are never autonomous, and the kill switch stops all automatic execution at once.

---

## 17. Audit log and trace (0:30)

**ON SCREEN:** **Audit log**: the *Chain verified* badge; click a **Trace** link.

**VOICE-OVER:**
> Every change and decision is chained with a cryptographic hash - verified here. From any entry, the full trace:
> the request, its audit events, every model call with what the evidence check removed. Every "why?" has an answer.

---

## 18. AI usage (0:35)

**ON SCREEN:** switch to the Admin window. **AI usage**: this month and today, the feature table, budgets, limits per
person, *Recent model calls*.

**VOICE-OVER:**
> The AI is optional, and an administrator controls its cost: monthly and daily budgets, limits per person, and for
> each feature which model it uses - chosen from measured answer quality. Over a limit nothing breaks; the platform
> answers without the model.

---

## 19. Reports (0:45)

**ON SCREEN:** **Reports**: the standard reports; paste `A one-page board brief on phishing and supplier risk this
month, as slides` → **Plan report** → generate; open the file. Click **Compliance evidence pack**.

**VOICE-OVER:**
> Standard reports for the SOC, the CISO and the board, generated from live data. Or I describe a report in words:
> the platform plans it from its data sources, I review the plan, and it builds the deck. Numbers come only from the
> data. For auditors, a compliance evidence pack tests the controls.

---

## 20. Access (0:25)

**ON SCREEN:** **Access**: role assignments, service accounts, role permissions.

**VOICE-OVER:**
> Time-bound, domain-scoped role grants on top of Entra roles; service-account keys for integrations, which can
> never approve actions. Nobody can change their own access.

---

## 21. Closing (0:30)

**ON SCREEN:** toggle dark mode; back to the Overview.

**VOICE-OVER:**
> One layer over your tools. One picture of every person and host. Investigations in seconds, every conclusion
> cited, every decision computed - and the analyst in control, every step recorded, in your own environment.
>
> Thank you for watching.

---

## Before you publish

- Every tool is simulated in this demo (vendor-shaped data, the same code paths); say "in this demo" if an approved
  action appears to run.
- Numbers you add from the screen move with time and with the AI's wording - read them on the day.
- The video shows only the fictional Acme organisation; record no real tenant or data.
