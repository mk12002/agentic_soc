# Demo video script - Agentic SOC platform, every screen in about 20 minutes

A screen recording with voice-over that walks through **every section of every screen** on the built-in demo
organisation (Acme, `acme-demo.com`, fictional). Every figure and behaviour below was read from a freshly reset
demo and checked against the code on 2026-10-22; where a value depends on the day or on the AI's wording, the script
says "read it off the screen". Voice-over about 2,800 words - about 18 minutes of speech at a steady pace; with
clicks and page loads the scenes add up to about 21 minutes.

Each scene has **ON SCREEN** (what to click, section by section, top to bottom) and **VOICE-OVER** (read as
written). Section names in *italics* are the headings exactly as the console shows them.

---

## Before you record

1. **Start the server with `.env` loaded** (the platform reads settings only from the environment). PowerShell, in
   the project folder:
   ```powershell
   .\.venv\Scripts\Activate.ps1
   . .\scripts\load_env.ps1
   python -m soc_platform reset-demo --yes
   python -m soc_platform serve
   ```
   From Command Prompt: `scripts\serve_with_env.cmd reset`. Wait until the log shows the phishing ML engine loaded
   (about 15 s) and the first scheduled jobs have run (about a minute) - the compliance pack in scene 20 tests that
   the retention job has run.
2. **AI on** comes from `SOC_LLM_*` in `.env`. Case summaries, the situation brief, the analyst's answers and the
   deep analysis are then written by the model from the platform's evidence; their wording changes between runs, so
   read them off the screen. Everything numeric is identical with the AI off.
3. **Three sign-ins, three browser profiles** (tabs of one browser share a sign-in):
   - **Lead** `lena@acme-demo.com`, all domains - the main window, scenes 1-14, 16, 17, 19, 20.
   - **Second lead** `alice@acme-demo.com`, all domains - only for the second approval in scene 10.
   - **Admin** `ada@acme-demo.com`, all domains - scenes 15, 18, 21 (only an administrator manages integrations, AI
     limits and access).
   Sign all three in before recording; switch windows instead of signing out on camera.
4. **Upload file:** `artifacts/phishing/corpus/html_attachment_phish.eml` (scene 11; the demo has not used it).
5. **Clipboard:** `Is jane.doe@acme-demo.com compromised and what should we do first?` (scene 3), `which internet
   facing hosts have KEV vulnerabilities?` (scene 12), `A one-page board brief on phishing and supplier risk this
   month, as slides` (scene 20).
6. **Browser** 1920 x 1080, zoom 90 %, light theme. Rehearse once - first page loads are slower.
7. **Approve nothing before recording**: the figures below (37 actions awaiting approval, 8 open cases) are the
   reset state.

**What is staged by the demo set-up, not by the pipelines** (say so if asked): a demo analyst opened the Log4Shell
remediation campaign and routed the two cloud findings to their owners, and six of the seven reported e-mails were
uploaded as samples (one arrived through the report mailbox). Everything else - verdicts, cases, correlation, risk,
severity, recommendations - was computed by the platform from the 21 tools' sample data.

---

## Scene list

| # | Screen | Time | # | Screen | Time |
|---|---|---|---|---|---|
| 1 | Opening, sign-in | 0:40 | 12 | Vulnerabilities | 1:15 |
| 2 | Overview | 1:30 | 13 | Cloud posture | 0:40 |
| 3 | Intelligence | 1:30 | 14 | ATT&CK coverage, Shadow IT | 1:00 |
| 4 | Cases | 0:30 | 15 | Integrations (Admin) | 1:20 |
| 5 | Phishing case | 2:00 | 16 | Automation policy | 0:35 |
| 6 | Attack story | 1:45 | 17 | Audit log, trace | 0:40 |
| 7 | Entity 360 | 0:40 | 18 | AI usage (Admin) | 0:45 |
| 8 | Incident case | 1:15 | 19 | Search | 0:20 |
| 9 | Phishing screen | 0:45 | 20 | Reports | 1:00 |
| 10 | Approvals (two leads) | 1:00 | 21 | Access (Admin), closing | 0:50 |
| 11 | Upload, Supplier risk | 0:50 | | | |

---

## 1. Opening and sign-in (0:40)

**ON SCREEN:** the sign-in page. Pick **Lead**, all domains, **Continue**. Land on the Overview.

**VOICE-OVER:**
> Every security team owns good tools. The time goes between them: one alert, five consoles, then the write-up.
> This is the Agentic SOC platform - one investigation and automation layer over the tools you already have. It
> gathers and correlates the evidence, computes the verdicts and scores in code, and recommends actions. A person
> decides: nothing changes in a security tool until it is approved.
>
> In production, people sign in with Entra ID and MFA, and their role and domain decide what they see and may
> approve. Everything here is a fictional company, Acme, with sample data from twenty-one security tools, run
> through the same code that reads the real tools.

---

## 2. Overview (1:30)

**ON SCREEN**, top to bottom:
- The six tiles: *Open cases* 8 (incident 3, phishing 5) · *Awaiting approval* 37 · *Automation rate* 0.0 % ·
  *Median time to close* · *Open insights* 20 · *Open vulnerabilities* 6 (6 past SLA, 3 exposed).
- *Value scorecard* - the KPI table; open "Enter a baseline, target or time-study figure" for a second.
- *New cases per day* and *Open cases by severity* (critical 3, high 4, medium 1).
- *Highest-priority insights* and *Riskiest users and hosts* (jane.doe 100, jane-lt01 98, web01 71).
- *Data quality*, *Integrations*, *Enrichment latency*, *Verdict quality*.

**VOICE-OVER:**
> The overview covers the last fourteen days across phishing, incidents and vulnerabilities. Eight open cases;
> thirty-seven recommended actions waiting for a person; and an automation rate of zero - by default nothing runs on
> its own. Twenty correlated findings, and six open vulnerabilities, all past their deadline.
>
> The value scorecard measures what the platform is deployed for - handling time, time to contain, time to a
> validated fix - from its own timestamps. A lead enters the baseline from before go-live and the target; until
> then it says "awaiting baseline", it never guesses.
>
> New cases per day and open cases by severity. The highest-priority findings, and the riskiest people and hosts,
> each with the areas their risk comes from.
>
> The bottom row is the platform checking itself. Data quality: every host and person from every tool was matched
> to one record - one hundred percent here, and anything ambiguous waits for an analyst instead of being guessed.
> Integrations lists any tool that is failing or stale. Enrichment latency is how long an investigation's look-ups
> took. Verdict quality compares the platform's verdicts with analysts' decisions over time - it needs more
> decisions before it can judge.

---

## 3. Intelligence (1:30)

**ON SCREEN:**
- *Situation brief* - point at the chip (*AI narrative* with the AI on, *Platform summary* without).
- *Ask the analyst*: paste the question, **Ask**. Point at the answer, *How this was answered*, and hover one
  reference (a popover shows what it cites).
- *Correlated findings*: the severity filter; open the first finding's *Next steps* and *Evidence*; point at
  *Acknowledge* / *Dismiss*.
- *Risk by user and host* on the right.

**VOICE-OVER:**
> Intelligence correlates across every tool and domain. The situation brief is what a shift lead needs first: the
> top threats, the riskiest people and hosts, what is waiting for approval, and exposure.
>
> I can ask in plain words. Is Jane Doe compromised, and what should we do first? The answer comes from read-only
> look-ups the platform runs - shown underneath - and every statement carries a reference I can hover. Her risk is
> critical, one hundred out of a hundred, and the first step is to revoke her sessions and reset her credentials.
> The figures and the recommendation are computed by the platform; the AI only writes the sentences, and any
> sentence without valid evidence is removed. With the AI switched off, the same facts and the same first step
> come back in the platform's own words.
>
> Correlated findings are raised by fixed rules, not by the model. The first: a phishing click, then a payload run
> on her laptop, then her account compromised - one chain across e-mail, endpoint and identity tools - with next
> steps and the evidence behind it. An analyst acknowledges or dismisses each finding, and that is recorded.
>
> On the right, risk for every person and host. Scores fade as the activity behind them ages, and every point is
> explained.

---

## 4. Cases (0:30)

**ON SCREEN:** **Cases**. The domain filter (*All 10 · Phishing 7 · Incident 3 · Vulnerability 0*), the owner filter
(*Everyone / Mine / Unassigned*), the columns. Point at **Run incident pipeline** and **Pull reported email**.

**VOICE-OVER:**
> Every investigation in one list, filtered by domain and by owner, with severity, verdict, confidence and status.
> Two reports - one spam, one legitimate invoice - were closed automatically, and one in ten automatic closures is
> sampled for an analyst to check. Vulnerabilities are tracked as findings and campaigns on their own screen, so
> that tab is empty here.
>
> The pipelines run on a schedule - alerts every five minutes, reported e-mail every two. These buttons run them
> now; on this demo data everything is already processed, and re-running changes nothing.

---

## 5. Phishing case (2:00)

**ON SCREEN:** open **Reported: Action required: your password expires today**.
- The header: *Critical*, *Malicious*, confidence 95 %, owner; click **Take case**.
- *Assessment*: the summary; *Facts* - hover two references (popover), click one (it scrolls to the evidence row);
  *MITRE ATT&CK* (T1566.002 Spearphishing Link, T1598.003, T1656 Impersonation, T1078 Valid Accounts).
- *Analysis*: ML models vs rules, the per-component scores and reliability tags, *Confirmed by*.
- *Recommended actions (9)*: blast radius, *not reversible*, the policy lines (four-eyes, destructive).
- *Evidence*: the groups (email, dns, endpoint, identity); one *open in tool* link.
- Right column: *Cross-domain context*, *Entities*, *Analyst decision*, *Analyst notes*, *Timeline*, *Audit trail*.

**VOICE-OVER:**
> A user reported this e-mail. I take the case, and that is recorded.
>
> The assessment says what was found, and every fact carries a reference to its evidence: a sender domain imitating
> Microsoft with look-alike characters, failed DMARC, a display name that doesn't match the sender, pressure
> language, and a link domain rated malicious by three intelligence sources. Facts are kept apart from inferences.
> The techniques are mapped to MITRE ATT&CK.
>
> The verdict comes from two independent analyses: trained models for each part of the e-mail - header, text,
> links, attachments, threat intelligence, user behaviour - and fixed rules. The more severe verdict counts. All of
> it runs inside the platform; no link from an e-mail is ever opened.
>
> Then it went beyond the one report. The campaign reached eight people. Jane clicked through; another person's
> click was blocked by Safe Links, and a blocked click is not counted as a click. It then checked Jane's laptop and
> account: PowerShell touching the phishing domain, a risky sign-in from an anonymising network, a forwarding rule
> and a new device. Defender for Office and Avanan had both passed this message - the platform shows that
> disagreement as evidence.
>
> Nine recommended actions, each with its blast radius, whether it can be undone, and the policy that applies.
> Purging the campaign, isolating the laptop, resetting the password and blocking the domain are four-eyes: two
> different people must approve. Resetting a password is destructive, so it can never run automatically. Nothing
> here has run.
>
> On the right: the risk of everyone involved and the related findings; every entity and which tools saw it; the
> analyst's decision, which feeds back into verdict quality; notes the team can add but never edit; a timeline of
> events from every tool about the people, hosts and indicators in this case; and the case's audit trail.

---

## 6. Attack story and deep analysis (1:45)

**ON SCREEN:** **Attack story**.
- The header: *Confirmed compromise*, the reason line; the summary paragraph.
- The tiles: *Kill-chain stages* 8, *Users reached* 1 / 8, *Hosts* 1, *Privileged secrets* 1, *Gaps checked* 3.
- *Kill chain* (observed / blocked / checked - none).
- *What happened*: scroll two steps, hover a reference; point at the blocked *Privilege Escalation* step.
- *Response plan* (Contain, Preserve evidence, Eradicate, Recover, Communicate) - do not press *Approve selected*.
- *Blast radius*, *Benign explanations tested*, *Gaps*, *Exposure on affected assets*.
- *Deep analysis*: **Run deep analysis** (AI on); point at "every statement cited" or the removed count.

**VOICE-OVER:**
> The attack story rebuilds the incident across tools and across the related cases. Confirmed compromise, high
> confidence: eight stages of the attack reached, one more blocked, corroborated by nine tools. From the e-mail to
> credential access took forty-three minutes - fourteen steps, seen by ten tools.
>
> The kill chain shows each ATT&CK stage: observed, blocked - here a privilege-escalation attempt stopped by the
> privilege manager - or checked with nothing found. Every step cites the events it rests on.
>
> It also tests the innocent explanations, and says why each was rejected: the e-mail was not legitimate; the
> sign-in was not travel or a VPN - it came from an anonymising network while her normal sign-ins are from India;
> the script was not IT work - it reached the phishing domain; the decoy was not touched by a scanner. The access to
> the privileged secret is marked unlikely to be normal duty, with the advice to confirm with its owner. The gaps
> list what was looked for and not found: no defense evasion, no exfiltration, no impact.
>
> The blast radius maps every person, host, indicator and secret involved. The response plan is in phases -
> contain, preserve evidence, eradicate, recover, communicate - and several actions can be approved together; each
> still passes the policy and the four-eyes rule.
>
> The deep analysis is an optional second opinion from the AI on this evidence alone, with internal identities
> pseudonymised. Any statement it cannot cite is removed, and it is counted here. The analyst decides.

---

## 7. Entity 360 (0:40)

**ON SCREEN:** click **jane.doe@acme-demo.com** (from the blast radius or the case). *Risk score* 100 · *Why this
score* (+50 deception hit, +40 endpoint alert, +30 risky sign-in...) · *Timeline across tools* · *Identifiers* ·
*Cases* · *Insights* · *Related* · *Per-tool attributes*.

**VOICE-OVER:**
> One person across every tool. Why this score lists each signal with its weight - a decoy file opened, a malicious
> PowerShell alert, a risky sign-in - and weights fade with age. Her identifiers from each tool - the Entra object
> id, her sign-in name, her Windows account - were matched on strong keys; an ambiguous match is never guessed, it
> goes to an analyst. Her cases, findings, related hosts and accounts, and what each tool says about her.

---

## 8. Incident case (1:15)

**ON SCREEN:** back to **Cases** → **Exchange Server exploitation attempt blocked**.
- Header: *High*, *Needs review*, confidence 55 %.
- *Assessment*: *Facts* (db01 not found in Falcon; owner from the CMDB); **Why high** - the rule list; *MITRE
  ATT&CK* T1190 Exploit Public-Facing Application.
- *Evidence* by source - point at "not sent to outside sources (private or reserved address)".
- *Recommended actions (3)*: isolate (four-eyes), collect forensics, ticket.

**VOICE-OVER:**
> Incidents work the same way. Related alerts are grouped into one case by host and person. For every host, user,
> address and hash, every relevant tool is queried in parallel under a time limit - twelve sources here. A tool that
> doesn't answer is shown as unavailable, never as clean. Internal addresses are never sent to outside
> intelligence services.
>
> Why high? Severity is computed by fixed rules, and every rule that applied is listed. The tool rated the alert
> medium. The server carries a vulnerability on the CISA known-exploited list - one level up. And the server is
> business-critical in the CMDB - so at least high. Two areas corroborate it, which sets the confidence at
> fifty-five percent. The same evidence always gives the same result.
>
> One more check runs on every incident: if one tool closed an alert as a false positive while another still
> reports it, the case says so and every action is held for a person.

---

## 9. Phishing screen (0:45)

**ON SCREEN:** **Phishing**. Tiles: *Reported* 7 · *Auto-closed* 2 (0 sampled for QA) · *Campaigns* 5 · *Repeat
clickers* 1 · *Time to containment* –. Cards: *Verdict mix*, *Users who clicked*, *Analyse a message*, *Most active
reporters*, *How reports were handled*.

**VOICE-OVER:**
> The phishing view. Seven reports: four malicious, one suspicious, one spam, one safe. Two closed automatically;
> one in ten automatic closures is sampled for review, and none of these two was picked. Five campaigns. One repeat
> clicker - Jane, who clicked in two campaigns. Time to containment appears once a containment action has run; none
> has yet. The people who report most are worth recognising - here the demo analyst who uploaded the samples. And
> how reports were handled: closed automatically, analysed, part of a campaign.

---

## 10. Approvals - one lead, then two (1:00)

**ON SCREEN:** **Approvals**. *Waiting by domain* (incident 18, phishing 16, vulnerability 3), *Waiting by action
type*, the domain filter, the table (Action, Targets, Rationale, Policy).
1. **Approve** one `email.reporter_feedback` row - it runs (toast "approved - Executed").
2. **Approve** an `endpoint.isolate` row - toast "First approval recorded - a second lead must approve"; the row
   now says *First approval by lena@acme-demo.com*.
3. Switch to the **Alice** window, **Approvals** → **Approve** the same row - it runs.

**VOICE-OVER:**
> Every recommended action lands here, with its rationale and the policy that applies. A normal action needs one
> approval: I send the reporter their feedback, and in this demo it runs against the simulated tool - request,
> approval and result all recorded.
>
> Isolating a laptop is four-eyes. My approval is recorded, but nothing runs - it needs a second, different lead.
> Approving it twice myself is refused. Here is a second lead: now it runs. Nobody approves their own request;
> analysts cannot approve high-impact actions; and every action is idempotent - repeating a request never repeats
> the action.

---

## 11. Upload a message, and supplier risk (0:50)

**ON SCREEN:** back in Lena's window, **Phishing** → *Analyse a message* → choose `html_attachment_phish.eml` →
**Analyse**. Open the new case (**Reported: Jane, please review and sign: Q3 Vendor Agreement.html** - malicious,
high). Then **Supplier risk** → the three suppliers; read *Krishna Logistics*.

**VOICE-OVER:**
> Reports arrive from the report button through the reporting mailbox - or an analyst uploads a message. The
> original is stored encrypted, and the verdict opens as a case: malicious, a sender imitating DocuSign, with the
> evidence and three recommended actions.
>
> Supplier risk watches the suppliers you list. For Krishna Logistics, two signals. One e-mail came from a domain
> one letter away from theirs - impersonation. Another came from their real domain, fully authenticated, asking to
> change bank details - so their own mailbox is probably compromised. The advice for both: never change payment
> details on an e-mail; call the supplier on a number you already hold.

---

## 12. Vulnerabilities (1:15)

**ON SCREEN:** **Vulnerabilities**.
- Tiles: *Open findings* 6 · *CISA KEV* 5 · *Internet-exposed* 3 · *Past SLA* 6 · *Asset match rate* 100 %.
- *Open by priority* (P1 3, P2 3), *Open findings by team*, *Age of open findings*.
- *Ask about exposure*: paste the question → **Query**; point at the answer and *Filter used*.
- *Coverage gaps* (No EDR: PRIYA-LT07; Not in CMDB: PRIYA-LT07, acmebackups).
- *Findings*: *Seen by* on the Log4Shell row, *In campaign*, *Start campaign* on another row; point at **Sync
  tickets**.

**VOICE-OVER:**
> Rapid7, CrowdStrike, Wiz and Defender all scan the same estate and name the same server differently. The
> platform resolves them to one record per host and vulnerability - the Log4Shell row was reported by four tools.
> Six open findings: five on the CISA known-exploited list, three internet-facing, all six past their deadline.
>
> Priority is computed from severity, the likelihood of exploitation, the known-exploited list, exposure and how
> critical the host is - each with a deadline - and owners come from the CMDB, by team.
>
> Questions are answered from the data, and the filter it used is shown: two findings on one internet-facing
> server - Log4Shell and HTTP/2 Rapid Reset.
>
> Coverage gaps: a laptop with no endpoint agent, and two assets missing from the CMDB.
>
> A campaign takes one vulnerability to every owner - Log4Shell has one, opened in this demo by an analyst; its
> notifications wait for approval like any action. Sync tickets checks the remediation tickets: a ticket closed
> while the scanner still sees the vulnerability is caught as a false closure and reopened.

---

## 13. Cloud posture (0:40)

**ON SCREEN:** **Cloud posture**. Tiles *Open* 2 · *Past SLA* 2 · *False closures* 0 · *Teams involved* 2; *Open by
severity*, *Open by owner*; the table. On the **acmebackups** row press **Mark fixed**, then **Validate** - toast
"Validation: Still present (false closure - reopened)"; *False closures* becomes 1.

**VOICE-OVER:**
> Cloud misconfigurations from Wiz follow the same lifecycle: an owner, a deadline, a ticket. A toxic combination - a
> public virtual machine with a critical vulnerability and a high-privileged identity - and a storage account open
> to the public. Watch: the owner says the storage account is fixed. Validate asks Wiz - it still reports it - so it
> is a false closure, and it reopens. Nothing is closed on someone's word.

---

## 14. ATT&CK coverage and Shadow IT (1:00)

**ON SCREEN:** **ATT&CK coverage**: tiles *Weighted coverage* 93.8 % (56 of 56 techniques) · *Priority blind spots*
0 · *Single-source* 4 · *Firing* 11; the *Matrix* - hover one cell. Then **Shadow IT**: tiles *Unsanctioned services*
5 · *High-risk services* 1 · *Users involved* 4 · *Risky sites reached* 1; *Unsanctioned services*, *By category*,
*Risky destinations*.

**VOICE-OVER:**
> Which attacks can you actually see? The platform keeps a catalogue of fifty-six priority ATT&CK techniques and maps
> each to the tools you have switched on: ninety-four percent weighted coverage, no priority blind spots - but four
> techniques that only one tool can see, so if that tool goes down you are blind. Eleven have actually fired. Switch
> a tool off and its blind spots appear here.
>
> Shadow IT, from DNS activity: a remote-access tool, file sharing, an unsanctioned AI service, and a personal VPN
> that was blocked. And one risky destination - the phishing site - was reached even though it was categorised as
> phishing, which the platform raises as a control gap.

---

## 15. Integrations (1:20) - Admin window

**ON SCREEN:** switch to **Ada (Admin)** → **Integrations**.
- The version pill; *Platform self-check* (14 of 14 checks pass).
- *Connectors (21 enabled)*: Stage (*Fixtures*; hover for the meaning), State, *Streams · age / expected*.
- **Preflight** on CrowdStrike: Configuration, Sign-in, Permissions, Streams (a warning: the sample data is a month
  old).
- **Configure** on one tool → change a setting → propose; *Configuration changes awaiting approval*. Point at
  **Pause**.
- *Configuration* (suppliers and sanctioned services lists), *Notifications* (no channel in this demo), *Scheduled
  jobs*.

**VOICE-OVER:**
> Integrations is where an administrator connects and watches the tools. The self-check proves the same figures
> agree on every screen, report and the database - fourteen of fourteen - and runs every hour.
>
> Twenty-one connectors. Each tool moves through stages: sample data, recording sanitised live responses, read-only,
> recommend, and only by a separate approved decision, automate. Every stream shows how old its data is against what
> is expected.
>
> A preflight checks a tool before it is trusted: its settings, sign-in, permissions and every data stream - and
> names the fix for anything that fails. Here it warns that the sample data is a month old; on a live tool that
> would mean a stalled feed.
>
> A configuration change is proposed by one person and approved by another - it waits here. Pause stops a tool at
> once, every write included. Notifications send findings above a threshold to Teams or Slack. And every scheduled
> job, its last run and its outcome.

---

## 16. Automation policy (0:35)

**ON SCREEN:** back to **Lena** → **Automation policy**: the level legend, *Actions* (Executes via, Level,
*destructive* / *reversible*), *Kill switch*, *Pending policy changes*.

**VOICE-OVER:**
> Every action type has an autonomy level, from observe to autonomous; all are at recommend. Destructive actions are
> marked and can never be autonomous. A policy change is proposed by one person and approved by another. The kill
> switch stops anything running automatically, on every server at once, and survives restarts; an action a person
> approves still runs - to stop every write to a tool, pause the tool.

---

## 17. Audit log and trace (0:40)

**ON SCREEN:** **Audit log**: the *Chain verified* pill; the table (Actor, Event, Subject); click a **Trace** link on
the approval rows from scene 10. On the trace: *Request*, *Audit events*, *Model calls*.

**VOICE-OVER:**
> Every retrieval, recommendation, approval and action is in an append-only log, each record chained to the last by
> a cryptographic hash - verified here. The first and second approval of that isolation are both on record.
>
> From any entry, the trace shows everything that request did: the request, its audit events, and every model call -
> what was sent, with identities pseudonymised, what came back, and what the evidence check removed.

---

## 18. AI usage (0:45) - Admin window

**ON SCREEN:** **Ada** → **AI usage & limits**: *This month*, *Today*, *Cost, last 30 days*; *By feature* (calls,
tokens, cost, usable, advice, tier); *Budgets*; *Limits per person*; *Who used it*; *Recent model calls*; *History*.

**VOICE-OVER:**
> The AI is optional, and an administrator controls it. Monthly and daily budgets, limits per person, and for each
> feature which model size it uses, whether it is on, and how long an answer may be. The advice column is computed
> from measured results: how many answers were usable and how many statements the evidence check removed. Over any
> limit nothing breaks - the platform answers from the same evidence without the model. Every change is versioned.

---

## 19. Search (0:20)

**ON SCREEN:** **Lena** → top search `jane-lt01`, Enter (the host, three correlated findings, one vulnerability
finding); then `CVE-2021-44228` (the Log4Shell finding).

**VOICE-OVER:**
> One search across cases, people, hosts, every tool's identifiers, findings and vulnerabilities.

---

## 20. Reports (1:00)

**ON SCREEN:** **Reports**: the callout (who writes the narrative); *Describe a report* - paste the request → **Plan
report** → review the plan → generate; open the deck. *Standard reports* (seven); *Exports*; **Generate pack** under
*Compliance evidence pack* (read the "control tests passed" line); *Audit export*.

**VOICE-OVER:**
> Seven standard reports for the SOC, the CISO and the board, built from live data. Or I describe a report in words:
> the platform plans it from its catalogue of data sources, I review the plan, and it builds the deck. Every number
> comes from the data; the AI, when on, only writes the prose around them.
>
> For auditors, the compliance evidence pack tests the controls - the audit chain, four-eyes approvals, policy change
> control, MFA, retention - and packages the evidence. And the full audit log exports for archiving or your SIEM.

---

## 21. Access, and closing (0:50) - Admin window

**ON SCREEN:** **Ada** → **Access**: *Role assignments* (the grant form), *Service accounts*, *Your access*, *Role
permissions* (the "never granted to service accounts" row). Then toggle dark mode and return to the **Overview**.

**VOICE-OVER:**
> Access adds time-bound, domain-scoped roles on top of Entra roles. Nobody can change their own access, and lead or
> administrator grants need a second administrator. Service accounts get keys for integrations, and can never
> approve anything.
>
> One layer over the tools you own. One picture of every person and host. Every conclusion cited, every figure and
> verdict computed - and the analyst in control, every step recorded, in your own environment.
>
> Thank you for watching.

---

## Before you publish

- Every tool is simulated (vendor-shaped sample data through the same code that reads the real tools). If an
  approved action appears to run, say "in this demo".
- Read any figure you add off the screen on the recording day; the AI's wording changes between runs.
- The video shows only the fictional Acme organisation - no real tenant, person or data.
