# Demo video script - Agentic SOC platform

A screen recording with voice-over for a client audience: security leadership, SOC leads and analysts, and the
architects who will review it. It shows **every screen**, and for each one explains **what the feature does, how it
works, and why it matters** - not only what is on the screen.

Every figure and behaviour was read from a freshly reset demo and checked against the code on 2026-10-22. Where a
value depends on the day or on the AI's wording, the script says "read it off the screen".

**Length:** voice-over about 3,800 words - about 25 minutes of speech at a steady pace; with clicks the scenes add
up to about 29 minutes. The scenes marked *(optional)* save about a minute; for a 20-minute cut, keep every scene's
first paragraph and drop the rest of its voice-over.

Each scene has:
- **ON SCREEN** - what to click, top to bottom.
- **THE POINT** - the one idea the viewer must leave with (not read aloud).
- **VOICE-OVER** - read as written.

---

## Before you record

1. **Start the server with `.env` loaded.** From Command Prompt in the project folder:
   `scripts\serve_with_env.cmd reset` (or in PowerShell: `.\.venv\Scripts\Activate.ps1`, `. .\scripts\load_env.ps1`,
   `python -m soc_platform reset-demo --yes`, `python -m soc_platform serve`). The first log lines must say
   `sign-in: development sign-in on`. Wait about a minute for the first scheduled jobs (the compliance pack in scene
   20 checks that the retention job has run).
2. **AI on** (`SOC_LLM_*` in `.env`): summaries, the brief, answers and the deep analysis are written by the model
   from the platform's evidence - read their wording off the screen. Every number is the same with the AI off. The
   Intelligence page takes a few seconds to load while the brief is written.
3. **Three browser profiles**, signed in before recording (tabs of one browser share a sign-in):
   **Lena** (Lead, all domains) - main window; **Alice** (Lead, all domains) - the second approval in scene 10;
   **Ada** (Admin, all domains) - scenes 15, 18, 21.
4. **Have ready:** `artifacts/phishing/corpus/html_attachment_phish.eml` (scene 11), and in a text file to paste:
   `Is jane.doe@acme-demo.com compromised and what should we do first?` (scene 3),
   `which internet facing hosts have KEV vulnerabilities?` (scene 12),
   `A one-page board brief on phishing and supplier risk this month, as slides` (scene 20).
5. **Approve nothing before recording.** Browser 1920 x 1080, zoom 90 %, light theme. Rehearse once.

**Be ready to say what the demo set-up staged** (if asked): a demo analyst opened the Log4Shell campaign and routed
the two cloud findings, and six of the seven reported e-mails were uploaded as samples. Every verdict, case,
correlation, score, severity and recommendation was computed by the platform from the tools' data.

---

## Scene list

| # | Screen | Time | # | Screen | Time |
|---|---|---|---|---|---|
| 1 | Opening: the problem and the approach | 1:30 | 12 | Vulnerabilities | 1:45 |
| 2 | Overview | 1:45 | 13 | Cloud posture *(optional)* | 0:50 |
| 3 | Intelligence and the AI rules | 2:15 | 14 | ATT&CK coverage, Shadow IT | 1:30 |
| 4 | Cases | 0:40 | 15 | Integrations - rolling out a tool | 1:45 |
| 5 | Phishing case | 2:30 | 16 | Automation policy | 1:00 |
| 6 | Attack story | 2:15 | 17 | Audit log and trace | 1:00 |
| 7 | One person across tools | 1:00 | 18 | AI usage and cost control | 1:00 |
| 8 | Incident case | 1:30 | 19 | Search *(optional)* | 0:20 |
| 9 | Phishing at scale | 1:00 | 20 | Reports and evidence | 1:15 |
| 10 | Approvals and four-eyes | 1:30 | 21 | Access, deployment, closing | 1:30 |
| 11 | Upload, supplier fraud | 1:00 | | | |

---

## 1. Opening: the problem and the approach (1:30)

**ON SCREEN:** the sign-in page; pick **Lead**, all domains; **Continue**. Land on the Overview.

**THE POINT:** one layer over the tools you already own; the AI investigates, code decides, a person approves.

**VOICE-OVER:**
> A SOC rarely lacks tools. It lacks time between them. One phishing report means the mail console, then the EDR,
> then identity, then DNS, then a ticket - the same person, host and address looked up five times under five names,
> and the conclusion written by hand at the end.
>
> The Agentic SOC platform is one investigation and automation layer over the tools you already own. It does not
> replace them. It connects to twenty-one of them - email security, EDR, identity, DNS, deception, privileged access,
> vulnerability scanners, threat intelligence, ITSM and SIEM - and does the gathering for the analyst.
>
> Three rules run through everything you'll see. First, every figure, score, verdict and severity is computed in code
> - the same evidence always gives the same answer. Second, the AI only explains: it writes from evidence it is
> handed, every sentence must cite that evidence, and the platform works fully without it. Third, nothing changes in
> a security tool until a person approves it.
>
> People sign in with Entra ID and MFA; their role and domain decide what they see and what they may approve. This is
> a fictional company, Acme, with sample data from all twenty-one tools, read through exactly the code that reads
> the real tools.

---

## 2. Overview (1:45)

**ON SCREEN:** the six tiles; the *Value scorecard* (open "Enter a baseline, target or time-study figure" briefly);
*New cases per day*, *Open cases by severity*; *Highest-priority insights*, *Riskiest users and hosts*; *Data quality*,
*Integrations*, *Enrichment latency*, *Verdict quality*.

**THE POINT:** every number is computed from stored records, and the platform proves its own data quality.

**VOICE-OVER:**
> The overview is the shift lead's first screen. Eight open cases, thirty-seven recommended actions waiting for a
> person, twenty correlated findings and six open vulnerabilities, all past their deadline. The automation rate is
> zero: by default the platform recommends and people decide. Automation is switched on per action type, by a
> recorded decision, only when the organisation is ready.
>
> The value scorecard is how this platform justifies itself. It measures the benefits it is bought for - time to
> handle a phishing report, time to contain a click, time from alert to decision, time to a validated fix - from its
> own timestamps. A lead enters the baseline from before go-live and the target; until a baseline exists it says so.
> It never estimates a saving.
>
> The bottom row is the platform checking itself. Data quality is the foundation of everything else: each tool names
> the same laptop and the same person differently, and the platform resolves them to one record. It matches on strong
> identifiers first - device ids, sign-in names, Windows account ids - then on weaker hints with a score. A match is
> made automatically only when it is clearly the best one; anything ambiguous waits for an analyst rather than being
> guessed. Here, every host and every person matched.
>
> Integrations lists any tool that has stopped answering or gone stale - an empty screen elsewhere is never mistaken
> for a quiet day. Enrichment latency is how long an investigation's look-ups took. And verdict quality compares the
> platform's verdicts with analysts' decisions over time, to catch drift.

---

## 3. Intelligence, and how the AI is kept honest (2:15)

**ON SCREEN:** *Situation brief* (point at the chip: *AI narrative*). *Ask the analyst*: paste the question → **Ask**;
point at the answer, *How this was answered*, hover a reference. *Correlated findings*: the filter; open the first
finding's *Next steps* and *Evidence*; *Acknowledge* / *Dismiss*. *Risk by user and host*.

**THE POINT:** correlation across domains is done by rules; the AI answers questions but cannot invent a fact or a
number.

**VOICE-OVER:**
> Intelligence looks across every tool and every domain at once - which is where attacks actually show up: a phishing
> click in one tool, a process on a laptop in another, a risky sign-in in a third.
>
> The situation brief summarises what matters now: the top threats, the riskiest people and hosts, what is waiting
> for approval, and exposure.
>
> I can ask a question in plain words. Is Jane Doe compromised, and what should we do first? Here is what happens
> underneath. The question is turned into look-ups from a fixed, read-only list - find this person, get her risk,
> get her context - shown here. The platform runs them against its own data. Only then is the model given the results,
> with internal names replaced by placeholders, and asked to write the answer. Every sentence must cite one of those
> results; a sentence without a valid citation, or with a number that isn't in the evidence, is removed before
> anyone sees it. Hover a reference and you see exactly what it rests on.
>
> So the answer - critical risk, a hundred out of a hundred, and revoke her sessions and reset her credentials first -
> comes from the data, not from the model. With the AI switched off, the same look-ups return the same facts and the
> same first step, in the platform's own words. If someone asks about a person the platform can't find, it says it
> can't find them - it never answers "no evidence".
>
> Correlated findings come from thirteen fixed rules - for example, a phishing click followed by execution on that
> person's laptop followed by a compromised sign-in. This one links e-mail, endpoint and identity tools into one
> finding, with next steps and the evidence behind it. Each finding is acknowledged or dismissed by an analyst, and
> re-running the rules never duplicates one.
>
> On the right, risk for every person and host: points for each signal, fading as the activity ages - except open
> exposures and incidents, which stay until they are resolved.

---

## 4. Cases (0:40)

**ON SCREEN:** **Cases**: the domain filter (*All 10 · Phishing 7 · Incident 3 · Vulnerability 0*), the owner filter,
the columns. Point at **Run incident pipeline** and **Pull reported email**.

**THE POINT:** one queue for every domain; clear benign reports close themselves, with a quality sample.

**VOICE-OVER:**
> Every investigation in one queue, with an owner, severity, verdict and confidence. Clear spam and clearly
> legitimate reports are closed automatically when the verdict is confident, and one in ten of those closures is
> sampled for an analyst to check - so automation is measured, not trusted blindly.
>
> The pipelines run on a schedule - alerts every five minutes, reported e-mail every two - and these buttons run them
> on demand. Every pipeline is idempotent: running it again on the same data changes nothing - no duplicate case, no
> duplicate action - which is why it is safe to re-run after an outage.

---

## 5. A phishing case, end to end (2:30)

**ON SCREEN:** **Reported: Action required: your password expires today** → **Take case**. *Assessment*: summary,
*Facts* (hover two references, click one - it scrolls to the evidence), *MITRE ATT&CK*. *Analysis*. *Recommended
actions (9)*. *Evidence* groups and an *open in tool* link. Right column: *Cross-domain context*, *Entities*, *Analyst
decision*, *Analyst notes*, *Timeline*, *Audit trail*.

**THE POINT:** a single report becomes a full compromise investigation automatically, every conclusion cited.

**VOICE-OVER:**
> One employee reported this e-mail with the report button. Taking the case assigns it to me, on record.
>
> The verdict comes from two independent analyses inside the platform. Trained machine-learning models score each
> part of the e-mail - the headers, the text, the links, attachments, threat intelligence on its indicators, and how
> unusual it is for the recipient. Alongside them, fixed rules check authentication and known patterns. The more
> severe verdict wins, and the panel shows each model's score and how reliable it is. The models run offline: no
> e-mail content leaves the platform, and no link from an e-mail is ever opened.
>
> Every statement in the assessment cites its evidence: a sender domain imitating Microsoft with a zero for an "o",
> failed DMARC, a display name that doesn't match the sender, pressure language, and a link domain rated malicious
> by three intelligence sources. Facts are kept separate from inferences, and the techniques are mapped to MITRE
> ATT&CK.
>
> Then the platform goes beyond the one report - this is the work an analyst would otherwise do by hand. It finds the
> whole campaign: eight recipients. It checks who clicked: Jane clicked through; another person's click was blocked by
> Safe Links, and a blocked click is not counted as a click. For Jane it then queries the endpoint, identity and DNS
> tools: PowerShell on her laptop touching the phishing domain, a sign-in from an anonymising network, a new inbox
> forwarding rule, a new device. Both e-mail security tools had passed the message - that disagreement is itself
> recorded as evidence, which is useful for tuning them.
>
> Nine recommended actions, each with its blast radius, whether it can be undone, and the policy reasons. Purging the
> campaign, isolating the laptop, resetting the password and blocking the domain are four-eyes - two different people
> must approve. A password reset is destructive, so it can never run automatically. Nothing has run.
>
> On the right, the cross-domain picture; every entity and which tools saw it; the analyst's decision, which feeds
> verdict quality; notes the team can add but never edit; a timeline of events from every tool about the people,
> hosts and indicators in this case; and the audit trail of the case itself.

---

## 6. The attack story (2:15)

**ON SCREEN:** **Attack story**: header (*Confirmed compromise*, reason), summary, tiles. *Kill chain*. *What happened*
(two steps, hover a reference; the blocked *Privilege Escalation* step). *Response plan* (don't approve). *Blast
radius*, *Benign explanations tested*, *Gaps*, *Exposure on affected assets*. *Deep analysis* → **Run deep analysis**.

**THE POINT:** the platform reconstructs the whole attack across tools and argues against itself before concluding.

**VOICE-OVER:**
> An analyst's hardest job is the narrative: what actually happened, in what order, how far it got. The attack story
> reconstructs it automatically from every tool and every related case.
>
> Its conclusion is a rule, not an opinion: confirmed compromise, because eight stages of the attack were reached,
> corroborated by nine tools, and every innocent explanation was rejected. From the e-mail to credential access took
> forty-three minutes - fourteen steps seen by ten tools.
>
> The kill chain shows each ATT&CK stage: observed, blocked - here the privilege manager stopped an elevation
> attempt - or checked and clean. Every step cites the events it rests on, and its confidence says whether one tool
> or several saw it.
>
> What makes this trustworthy is that it tests the alternatives. Was the e-mail legitimate? Rejected - the verdict
> and its signals. Was the sign-in Jane travelling or on a VPN? Rejected - it came from an anonymising network, and
> her normal sign-ins are from India. Was the script normal IT work? Rejected - it reached the phishing domain. Was the
> decoy touched by a scanner? Rejected. Was the privileged secret normal duty? Unlikely - confirm with its owner. And
> the gaps say what was looked for and not found: no defense evasion, no exfiltration, no impact. "Not found" is
> stated, never assumed.
>
> The blast radius shows how far it reached: Jane and her laptop at the centre, the privileged secret, the seven other
> people who received the e-mail, the related cases, and every indicator grouped by type. Cases the platform found
> benign - the spam and the legitimate invoice Jane also received - are left out. The response plan is ordered the way an incident
> responder works - contain, preserve evidence, eradicate, recover, communicate - and actions can be approved
> together, each still checked by the policy.
>
> The deep analysis is optional: a second opinion from the AI on exactly this evidence, with identities replaced by
> placeholders. Any statement it can't cite is removed and counted here. It advises; the analyst decides.

---

## 7. One person across every tool (1:00)

**ON SCREEN:** click **jane.doe@acme-demo.com**: *Risk score*, *Why this score*, *Timeline across tools*,
*Identifiers*, *Cases*, *Insights*, *Related*, *Per-tool attributes*.

**THE POINT:** entity resolution is what makes cross-tool investigation possible - and it never guesses.

**VOICE-OVER:**
> This is the shared picture everything else is built on: one person, assembled from ten tools. Her identifiers -
> the Entra object id, her sign-in name, her e-mail, her Windows account id - were linked on strong keys, so the
> platform knows the "jane.doe" in the EDR and the "ACME backslash jane.doe" in the vault are the same person.
>
> Why this score lists every signal with its points and source - a decoy file opened, a malicious PowerShell alert,
> a risky sign-in - so a score of a hundred can be defended line by line. The points add up to far more than a
> hundred; the score puts them on a curve - every signal raises it, each by less as the total grows - so it never
> passes a hundred, and one noisy alert can't make someone critical on its own. Her timeline across tools, her cases, the
> hosts and accounts linked to her, and what each tool reports about her.

---

## 8. An incident case, and how severity is decided (1:30)

**ON SCREEN:** **Cases** → **Exchange Server exploitation attempt blocked**: header (*High*, *Needs review*, 55 %);
*Facts*; **Why high**; *MITRE ATT&CK* T1190; *Evidence* (point at "not sent to outside sources"); *Recommended
actions (3)*.

**THE POINT:** parallel enrichment across every tool in seconds, and a severity anyone can audit.

**VOICE-OVER:**
> Alerts from the EDRs, identity, deception and the SIEM are grouped into incidents by host and person, so one
> attack is one case, not twenty alerts.
>
> Each incident is enriched automatically. For every host, user, address and hash, every relevant tool is queried in
> parallel - twelve sources here - under a time limit, with results cached so the same look-up isn't repeated. If a
> tool doesn't answer in time, the case says that source was unavailable; it is never treated as "nothing found".
> Internal addresses and the organisation's own domains are never sent to outside intelligence services.
>
> Severity is computed by fixed rules, and the case shows every rule that applied. The tool rated this alert medium.
> The server carries a vulnerability on the CISA known-exploited list - that raises it one level. The server is
> business-critical in the CMDB - so it is at least high. Two independent areas confirm it, which sets the confidence.
> This is exposure-informed triage: the same alert on an unpatched, critical server matters more than on a laptop,
> and the platform knows that because it holds the vulnerability data too.
>
> One more safeguard: if one tool closed an alert as a false positive while another still reports it, the case shows
> the conflict and holds every action for a person.

---

## 9. Phishing at scale (1:00)

**ON SCREEN:** **Phishing**: tiles (*Reported* 7, *Auto-closed* 2 with "0 sampled for QA", *Campaigns* 5, *Repeat
clickers* 1, *Time to containment* –); *Verdict mix*; *Users who clicked*; *Analyse a message*; *Most active
reporters*; *How reports were handled*.

**THE POINT:** the programme view - volume, outcomes, repeat clickers, and the time-to-contain KPI.

**VOICE-OVER:**
> The phishing programme at a glance. Seven reports - four malicious, one suspicious, one spam, one safe. Two closed
> automatically; neither fell in the ten-percent quality sample this time. Five campaigns.
>
> Repeat clickers are the people to train first - here Jane, who clicked in two campaigns. Time to containment is
> measured from the report to the first containment action, and appears once one has run. And the most active
> reporters are worth recognising - reporting is the behaviour you want more of.

---

## 10. Approvals, and what four-eyes really means (1:30)

**ON SCREEN:** **Approvals**: *Waiting by domain*, *Waiting by action type*, the filter, the table (Rationale, Policy).
1. **Approve** an `email.reporter_feedback` row → it runs.
2. **Approve** an `endpoint.isolate` row → "First approval recorded - a second lead must approve"; the row shows
   *First approval by lena@acme-demo.com*.
3. **Alice** window → **Approvals** → **Approve** the same row → it runs.

**THE POINT:** every write to a tool is a governed request; sensitive ones genuinely need two people.

**VOICE-OVER:**
> Everything the platform wants to change in a tool arrives here as a request: what, on which targets, why, and
> which policy applies. There is no other way for the platform to write to a tool.
>
> A routine action needs one approval. I send the reporter their feedback, and it runs - in this demo, against the
> simulated mail system - with the request, the approval and the result all recorded.
>
> Isolating a laptop is four-eyes. I approve it - and it does not run. My approval is recorded; it needs a second,
> different lead. I can't approve it twice myself. Here is a second lead, Alice. Now it runs.
>
> Underneath, each action is protected in several ways. Its preconditions are checked again at the moment it runs,
> in case things changed. Each request has a unique key, so a retry or a double click can never isolate a host twice.
> The decision is committed before the tool is called and the outcome after, so an action that reached a tool is
> always on record. And reversible actions record their reverse - releasing the host is itself a four-eyes action.

---

## 11. Upload a message, and supplier fraud (1:00)

**ON SCREEN:** back in Lena's window: **Phishing** → *Analyse a message* → `html_attachment_phish.eml` → **Analyse**;
open the new case (**Reported: Jane, please review and sign: Q3 Vendor Agreement.html** - malicious). Then **Supplier
risk** → *Krishna Logistics*.

**THE POINT:** the same pipeline for any message; and business e-mail compromise through suppliers is caught.

**VOICE-OVER:**
> An analyst can also upload any message. The original is stored encrypted, and the same pipeline runs: malicious, a
> sender imitating DocuSign, evidence, and three recommended actions - a new case, investigated before anyone opened it.
>
> Supplier fraud is where phishing costs real money. The platform watches the suppliers you list. For Krishna
> Logistics it found two different things. One e-mail came from a domain one letter away from theirs -
> impersonation. The other came from their real domain, passing every authentication check, asking to change bank
> details - which means the supplier's own mailbox is probably compromised, something authentication checks alone
> would never flag. The advice in both cases: never change payment details on an e-mail; call the supplier on a
> number you already hold.

---

## 12. Vulnerabilities: from four scanners to one decision (1:45)

**ON SCREEN:** **Vulnerabilities**: tiles; *Open by priority*, *Open findings by team*, *Age of open findings*; *Ask
about exposure* → paste → **Query** (point at *Filter used*); *Coverage gaps*; *Findings* (*Seen by*, *In campaign*,
*Start campaign*); point at **Sync tickets**.

**THE POINT:** one record per host and CVE, prioritised by real risk, closed only when a scan proves the fix.

**VOICE-OVER:**
> Most organisations run several scanners, and each reports the same flaw on the same server under a different name.
> Rapid7, CrowdStrike, Wiz and Defender all feed in here, and the platform keeps one record per host and
> vulnerability - the Log4Shell row was reported by four tools, and it is one finding with one owner.
>
> Priority goes beyond the CVSS score. It combines severity with the probability of exploitation from EPSS, whether
> the flaw is on the CISA known-exploited list, whether the host faces the internet, and how critical the host is in
> the CMDB. Each priority comes with a deadline, and each finding goes to the team that owns the host.
>
> Questions get answers from the data, with the filter shown so anyone can check it: two findings on one
> internet-facing server - Log4Shell and HTTP/2 Rapid Reset.
>
> Coverage gaps are the findings you can't see: a laptop with no endpoint agent, and assets missing from the CMDB.
>
> A campaign takes one vulnerability to every owner at once - Log4Shell has one here; its notifications wait for
> approval like any action. And a finding is closed only when a new scan proves the fix. Sync tickets compares the
> remediation tickets with the scanners: a ticket closed while the vulnerability is still there is caught as a false
> closure and reopened.

---

## 13. Cloud posture *(optional)* (0:50)

**ON SCREEN:** **Cloud posture**: tiles; *Open by severity*, *Open by owner*; the table. On **acmebackups**: **Mark
fixed**, then **Validate** → "Validation: Still present (false closure - reopened)"; *False closures* becomes 1.

**THE POINT:** nothing is closed on someone's word.

**VOICE-OVER:**
> Cloud misconfigurations from Wiz follow the same lifecycle - owner, deadline, ticket. A toxic combination: a public
> virtual machine with a critical vulnerability and a high-privileged identity. And a storage account open to the
> public. Watch: the owner marks the storage account fixed. Validate asks Wiz, which still sees the problem - so it is
> a false closure, and it reopens. Closure is proved by the tool, never claimed.

---

## 14. ATT&CK coverage and Shadow IT (1:30)

**ON SCREEN:** **ATT&CK coverage**: tiles (93.8 %, 56 of 56; 0 blind spots; 4 single-source; 11 firing); hover a
matrix cell. **Shadow IT**: tiles; *Unsanctioned services*, *By category*, *Risky destinations*.

**THE POINT:** know what you can't see, and what people use that you didn't approve.

**VOICE-OVER:**
> A question boards ask: which attacks would we actually see? The platform keeps a catalogue of fifty-six priority
> ATT&CK techniques and maps each one to the tools you have switched on. Ninety-four percent weighted coverage, no
> priority blind spots - but four techniques only one tool can see, so if that tool goes down, you're blind to them.
> Eleven have actually fired in your data. Switch a tool off and its blind spots appear immediately - which makes this
> a planning tool for licences and gaps, not a slide.
>
> Shadow IT comes from DNS: a remote-access tool, file-sharing services, an unsanctioned AI service, a personal VPN
> that was blocked. And the most important row: a phishing site was reached even though DNS had it categorised as
> phishing - so the block policy has a gap, and the platform raises it as a finding with the fix.

---

## 15. Integrations: how a tool goes live safely (1:45) - Admin window

**ON SCREEN:** **Ada (Admin)** → **Integrations**: the version pill; *Platform self-check* (14 of 14); *Connectors (21
enabled)* - Stage (hover), State, *Streams · age / expected*; **Preflight** on CrowdStrike; **Configure** on a tool →
change a setting → propose → *Configuration changes awaiting approval*; **Pause**; *Configuration*, *Notifications*,
*Scheduled jobs*.

**THE POINT:** a tool is trusted step by step, with checks and two-person changes - this is how go-live works.

**VOICE-OVER:**
> This screen is how the platform goes into a real environment. Each tool connects with its own read-only identity
> first, and moves through stages: sample data; recording, where live responses are saved with every identity
> removed, to test against; read-only, where it investigates but recommends steps for a person to do by hand;
> recommend, where it proposes actions for approval; and only by a separate, approved decision, automate.
>
> Before a tool moves up, a preflight checks everything it needs: the settings, the sign-in, the permission for each
> data stream, that records parse, how fresh and how large the data is, and the clock - and names the fix for
> anything that fails. A configuration change is proposed by one person and approved by another, and secrets are
> never stored here - only references to where they are kept. Pause stops a tool at once, including every write.
>
> The self-check proves the platform's own consistency every hour: the same figure agrees on every screen, report
> and the database, and every reference resolves - fourteen of fourteen. Notifications send findings above a
> threshold to Teams or Slack - once per finding and channel, and again if it escalates. And every scheduled job is visible, retried on failure, and never
> runs twice at once, even across several servers.

---

## 16. Automation policy (1:00)

**ON SCREEN:** **Lena** → **Automation policy**: the level legend; *Actions* (Executes via, Level, *destructive* /
*reversible*); *Kill switch*; *Pending policy changes*.

**THE POINT:** autonomy is a versioned, two-person decision per action type, with a durable off switch.

**VOICE-OVER:**
> Autonomy is not on or off; it is set per action type, from observe, to enrich, to recommend, to approve, to
> autonomous. Today every action is at recommend. Moving one up - say, blocking a known-malicious file hash on
> endpoints automatically - is a policy change proposed by one person and approved by another, with every version kept.
>
> Some limits can't be changed by policy: destructive actions, like resetting a password or purging mail, are never
> autonomous. Actions on VIPs or on more targets than a set limit always need approval.
>
> The kill switch stops everything that would run automatically, on every server at once, and survives a restart.
> An action a person explicitly approves still runs; to stop every write to one tool, you pause that tool.

---

## 17. Audit log and trace (1:00)

**ON SCREEN:** **Audit log**: *Chain verified*; the table; click **Trace** on the approval rows from scene 10; on the
trace: *Request*, *Audit events*, *Model calls*.

**THE POINT:** every "why?" has an answer that can be proved untampered.

**VOICE-OVER:**
> Every look-up, conclusion, recommendation, approval and action is written to an append-only log. Each record
> carries a cryptographic hash of the one before, so changing or deleting any record breaks the chain - and the chain
> is verified here. Both approvals of that isolation are on record, with who and when.
>
> From any entry, the trace shows everything that request caused: the request itself, its audit records, and every
> model call - exactly what was sent, with identities replaced by placeholders, what came back, and which statements
> the evidence check removed. When an auditor or a regulator asks why the platform recommended something, this is the
> answer.

---

## 18. AI usage and cost control (1:00) - Admin window

**ON SCREEN:** **Ada** → **AI usage & limits**: *This month*, *Today*, *Cost*; *By feature*; *Budgets*; *Limits per
person*; *Who used it*; *Recent model calls*; *History*.

**THE POINT:** the AI is optional, bounded, measured - and its failure changes nothing that matters.

**VOICE-OVER:**
> The model the platform uses is your choice - in production, the organisation's own approved LLM endpoint - and an
> administrator controls it here. Monthly and daily token budgets; limits per person; and for each feature, whether
> it is on, which model size it uses, and how long its answers may be.
>
> The advice column is computed from measured results, not opinion: how many answers were usable, and how many
> statements the evidence check had to remove. If a cheaper model answers just as well, it says so.
>
> When a limit is reached or the model is unavailable, nothing breaks: the platform answers from the same evidence in
> its own words, and every figure, verdict and action is exactly the same.

---

## 19. Search *(optional)* (0:20)

**ON SCREEN:** **Lena** → search `jane-lt01` (the host, three correlated findings, one vulnerability finding); then
`CVE-2021-44228`.

**VOICE-OVER:**
> One search across cases, people, hosts, every tool's own identifiers, findings and vulnerabilities - paste whatever
> a ticket or a vendor gives you.

---

## 20. Reports and compliance evidence (1:15)

**ON SCREEN:** **Reports**: the callout; *Describe a report* → paste → **Plan report** → review the plan → generate;
open the deck. *Standard reports*; *Exports*; **Generate pack** (*Compliance evidence pack*); *Audit export*.

**THE POINT:** reporting with numbers that can't drift from the data, and audit evidence on demand.

**VOICE-OVER:**
> Seven standard reports - for the SOC, the CISO and the board - are built from live data on demand or on a
> schedule. Or I describe the report I need in words. The platform plans it from its catalogue of data sources, I
> review the plan before anything is generated, and it builds the deck in the house style. Every number in it is
> computed from the data; the AI, when it's on, writes only the prose around those numbers.
>
> For auditors, the compliance evidence pack tests the controls themselves - the audit chain is intact, four-eyes
> actions had two different approvers, no policy was approved by its author, MFA is enforced, retention ran - and
> packages the results with the evidence. The full audit log can also be exported for archiving or your SIEM.

---

## 21. Access, deployment, and closing (1:30) - Admin window

**ON SCREEN:** **Ada** → **Access**: *Role assignments* (the grant form), *Service accounts*, *Your access*, *Role
permissions* (the row of permissions never granted to service accounts). Toggle dark mode; back to the **Overview**.

**THE POINT:** least privilege by design; it runs in your environment; the analyst stays in control.

**VOICE-OVER:**
> Access builds on your Entra roles. Five roles - analyst, lead, auditor, automation admin and administrator - each
> scoped to the domains a person works in. Grants can expire; nobody can change their own access; and granting a lead
> or administrator role needs a second administrator. Integrations use service-account keys, which can never approve
> an action or change a policy.
>
> The platform is deployed in your own environment - in your cloud tenant or on your own servers - with stored
> e-mails and reports encrypted, retention and legal hold, and high availability. Your data stays with you, and the
> AI it uses is the one you approve.
>
> So: one layer over the tools you already own. One picture of every person and host. Investigations that gather
> themselves, conclusions that cite their evidence, figures and verdicts computed in code - and every decision that
> matters made by a person, and recorded.
>
> Thank you for watching.

---

## Before you publish

- Every tool is simulated (vendor-shaped sample data through the same code that reads the real tools). If an
  approved action appears to run, say "in this demo".
- Read any figure you add off the screen on the recording day; the AI's wording changes between runs.
- Only the fictional Acme organisation appears - no real tenant, person or data.
