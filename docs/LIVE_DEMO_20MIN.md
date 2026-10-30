# Live demo in 20-23 minutes - run sheet

A timed path through the platform for a live audience. It covers every important feature and concept, in an order
that tells one story. For the detail behind any screen (every section, every formula, the long Q&A) keep
[LIVE_DEMO_NOTES.md](LIVE_DEMO_NOTES.md) open in another window; the § references below point into it.

Figures are those of a freshly reset demo (see LIVE_DEMO_NOTES.md - they were read from one). Anything that moves with
the day (risk decay, SLA ages, timings, audit counts, AI wording) is *read it off the screen*.

**Timing at a glance** (target 21 minutes, 2 minutes of slack):

| # | Clock | Segment | Concept it proves |
|---|---|---|---|
| 1 | 0:00 - 1:30 | Opening | one layer over existing tools; code decides, AI explains, people approve |
| 2 | 1:30 - 2:45 | Overview | value measured against a baseline, never invented |
| 3 | 2:45 - 6:45 | Phishing case | end-to-end investigation, two independent analyses, cited evidence |
| 4 | 6:45 - 9:00 | Attack story | cross-tool reconstruction that argues against itself |
| 5 | 9:00 - 10:00 | Entity 360 | one person from every tool; explainable risk |
| 6 | 10:00 - 11:45 | Incident case | exposure-informed triage: same alert, different severity |
| 7 | 11:45 - 13:30 | Approvals | nothing changes without a person; four-eyes live |
| 8 | 13:30 - 15:00 | Intelligence | correlation rules and the read-only analyst assistant |
| 9 | 15:00 - 16:30 | Vulnerabilities | four scanners → one record; priority; closure proved by the tool |
| 10 | 16:30 - 17:45 | Watch lists | the SOC's own block / exception lists on every case, context only |
| 11 | 17:45 - 19:30 | Govern | safe rollout per tool, autonomy policy and kill switch, AI by model name |
| 12 | 19:30 - 20:30 | Reports and audit | figures that can't drift, client style, tamper-evident trail |
| 13 | 20:30 - 21:30 | Close | limits, what's next |

---

## Before the audience arrives (10 minutes earlier)

- [ ] Start clean with `.env` loaded: `scripts\serve_with_env.cmd reset`. The first log lines must say
  `sign-in: development sign-in on`.
- [ ] Three browser profiles signed in: **Lena** (Lead, all domains - your main window), **Alice** (Lead, all domains -
  the second approver), **Ada** (Admin, all domains).
- [ ] Check: **Cases** *All 10 · Phishing 7 · Incident 3*; **Approvals** 37; **Vulnerabilities** 6.
- [ ] Open the case *Reported: Action required: your password expires today*, then its **Attack story**, once (warms
  it). With the AI on, run **Deep analysis** once so it is cached.
- [ ] Open these as tabs in Lena's window, in this order, so you never hunt for a page: Overview · the phishing case ·
  Cases · Approvals · Intelligence · Vulnerabilities · Watch lists · Integrations · Automation policy · Reports · Audit
  log. Ada's window: AI usage.
- [ ] A small watch-list workbook on the desktop: sheet *Users* with a *Username* header and `ACME\jane.doe`; sheet
  *Hosts* with a *Hostname* header and `web01`.
- [ ] Approve nothing beforehand; every approval moves counts on several pages.
- [ ] 1920 × 1080, about 90 % zoom, light theme.

---

## 1. Opening - 0:00 to 1:30 (no clicks; Overview on screen)

**Say:**
> "Your SOC already has strong tools. The time goes into gathering, correlating and documenting across them. This
> platform is one investigation and automation layer on top of the tools you already own - 21 connectors, three
> workflows: phishing, incidents and vulnerabilities, plus an intelligence layer across all three."

**The three rules - say them slowly; most questions come back to one of them:**
1. **Every figure, score, verdict and severity is computed in code.** Same evidence, same answer.
2. **The AI only explains.** Every sentence must cite evidence or it is removed, and with the AI off you get the same
   numbers, verdicts and actions.
3. **Nothing changes in a security tool until a person approves it.** The default for every action is *recommend*.

**Say the limits up front (it buys credibility):**
> "What you're seeing runs on vendor-shaped sample data through the production code. It hasn't run on your tenant yet
> - that happens tool by tool, read-only first. Accuracy on your mail and alerts is measured in shadow mode against
> your analysts' decisions."

---

## 2. Overview - 1:30 to 2:45

**Click:** nothing - point.

- **Tiles:** *Open cases 8* (2 of 10 auto-closed), *Awaiting approval 37*, *Automation rate 0 %*.
  > "Zero percent automation is by design. Automation is switched on per action type, by a two-person decision,
  > when the evidence says it's safe."
- **Value scorecard:** 8 benefit measures - phishing handling time, time to contain a click, alert to decision,
  time to a validated fix, findings past SLA, report hours, analyst capacity freed, agreement with analysts.
  > "Each row says where its number comes from. Until you give it a baseline it says *awaiting baseline* - it never
  > invents a saving."
- **Automation quality gate** under the table: agreement ≥ 90 % and missed threats ≤ 2 %; *not yet met*.
  > "This is the evidence you'd want before automating anything."
- **Data quality:** asset and identity match rate, unresolved queue 0. One sentence:
  > "Every tool's records are resolved to one host and one person. Ambiguous matches go to a review queue, never
  > guessed."

---

## 3. Phishing case - 2:45 to 6:45 (the centrepiece)

**Click:** the tab with *Reported: Action required: your password expires today*. (Detail: LIVE_DEMO_NOTES §6.)

**Tell the story the platform worked out by itself (point at each as you go):**
1. **Verdict: malicious, 95 %, critical.** A sender imitating Microsoft (`micros0ft` with a zero), failed DMARC,
   display name mismatch, pressure language, a link domain rated malicious by three intelligence sources.
2. **Analysis card - two independent verdicts side by side:** seven offline ML models (one per e-mail component) and
   fixed, named rules. The more severe counts.
   > "The models run inside the platform - no e-mail leaves for analysis. Links are never opened or fetched."
3. **Campaign scope:** every recipient of the same campaign found (8).
4. **Who clicked:** Jane clicked through; another click was **blocked by Safe Links - and a blocked click is not
   counted as a click.**
5. **Impact on Jane:** the EDRs, Entra and DNS were queried in parallel: PowerShell on her laptop reaching the
   phishing domain, a sign-in from an anonymising network, a new inbox forwarding rule, a new device.
6. **Control disagreement:** both e-mail security tools had passed the message - recorded as evidence.

**Show grounding (15 seconds, it lands well):** hover a reference like **E3** in the Assessment - the popover shows tool,
time and record; click it and the evidence row lights up.
> "Facts and inferences are kept apart, and every statement points at a record."

**Recommended actions (9):** scroll to the table.
> "Contain first, communicate last. Purge, isolation, password reset and domain block need two different people.
> Purge and password reset are destructive - never automatic, whatever the policy says."

Point at the right column in one breath: *Entities* (with *seen by* - which tools), *Analyst decision* (feeds the
quality measures), *Analyst notes* (append-only), *Timeline* and *Audit trail*.

---

## 4. Attack story - 6:45 to 9:00

**Click:** **Attack story** on the case. (LIVE_DEMO_NOTES §8.)

- **Read the computed reason aloud:** *"Confirmed compromise - 8 kill-chain stages reached (1 more blocked),
  corroborated by 9 tools; benign explanations rejected."*
  > "This verdict is a rule, not the AI: three or more stages including a deep one, three or more tools, and no
  > benign explanation left standing."
- **Kill chain:** observed / blocked / *checked - none* / *blind spot*.
  > "Privilege escalation was blocked by the privilege manager. And 'not found' always says which tools looked - a
  > stage no tool can see is a blind spot, never 'clean'."
- **Benign explanations tested** - the most persuasive section:
  > "It argues against itself: legitimate e-mail? Rejected. Travel or VPN? Rejected - anonymising network. Legitimate
  > IT script? Rejected - it reached the phishing domain. Privileged secret access was normal duty? Unlikely - confirm
  > with its owner."
- **Response plan:** Contain → Preserve evidence → Eradicate → Recover → Communicate; *Approve selected* still goes
  through the policy and four-eyes for each action.
- **Deep analysis** (only if AI is on and it's cached): one sentence.
  > "An optional second opinion from the model on exactly this evidence, pseudonymised. If it disagrees, it says so
  > in red - the platform's verdict does not change."

---

## 5. Entity 360 - 9:00 to 10:00

**Click:** `jane.doe@acme-demo.com` in the story. (LIVE_DEMO_NOTES §9.)

- **Seen by 10 tools.** *Identifiers* lists every key that tied them together (Entra id, UPN, SID, SAM name).
  > "The 'jane.doe' in the EDR and the 'ACME\jane.doe' in the vault are known to be the same person."
- **Risk 100/100 - Why this score:** each signal with its points and source (deception hit +50, endpoint alert +40,
  risky sign-in +30...).
  > "Score = 100 × (1 − e^(−points/60)): every signal raises it, each by less, so one noisy alert can't make someone
  > critical. Activity halves every 7 days; open exposures and incidents don't decay until fixed."

---

## 6. Incident case - 10:00 to 11:45

**Click:** Cases tab → **Unusual outbound connection from web server**. (LIVE_DEMO_NOTES §7.)

- Point at **Why high** in the Assessment:
  > "The tool rated this alert **low**. web01 carries Log4Shell, a CISA known-exploited vulnerability - one level up.
  > It's internet-facing and business-critical in the CMDB - at least high. The same alert on a patched laptop
  > would stay low. The platform knows because it holds the vulnerability and CMDB data too."
- **Needs review, 55 %:** only two independent areas agree.
  > "It's honest that a person should look - and still recommends containment."
- **Evidence** came from parallel enrichment: every relevant tool asked at once, 20-second deadline; a tool that
  doesn't answer shows as *unavailable*, never as "nothing found".

---

## 7. Approvals and four-eyes - 11:45 to 13:30

**Click:** Approvals tab. (LIVE_DEMO_NOTES §10.)

> "Every write the platform wants to make arrives here - what, which targets, why, under which policy. There is no
> other path to a tool."

1. Approve an **email.reporter_feedback** row → it runs (against the simulated mail system).
2. Approve an **endpoint.isolate** row → toast *"First approval recorded - a second lead must approve"*.
3. Switch to **Alice's** window → Approvals → approve the same row → it runs.

> "Same person can't give both approvals. API keys can never approve. Preconditions are re-checked at the moment it
> runs, a retry can never isolate a host twice, and a reversible action records its reverse."

---

## 8. Intelligence - 13:30 to 15:00

**Click:** Intelligence tab. (LIVE_DEMO_NOTES §4.)

- **Situation brief:** the chip says *AI narrative* or *Platform summary* - say which, and that the figures are the
  same either way.
- **Correlated findings (20):** expand the top one (the phishing compromise chain) - rule name, evidence, next steps.
  > "13 fixed correlation rules across every domain - compromise chain, privileged access after compromise, exposed
  > host under attack, supplier fraud, repeat clicker... The AI may write the paragraph, never the finding."
- **Ask the analyst:** type `Is jane.doe@acme-demo.com compromised and what should we do first?`
  > "The question becomes look-ups from a fixed, read-only list; the answer is written only from their results, and a
  > sentence without a valid citation is removed. The assistant can't take any action."

---

## 9. Vulnerabilities - 15:00 to 16:30

**Click:** Vulnerabilities tab. (LIVE_DEMO_NOTES §13.)

- Point at **Seen by** on the Log4Shell row: rapid7, crowdstrike, wiz, defender_endpoint.
  > "Four scanners, four names for the same server - one record per host and CVE."
- **Priority:**
  > "CVSS says how bad a bug could be; EPSS and KEV say whether it's being exploited; exposure and criticality say
  > whether it matters here. Known-exploited and internet-facing is always P1. The owner comes from the CMDB."
- **Ask about exposure:** type `which internet facing hosts have KEV vulnerabilities?` → *2 findings on 1 asset*; point
  at the **Filter used** line.
  > "The question becomes a filter that runs on the database - the answer is data, not generated text."
- **Closure is proved, not claimed** (say it; click only if ahead of time): *Sync tickets* reopens a finding whose
  ticket was closed while the scanner still sees it - a *false closure*. Cloud posture does the same with Wiz.

---

## 10. Watch lists - 16:30 to 17:45

**Click:** Watch lists tab, as Lena. (LIVE_DEMO_NOTES §22.)

1. List: *Block list*. Choose the workbook. **Preview** → what would be added, with each entry's type; nothing has
   changed yet.
2. **Upload**.
3. Cases tab → the red *Block list* badges on every case involving Jane or web01.
4. Open the phishing case → the banner names Jane, what matched (`ACME\jane.doe` → her address) and who listed it.

> "Excel or CSV, users, hosts, IPs, domains, URLs, hashes. A match is shown on the case - context only: severity,
> verdict and actions don't change, and an exception never clears a case. Leads only, with MFA, every change audited."

---

## 11. Govern - 17:45 to 19:30 (three screens, about 35 seconds each)

**Integrations** (LIVE_DEMO_NOTES §17): point at the **Stage** column and **Self-check 14 of 14**.
> "Each tool goes live on its own: Fixtures → Record → Read → Recommend → Automate. Before a live stage, preflight
> checks sign-in, every data stream's permission, parsing, freshness and the clock, and names the fix. Secrets live in
> your vault - this screen only says *Set* or *Not set*. A change is proposed by one person and approved by another,
> no restart, and any tool can be paused instantly."
(If time: click **Preflight** on CrowdStrike.)

**Automation policy** (§18): the 26 action types, all at **L2**.
> "Autonomy is per action type, versioned, two-person. Destructive actions, VIP targets and big blast radius can never
> run on their own. The kill switch stops every automatic execution across every server - pausing a tool stops every
> write to it."

**AI usage** - Ada's window (§19): point at a feature's **model dropdown** (gpt-4.1-nano / gpt-4.1-mini / gpt-4.1),
the monthly and daily **budgets**, and **usable %**.
> "You choose the model per feature, by name, and can add more. Budgets and per-person limits; over a limit, or with
> the model down, people get the platform's own cited text - nothing that matters changes. Recommended: gpt-4.1-mini for
> routine text and gpt-4.1 for reports and deep analysis - about $21 a month at your volume."

---

## 12. Reports and audit - 19:30 to 20:30

**Reports** (§20): point at the **standard reports** and **Report style**.
> "Every figure in a report is computed and handed to the writer as numbered facts; a sentence with a figure that
> isn't in them is removed. Upload your Word and PowerPoint templates, logo and writing guide, and every report
> follows your house style."

**Audit log** (§23): point at *Chain verified* and the two approval records of the isolation you just did - two
different actors.
> "Append-only and SHA-256 hash-chained: changing any record breaks the chain, and the database itself refuses edits.
> Export it as JSON Lines, CSV, Excel or a Word report - an unfiltered export can be re-verified outside the
> platform."
(If time: click **Trace** on a model-call row: the exact pseudonymised prompt, the answer, and every sentence the
evidence check removed.)

---

## 13. Close - 20:30 to 21:30

> "To sum up: one layer over the tools you have. Code computes every figure and verdict, the AI explains with
> citations and can be switched off, and nothing touches a tool without a person - by default, for every action.
> Development is complete. Next is your environment and sign-in, then your tools connected read-only one at a
> time, and a shadow-mode pilot measured against your analysts."

Then go to the deck's last slide (*Next steps and what we need to go live*) and open for questions.

---

## If you are running long or short

| Behind by | Cut |
|---|---|
| 1 min | Entity 360 (§5) - say the risk formula on the attack story instead |
| 2 min | the Ask-the-analyst question (§8); the exposure question (§9) |
| 3+ min | Watch lists upload (§10) - just say it and show the Watch lists page; AI usage (§11) - one sentence |

**Ahead of time? Add, in this order:** upload `artifacts/phishing/corpus/html_attachment_phish.eml` on *Phishing →
Analyse a message* (a new malicious case appears in seconds) · Cloud posture: **Mark fixed → Validate** on acmebackups →
*false closure - reopened* (say: *"it never changes Wiz or the cloud - it routes the fix and proves it"*; the *Ownership mapping* card is where the cloud teams' spreadsheet of subscription → team is uploaded, since Wiz has no CMDB) · ATT&CK coverage (93.8 %, 0 blind spots, 4 single-source) · Supplier risk (a look-alike
supplier domain and the real supplier's mailbox likely compromised) · Shadow IT.

---

## The ten questions you will get (answers in one breath)

| Question | Answer |
|---|---|
| Is the AI deciding? | No. Verdicts, scores, severities and findings are fixed rules in code; the AI writes cited narrative only, and with it off every number is the same. |
| Does our e-mail go to OpenAI? | The ML models run offline in the platform. The optional narrative sees only the evidence, with identities pseudonymised, sent only to the approved endpoint - your own LLM gateway in production. |
| Do you click the links? | Never. Nothing fetches a URL taken from an e-mail. |
| How accurate is it? | On our small labelled test set, the models plus rules got every verdict right - a regression check, not a claim. Real accuracy is measured in shadow mode on your mail. |
| What if a tool is down? | Its evidence shows as *unavailable* and everything else keeps working; tested with every tool down at once. |
| Can it act on its own? | Not by default - every action is L2, recommend. Automation is per action type, two-person, and destructive actions never run on their own. |
| What does the kill switch stop? | Every automatic execution, on every server, surviving restarts. A person's explicit approval still runs; pause a tool to stop every write to it. |
| Where does it run? | In your environment - Azure or on premises - with PostgreSQL; stored e-mails and reports are encrypted at rest. Outbound only to your tools, your LLM endpoint and webhooks. |
| What do you need from us? | The deck's last slide: environment, Entra app registration, one read-only service account per tool and the reporting mailbox, LLM gateway access, licence confirmations, tool owners and two SOC leads. |
| Is it hard-coded to the demo? | No. The test suite renames the whole organisation into other generated estates and requires the same results with zero leaked demo names. |

**Never say:** "it runs on a real tenant", "the AI decides", "99 % accurate", "it isolated the laptop" (say: "in this
demo, against the simulated tool, after two approvals"), "the kill switch stops everything", or any number not on the
screen. And never name the client or its in-house LLM platform - say "your organisation" and "your LLM gateway".
