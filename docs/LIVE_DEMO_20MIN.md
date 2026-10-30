# Live demo in about 25 minutes - speaking script

Read the plain paragraphs aloud. Lines starting with **▶** are what you click or point at - do them, don't say them.
Each section shows its clock time; if you're behind, see *Running long or short* at the end. The detail behind every
screen (formulas, every section, the long Q&A) is in [LIVE_DEMO_NOTES.md](LIVE_DEMO_NOTES.md) - keep it open in
another window.

The figures below are those of a freshly reset demo. Anything that moves with the day - risk scores, SLA ages,
timings, audit counts, the AI's wording - read off the screen rather than from this page.

**Timing at a glance** (about 24 minutes, with a minute of slack):

1. Opening - 0:00
2. Overview - 1:30
3. Phishing case - 2:45
4. Attack story - 6:45
5. Entity 360 - 9:00
6. Incident case - 10:00
7. Approvals and four-eyes - 11:30
8. Intelligence - 13:15
9. Vulnerabilities - 14:45
10. Cloud posture - 16:00
11. Insight: ATT&CK coverage, Shadow IT, Supplier risk - 17:00
12. Watch lists - 19:15
13. Govern - 20:15
14. Reports and audit - 22:00
15. Close - 23:00 to 24:00

---

## Before the audience arrives (10 minutes earlier)

- [ ] Start clean with `.env` loaded: `scripts\serve_with_env.cmd reset`. The first log lines must say
  `sign-in: development sign-in on`.
- [ ] Three browser profiles signed in: **Lena** (Lead, all domains - your main window), **Alice** (Lead, all domains -
  the second approver), **Ada** (Admin, all domains).
- [ ] Check: **Cases** shows *All 10 · Phishing 7 · Incident 3*; **Approvals** 37; **Vulnerabilities** 6.
- [ ] Open the case *Reported: Action required: your password expires today*, then its **Attack story**, once to warm
  it. With the AI on, run **Deep analysis** once so it is cached.
- [ ] Tabs in Lena's window, in this order: Overview · the phishing case · Cases · Approvals · Intelligence ·
  Vulnerabilities · Cloud posture · ATT&CK coverage · Shadow IT · Supplier risk · Watch lists · Integrations ·
  Automation policy · Reports · Audit log. Ada's window: AI usage.
- [ ] A small watch-list workbook on the desktop: sheet *Users* with a *Username* header and `ACME\jane.doe`; sheet
  *Hosts* with a *Hostname* header and `web01`.
- [ ] Approve nothing beforehand - every approval moves counts on several pages.
- [ ] 1920 × 1080, about 90 % zoom, light theme.

---

## Every tab, in a sentence or two

The sidebar has four groups. Use these when someone asks *"what's that tab?"*, or to fill time. The section number
says where the script demonstrates it; *(on request)* means it isn't in the timed path.

### Operate - the daily work

**Overview** (section 2).
This is the front page: the last fourteen days across phishing, incidents and vulnerabilities - open cases, actions
waiting for approval, the automation rate, and the value scorecard. Every figure is computed from stored records.

**Intelligence** (section 8).
This looks across all three workflows at once. It has a situation brief, the correlated findings raised by thirteen
fixed rules, the riskiest people and machines with their scores, and an assistant you can ask questions in plain
English. The assistant only explains - it can't act.

**Cases** (sections 3 and 6).
Every investigation, phishing and incidents together. You can filter by domain or by owner, take a case yourself, and
open any case for its evidence, its reasoning and its recommended actions.

**Approvals** (section 7).
Every action the platform wants to take, waiting for a person. You can filter by domain or by your own cases, and *Why
and what* shows the evidence and the impact without leaving the list. Nothing here runs until the right person
approves it.

### Domains - one screen per workflow

**Phishing** *(on request; "ahead of time" item 2)*.
Everything about reported e-mail: how many were reported, how many closed automatically, campaigns, who clicked and who
clicked more than once, and how long containment took. You can also upload a suspicious e-mail here and get a full
case in seconds.

**Vulnerabilities** (section 9).
Findings from four scanners merged into one record per machine and vulnerability, ranked by real-world risk, with the
owner and the deadline. Every vulnerability opens to show exactly why it got its priority.

**Cloud posture** (section 10).
Cloud misconfigurations found by Wiz, each routed to the owning team with a deadline and a ticket. When a team says
it's fixed, the platform asks Wiz again before it believes them.

### Insight - where you stand

**ATT&CK coverage** (section 11).
This maps the attacker techniques in the MITRE ATT&CK framework against the tools you have switched on. It shows what
you can see, what you can't - the blind spots - what only one tool can see, and which detections have actually fired.

**Shadow IT** (section 11).
From DNS traffic, this shows the online services people use that aren't on your approved list, and any risky sites
that were reached or blocked.

**Supplier risk** (section 11).
For your key suppliers, this watches for look-alike domains, impersonation and payment-diversion attempts - the signs
that a supplier's mailbox has been taken over.

### Govern - control and proof

**Watch lists** (section 12).
Your SOC's own block and exception lists - users, machines, IP addresses, domains, links and file hashes. Every case is
checked against them, and a match is shown as context only.

**Integrations** (section 13).
Where each tool is connected and rolled out stage by stage, with preflight checks, data freshness and the scheduled
jobs. A change is proposed by one person and approved by another, and any tool can be paused at once.

**Automation policy** (section 13).
How much each kind of action may do on its own - today, everything is recommend only. Policy changes need a second
person, and the kill switch is here.

**AI usage** (section 13).
Which AI model each feature uses, the monthly and daily budgets, per-person limits, and what it all costs.

**Reports** (section 14).
The standard reports, ready to run, or describe a report in words and the platform plans it. Every figure is computed
in code, and reports follow your own templates and style.

**Access** *(on request; "ahead of time" item 3)*.
For administrators: who has which role, granted with a reason and an end date; keys for service accounts, shown only
once; and a table of exactly what every role can do. An administrator can't approve actions - that's a different job.

**Audit log** (section 14).
Every look-up, recommendation, approval and action, by a person or by the platform, in a chain that can't be quietly
changed - and it can be exported and checked independently.

---

## 1. Opening - 0:00 to 1:30

**▶ Overview on screen. No clicks.**

Your SOC already has strong tools. Where the time goes is everything in between - gathering evidence from each tool,
connecting it, and writing it up.

What I'm going to show you is one investigation and automation layer that sits on top of the tools you already own.
It connects to twenty-one of them, and it runs three workflows - phishing, incidents and vulnerabilities - with an
intelligence layer that looks across all three.

Before I click anything, there are three rules this platform lives by. Most questions you'll have come back to one of
them.

First: every figure, every score, every verdict and every severity is computed in code. The same evidence always gives
the same answer.

Second: the AI only explains. Every sentence it writes has to point at a piece of evidence, or it's removed. And if you
switch the AI off, you get exactly the same numbers, verdicts and recommended actions.

Third: nothing changes in any of your security tools until a person approves it. That's the default for every single
action.

And one honest point up front. What you're seeing runs on sample data shaped exactly like your vendors' data, going
through the production code. It hasn't run on your tenant yet. That happens one tool at a time, read-only first. And
accuracy on your own mail and alerts is measured in shadow mode, against your analysts' decisions.

---

## 2. Overview - 1:30 to 2:45

**▶ Point at the tiles: Open cases 8, Awaiting approval 37, Automation rate 0 %.**

This is the overview. Eight open cases - two more were closed automatically. Thirty-seven actions waiting for a
decision. And an automation rate of zero percent.

That zero is deliberate. Automation is switched on one action type at a time, by a two-person decision, and only when
the evidence says it's safe.

**▶ Point at the Value scorecard.**

This scorecard tracks the benefits you'd actually care about - how long a phishing report takes to handle, how fast a
clicked link is contained, time from alert to decision, time to a proven fix, and so on. Each row says where its
number comes from. And until you give it your baseline, it says *awaiting baseline*. It never invents a saving.

**▶ Point at the Automation quality gate under the table.**

This line is the evidence you'd want before automating anything: at least ninety percent agreement with your analysts,
and no more than two percent missed threats. Today it says *not yet met* - and that's the honest answer.

**▶ Point at Data quality.**

And one more thing here. Every tool's records are matched to one host and one person. When a match is ambiguous, it
goes to a review queue. It's never guessed.

---

## 3. Phishing case - 2:45 to 6:45 (the centrepiece)

**▶ Open the tab with *Reported: Action required: your password expires today*.** (Detail: LIVE_DEMO_NOTES §6.)

Let me show you one case from start to finish. Someone reported this e-mail. Everything you're about to see, the
platform worked out on its own.

**▶ Point at the verdict.**

The verdict is malicious, ninety-five percent, critical. And here's why. The sender is imitating Microsoft - look
closely, that's "micros0ft" with a zero. It failed DMARC. The display name doesn't match the sender. The wording
pushes you to act now. And the link goes to a domain that three intelligence sources rate as malicious.

**▶ Point at the Analysis card.**

This verdict comes from two independent analyses, side by side. On one side, seven machine-learning models - one for
each part of the e-mail. On the other, a set of fixed, named rules. Whichever is more severe wins.

Two things matter here. The models run inside the platform - no e-mail leaves your environment to be analysed. And no
link is ever opened or fetched.

**▶ Point at campaign scope and who clicked.**

It then worked out the whole campaign: eight people received the same e-mail. And it checked who clicked. Jane
clicked through. Someone else's click was blocked by Safe Links - and a blocked click is not counted as a click.

**▶ Point at the impact on Jane.**

Then it looked at what happened to Jane - asking the endpoint tools, Entra and DNS all at the same time. On her
laptop, PowerShell reached the phishing domain. There was a sign-in from an anonymising network. A new inbox
forwarding rule. And a new device registered to her account.

**▶ Point at the control disagreement.**

And notice this: both of your e-mail security tools let this message through. The platform records that as evidence
in its own right.

**▶ Hover a reference like E3 in the Assessment, then click it.**

Every statement here points at a record. Hover over a reference and you see the tool, the time and the record. Click it
and the evidence lights up. Facts and inferences are kept apart, so you always know which is which.

**▶ Scroll to Recommended actions.**

Here are the nine recommended actions, in order - contain first, communicate last. Purging the campaign, isolating the
laptop, resetting the password and blocking the domain all need two different people to approve. And purge and
password reset are treated as destructive - they can never run automatically, whatever the policy says.

**▶ Sweep down the right-hand column.**

Down the side: every entity involved and which tools saw it, the analyst's decision - which feeds the quality
measures you saw on the overview - notes that can only be added to, never edited, the timeline, and the audit trail.

---

## 4. Attack story - 6:45 to 9:00

**▶ Click Attack story on the case.** (LIVE_DEMO_NOTES §8.)

Now the same incident, rebuilt across every tool as one attack story.

**▶ Point at the reason line at the top.**

Look at the line at the top: confirmed compromise - eight kill-chain stages reached, one more blocked, corroborated by
nine tools, benign explanations rejected.

That verdict is a rule, not the AI. Three or more stages including a deep one, three or more tools agreeing, and no
innocent explanation left standing.

**▶ Point at the kill chain.**

Each stage is marked observed, blocked, checked and nothing found, or blind spot. Privilege escalation here was
blocked by the privilege manager. And when something isn't found, it always tells you which tools looked. A stage no
tool can see is called a blind spot - it's never called clean.

**▶ Point at Benign explanations tested.**

This is the part people find most convincing. The platform argues against itself. Could this be a legitimate e-mail?
Rejected. Could the odd sign-in be travel or a VPN? Rejected - it came from an anonymising network. Could the script
be legitimate IT work? Rejected - it reached the phishing domain. Was the privileged secret accessed as part of normal
duties? Unlikely - and it tells you to confirm with the secret's owner.

**▶ Point at the Response plan.**

The response plan follows the same order: contain, preserve evidence, eradicate, recover, communicate. You can approve
several at once, but each action still goes through the policy and the two-person rule.

**▶ Only if the AI is on and Deep analysis is cached - scroll to it.**

And this is an optional second opinion from the model, on exactly this evidence, with identities pseudonymised. If it
disagrees, it says so in red. The platform's verdict doesn't change.

---

## 5. Entity 360 - 9:00 to 10:00

**▶ Click `jane.doe@acme-demo.com` in the story.** (LIVE_DEMO_NOTES §9.)

This is Jane, as one person, seen by ten tools. The identifiers show how they were tied together - her Entra ID, her
e-mail address, her Windows account. So the "jane.doe" in the endpoint tool and the "ACME backslash jane.doe" in the
password vault are known to be the same person.

**▶ Point at Why this score.**

Her risk is a hundred out of a hundred, and every point is explained: the deception hit, the endpoint alert, the
risky sign-in, each with its source. Every signal raises the score, but each one by a little less, so a single noisy
alert can't make someone critical. Activity fades by half every week. Open exposures and open incidents don't fade
until they're fixed.

---

## 6. Incident case - 10:00 to 11:30

**▶ Cases tab → open *Unusual outbound connection from web server*.** (LIVE_DEMO_NOTES §7.)

Now an incident, to show why the platform needs all your data in one place.

**▶ Point at Why high in the Assessment.**

The tool that raised this alert rated it low. But this server, web01, has Log4Shell - a vulnerability CISA lists as
actively exploited. That moves it up a level. It's also internet-facing, and the CMDB says it's business-critical. So
it's at least high.

The same alert on a fully patched laptop would have stayed low. The platform can only make that call because it holds
the vulnerability data and the CMDB data alongside the alert.

**▶ Point at Needs review, 55 %.**

And it's honest about its confidence: only two independent areas agree, so it marks this for a person to review - and
still recommends containment.

**▶ Point at the Evidence.**

All this evidence came from asking every relevant tool at the same time, with a twenty-second deadline. If a tool
doesn't answer, it shows as unavailable - never as "nothing found".

---

## 7. Approvals and four-eyes - 11:30 to 13:15

**▶ Approvals tab.** (LIVE_DEMO_NOTES §10.)

Every change the platform wants to make in one of your tools arrives here: what it wants to do, to which targets, why,
and under which policy. There is no other path to a tool.

**▶ Click Why and what on an endpoint.isolate row.**

And you don't have to open the case to decide. This shows the evidence the action is based on, exactly what will
happen, whether it can be undone, and who recommended it.

**▶ Approve an email.reporter_feedback row.**

A routine action like thanking the person who reported the e-mail runs as soon as it's approved - here, against the
simulated mail system.

**▶ Approve the endpoint.isolate row.**

Isolating a laptop is different. My approval is recorded - and it waits. A second lead has to approve.

**▶ Switch to Alice's window → Approvals → approve the same row.**

Alice approves - and now it runs.

The same person can never give both approvals. An API key can never approve anything. Preconditions are checked again
at the moment it runs, a retry can never isolate a host twice, and anything reversible records how to reverse it.

---

## 8. Intelligence - 13:15 to 14:45

**▶ Intelligence tab.** (LIVE_DEMO_NOTES §4.)

The intelligence layer looks across all three workflows.

**▶ Point at the chip on the Situation brief.**

This brief is labelled - read the chip: *AI narrative* or *Platform summary*. Either way, the figures in it are the
same.

**▶ Expand the top correlated finding - the phishing compromise chain.**

These are correlated findings - twenty of them right now. Each comes from one of thirteen fixed rules: a compromise
chain like this one, privileged access after a compromise, an exposed server under attack, supplier fraud, a repeat
clicker. The AI may write the paragraph. It never decides the finding.

**▶ Point at Risk by user and host on the right.**

On the right, the people and machines most at risk right now - Jane at the top, then her laptop. Each score is built
from signals across every tool, and fades as they age. Click any name and you get the full picture you saw for Jane
earlier.

**▶ Type in Ask the analyst: `Is jane.doe@acme-demo.com compromised and what should we do first?`**

And you can simply ask. Behind the scenes, the question becomes look-ups from a fixed, read-only list. The answer is
written only from what those look-ups returned, and any sentence without a valid source is removed. The assistant
can't take any action.

---

## 9. Vulnerabilities - 14:45 to 16:00

**▶ Vulnerabilities tab.** (LIVE_DEMO_NOTES §13.)

**▶ Point at Seen by on the Log4Shell row.**

Look at this row. Four scanners - Rapid7, CrowdStrike, Wiz and Defender - each with its own name for the same server.
The platform turns that into one record per server and vulnerability.

**▶ Click the CVE to open the finding.**

And every finding opens. Here's how its priority was worked out. The CVSS score says how bad a bug could be. EPSS and
the CISA list say whether it's actually being exploited. Exposure and criticality say whether it matters here. Each
one shows exactly what it added. Anything known-exploited and internet-facing is always top priority. The owner comes
from the CMDB.

**▶ Back to the list. Type in Ask about exposure: `which internet facing hosts have KEV vulnerabilities?`**

You can ask questions here too. The answer: two findings on one server. And look at the line underneath - *filter
used*. Your question became a filter on the database. The answer is data, not generated text.

**▶ Say it; click Sync tickets only if you're ahead of time.**

And a fix is proved, not claimed. If someone closes a ticket while the scanner still sees the vulnerability, the
platform reopens it and calls it a false closure.

---

## 10. Cloud posture - 16:00 to 17:00

**▶ Cloud posture tab.**

The same idea, for your cloud. Wiz finds misconfigurations - not software bugs, but settings that leave something
open. Here there are two.

**▶ Point at the two rows: the exposed VM on web01, and public blob access on acmebackups.**

A virtual machine that's exposed to the internet, with a critical vulnerability and a highly privileged identity -
that's high, and it goes to the Web Platform team. And a storage account that allows public access to its files -
medium, for the Cloud Platform team. Each has an owner, a deadline, and a ticket waiting for approval. You saw those
tickets in the approvals queue, in plain words, saying exactly what to fix.

**▶ On acmebackups: click Mark fixed, then Validate.**

Now say the team tells us it's fixed. The platform doesn't take their word for it - it asks Wiz again. Wiz still sees
the problem, so it's marked a false closure and reopened.

It never changes Wiz or your cloud. It routes the fix to the right owner, and proves whether it happened.

**▶ Point at the Ownership mapping card.**

And because Wiz has no CMDB, your cloud teams can upload their spreadsheet of which subscription belongs to which
team, right here.

---

## 11. Insight - 17:00 to 19:15 (three screens, about 45 seconds each)

These next three screens answer a different question: not *what's happening*, but *where do we stand*.

**▶ ATT&CK coverage tab.**

This is MITRE ATT&CK - the public catalogue of how attackers operate, from getting in through to stealing data or
causing damage. Each column is a stage of an attack, and each box is a technique.

**▶ Point at the four tiles.**

For every technique, the platform asks two questions. Could we see it, with the tools you have switched on? And have
we seen it - has a detection actually fired? Right now that's ninety-three point eight percent coverage, and no
priority blind spots: nothing important that none of your tools can see.

But look at this: four techniques only one tool can see. Password spraying and MFA fatigue - only Entra. Hiding
command traffic in DNS, and uploading data to cloud storage - only Umbrella. If one of those tools goes down, you're
blind to them.

**▶ Point at the Exfiltration column.**

And the weakest stage is data leaving the company - fifty percent. That's exactly the kind of finding that should
drive a tool decision.

**▶ Hover any box.**

Hover over any technique and it tells you which tools detect it, and how often it's fired. Switch a tool off, and this
map changes immediately - so you can see what you'd lose before you lose it.

**▶ Shadow IT tab.**

From DNS traffic, this shows the online services people use that aren't on your approved list. Here, five of them,
used by four people. AnyDesk is flagged high risk - remote-access software is a favourite of attackers. Then
WeTransfer, DeepSeek, NordVPN and MEGA.

**▶ Point at Risky destinations.**

And risky sites: the phishing domain from our case was reached, and a fake Flash-update site was blocked. The traffic
is counted and summarised; the individual requests aren't stored.

**▶ Supplier risk tab.**

And this one protects you from your suppliers' problems. For each key supplier, the platform watches for look-alike
domains, impersonation and payment-diversion attempts.

**▶ Point at Krishna Logistics.**

Krishna Logistics is critical. Someone registered a look-alike domain - one letter different, an "l" where there
should be an "i". There are requests to change bank details, and the advice is right there: verify by phone, using a
number you already have. And one message passed the supplier's own authentication - which means the real supplier's
mailbox is probably compromised.

**▶ Point at Microsoft (cloud provider).**

And the domain from our phishing case shows up here too, imitating Microsoft. One finding, seen from every angle.

---

## 12. Watch lists - 19:15 to 20:15

**▶ Watch lists tab, as Lena.** (LIVE_DEMO_NOTES §22.)

Your SOC keeps its own lists - accounts to watch, hosts that are allowed to do unusual things. Those come in here.

**▶ List: Block list. Choose the workbook. Click Preview.**

I'll load a spreadsheet. Preview shows exactly what would be added, and what kind of entry each one is. Nothing has
changed yet.

**▶ Click Upload. Then the Cases tab.**

Now look at the cases: every case involving Jane or web01 carries a red *Block list* badge.

**▶ Open the phishing case and point at the banner.**

And on the case, it says who matched, what matched - "ACME backslash jane.doe" became her e-mail address - and who put
it on the list.

It takes Excel or CSV, and users, hosts, IP addresses, domains, links and file hashes. A match is context only.
Severity, verdict and actions don't change, and an exception never clears a case. Only leads can change these lists,
with MFA, and every change is audited.

---

## 13. Govern - 20:15 to 22:00 (three screens, about 35 seconds each)

**▶ Integrations tab. Point at the Stage column and Self-check 14 of 14.** (LIVE_DEMO_NOTES §17.)

Now, how this goes live safely. Each tool is switched on by itself, in stages: sample data, then recording, then
read-only, then recommend, and only then automate.

Before any live stage, a preflight check tests the sign-in, the permission for every data stream, that the data can
be read, that it's fresh, and that the clocks agree - and if something's wrong, it names the fix. Your secrets stay in
your vault; this screen only ever says *set* or *not set*. A change is proposed by one person and approved by
another, with no restart. And any tool can be paused instantly.

**▶ If time: click Preflight on CrowdStrike.**

**▶ Automation policy tab. Point at the action types, all at L2.** (§18.)

Autonomy is set per action type, it's versioned, and changing it takes two people. Today every action is at level
two - recommend only. Destructive actions, important people as targets, and anything with a large blast radius can
never run on their own. The kill switch stops every automatic action on every server at once. And pausing a tool
stops every change to that tool.

**▶ Ada's window: AI usage. Point at a model dropdown, the budgets and usable %.** (§19.)

And you stay in control of the AI. You pick the model for each feature, by name, and you can add more. There are
monthly and daily budgets, and limits per person. If someone goes over a limit, or the model is down, they get the
platform's own cited text instead - nothing that matters changes. Our recommendation is GPT-4.1 mini for routine text
and GPT-4.1 for reports and deep analysis. At your volume, that's about twenty-one dollars a month.

---

## 14. Reports and audit - 22:00 to 23:00

**▶ Reports tab. Point at the standard reports and Report style.** (§20.)

Reports. Every figure in a report is calculated first and handed to the writer as numbered facts. A sentence with a
figure that isn't in those facts is removed. And you can upload your own Word and PowerPoint templates, your logo and
your writing guide, so every report comes out in your house style.

**▶ Audit log tab. Point at *Chain verified* and the two approval records for the isolation.** (§23.)

And here's the trail of everything that happened - including the two approvals for that laptop isolation, by two
different people. This log can only be added to. Every record is chained to the one before it, so changing any record
breaks the chain - and the database itself refuses edits. You can export it to JSON, CSV, Excel or a Word report, and a
full export can be checked again outside the platform.

**▶ If time: click Trace on a model-call row.**

And this shows exactly what the AI was sent, with identities pseudonymised, what it answered, and every sentence the
evidence check removed.

---

## 15. Close - 23:00 to 24:00

So, to sum up. One layer over the tools you already have. Code computes every figure and every verdict. The AI
explains, with sources, and it can be switched off. And nothing touches a tool without a person - by default, for
every action.

Development is complete. The next steps are your environment and your sign-in, then your tools connected read-only,
one at a time, and then a pilot in shadow mode, measured against your own analysts.

**▶ Go to the deck's last slide - *Next steps and what we need to go live* - and open for questions.**

---

## Running long or short

**Behind by about a minute:** skip Entity 360 (section 5). On the attack story, just say: *"Jane's risk is a hundred
out of a hundred, and every point is explained."*

**Behind by two minutes:** also skip typing the question to the analyst (section 8) and the exposure question
(section 9). Just say they exist.

**Behind by three minutes:** also skip Shadow IT (section 11) - say it in one sentence from the tab descriptions -
and skip the Mark fixed / Validate clicks on Cloud posture (section 10): just say the platform asks Wiz again.

**Behind by four or more:** also skip the watch-list upload (section 12) - show the Watch lists page and say what it
does - and cover AI usage (section 13) in one sentence.

**Ahead of time? Add these, in this order:**

1. **A live phishing upload.** ▶ *Phishing → Analyse a message*, upload
   `artifacts/phishing/corpus/html_attachment_phish.eml`. Say: *"A new malicious case appears in seconds."*
2. **The Phishing tab.** Say: *"Everything about reported e-mail in one place - how many were reported, how many
   closed on their own, the campaigns, and who clicked more than once."*
3. **Access, in Ada's window.** Say: *"Roles are granted with a reason and an end date, and an administrator can't
   approve actions - that's a different job."*

---

## The ten questions you will get

**"Is the AI making the decisions?"**
No. Verdicts, scores, severities and findings are fixed rules in code. The AI writes the explanation, with sources,
and that's all. Switch it off and every number stays the same.

**"Does our e-mail go to OpenAI?"**
The machine-learning models run offline, inside the platform. The optional narrative only sees the evidence, with
identities pseudonymised, and only goes to the endpoint you've approved - in production, that's your own LLM gateway.

**"Do you click the links?"**
Never. Nothing in the platform fetches a link taken from an e-mail.

**"How accurate is it?"**
On our small labelled test set, the models and rules together got every verdict right - but that's a regression
check, not a claim. Real accuracy is measured in shadow mode, on your own mail.

**"What happens if one of our tools is down?"**
Its evidence shows as unavailable, and everything else keeps working. We've tested it with every tool down at once.

**"Can it act on its own?"**
Not by default. Every action is at level two - recommend. Automation is switched on per action type, by two people,
and destructive actions never run on their own.

**"What does the kill switch stop?"**
Every automatic action, on every server, and it survives restarts. A person's explicit approval still runs. To stop
every change to a tool, you pause that tool.

**"Where does it run?"**
In your environment - Azure or on-premises - on PostgreSQL. Stored e-mails and reports are encrypted. It only connects
out to your tools, your LLM endpoint, and the notification channels you configure.

**"What do you need from us?"**
It's on the last slide: an environment, an Entra app registration, one read-only service account per tool and the
reporting mailbox, access to your LLM gateway, licence confirmations, the tool owners, and two SOC leads.

**"Is it hard-coded to this demo?"**
No. Our test suite renames the whole organisation into other generated companies and requires the same results, with
not a single demo name leaking through.

---

## Never say

- "It runs on a real tenant."
- "The AI decides."
- "Ninety-nine percent accurate."
- "It isolated the laptop." Say instead: *"In this demo, against the simulated tool, after two approvals."*
- "The kill switch stops everything."
- Any number that isn't on the screen.
- The client's name or its in-house LLM platform - say *"your organisation"* and *"your LLM gateway"*.
