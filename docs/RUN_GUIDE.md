# Run guide - starting the platform, loading data and ingesting live during a demo

Everything you need to run the complete system on your laptop, load the sample organisation, and feed new data in
while people watch. Every command here was run end to end before it was written down. Commands are for **Windows
PowerShell** (your machine); a bash equivalent follows where it differs.

For *what to say* while presenting, use [PRESENTER_GUIDE.md](PRESENTER_GUIDE.md). This guide covers *making it run*.

---

## Contents

1. [The 5-minute start](#1-the-5-minute-start)
2. [One-time setup](#2-one-time-setup)
3. [Configure `.env`](#3-configure-env)
4. [Start the platform](#4-start-the-platform)
5. [What the sample data contains, and a 2-minute health check](#5-what-the-sample-data-contains)
6. [Ingesting data live during a demo](#6-ingesting-data-live-during-a-demo)
7. [Using the API directly (tokens and roles)](#7-using-the-api-directly)
8. [With and without the LLM](#8-with-and-without-the-llm)
9. [A different organisation (to prove nothing is hard-coded)](#9-a-different-organisation)
10. [Resetting between demos](#10-resetting-between-demos)
11. [Running with Docker and PostgreSQL](#11-running-with-docker-and-postgresql)
12. [Connecting real tools (after the demo)](#12-connecting-real-tools)
13. [Proving it works: the test and verification commands](#13-proving-it-works)
14. [Troubleshooting](#14-troubleshooting)
15. [Quick reference card](#15-quick-reference-card)

---

## 1. The 5-minute start

If setup (§2) and `.env` (§3) are already done:

```powershell
cd "D:\Code_stuff\Agentic SOC"
.\.venv\Scripts\Activate.ps1
. .\scripts\load_env.ps1                  # note the leading dot
python -m soc_platform init-db
python -m soc_platform demo              # loads the sample organisation (about 1 minute)
python -m soc_platform serve             # the whole platform, jobs included - leave this window open
```

Open **http://127.0.0.1:8080**. Sign in with work email `lena@acme-demo.com` and role **Lead**.

---

## 2. One-time setup

**You need:**
- Python 3.11 or newer.
- Git.
- Optionally Node.js 18+, only for the automated browser tour (§13).

```powershell
cd "D:\Code_stuff\Agentic SOC"
python -m venv .venv                      # skip if .venv already exists
.\.venv\Scripts\Activate.ps1
pip install -r requirements\platform.txt
pip install -r requirements\dev.txt       # only for running the tests (§13)
```

If PowerShell refuses to run `Activate.ps1`, allow local scripts once for your user:
`Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`.

**The phishing ML engine** (your trained models: header, content, URL, attachment, threat intel, user behaviour;
the sandbox model only with a detonation host) runs automatically when its libraries are installed:

```powershell
pip install -r requirements\phishing.txt     # scikit-learn 1.8, XGBoost, LightGBM, LangGraph (no PyTorch needed)
```

Then every reported e-mail is analysed by the models **and** the platform's rule-based analyser, and each case shows
both opinions and every model's score. `demo` prints which analysis it used. The server loads the models in the
background at start-up (about 10 seconds). Without these libraries, or with `SOC_PHISHING_ENGINE=0`, the rule-based
analyser works alone.

---

## 3. Configure `.env`

The platform reads its settings **from the environment only**. It does not read `.env` by itself.
`scripts\load_env.ps1` loads the file into your current PowerShell window:
- it skips comments and empty values
- it strips inline comments and quotes
- it prints only the names it set, never the values

**Your `.env` needs these two lines, which it does not have yet.** Without them you can't sign in, and phishing
can't tell internal senders from external ones:

```ini
SOC_DEV_JWT_SECRET=<a long random string>
SOC_ORG_DOMAINS=acme-demo.com
```

Generate the secret, then paste it into `.env`:

```powershell
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

**Optional settings:**

| Setting | Default | When to set it |
|---|---|---|
| `SOC_LLM_PROVIDER`, `SOC_LLM_ENDPOINT`, `SOC_LLM_API_KEY`, `SOC_LLM_DEPLOYMENT`, `SOC_LLM_APPROVED_ENDPOINTS`, `SOC_LLM_MODEL_VERSION` | none (deterministic) | Already in your `.env` for Azure AI Foundry. See §8 |
| `SOC_PORT` | 8080 | If 8080 is taken |
| `SOC_HOST` | 127.0.0.1 | `0.0.0.0` to let another machine on your network open it (dev sign-in stays local-only; see §14) |
| `SOC_DATABASE_URL` | `sqlite:///./soc_platform.db` | A separate database per demo, or PostgreSQL |
| `SOC_RAW_PAYLOAD_DIR`, `SOC_REPORT_OUTPUT_DIR` | `.\data\raw`, `.\data\reports` | Where reported e-mails and generated reports are written |

**Don't set** `SOC_ENVIRONMENT=prod` for a laptop demo. Production mode requires single sign-on, an encryption key
and MFA, and it turns off the dev sign-in you use in the demo. Deploying for real (the client's tools, Entra sign-in,
the client's own LLM instead of the demo Azure model) is covered step by step in
[CLIENT_DEPLOYMENT_GUIDE.md](CLIENT_DEPLOYMENT_GUIDE.md).

The other entries in your `.env` (for example `AZURE_OPENAI_*`, `RABBITMQ_*`, `GRAPH_*`) belong to the optional
phishing ML engine. The platform ignores them.

---

## 4. Start the platform

### Start the server

```powershell
cd "D:\Code_stuff\Agentic SOC"
.\.venv\Scripts\Activate.ps1
. .\scripts\load_env.ps1
python -m soc_platform init-db            # creates the tables (safe to repeat)
python -m soc_platform demo               # loads the sample organisation (safe to repeat: changes nothing the 2nd time)
python -m soc_platform serve              # http://127.0.0.1:8080  - Ctrl+C stops it
```

`demo` prints what it loaded:
- `[VM]` lines for the vulnerability refresh and the Log4Shell campaign
- `[IM]` lines, one per incident
- `[PH]` lines, one per phishing report
- the top correlated findings, one analyst answer and three reports
- `[AUDIT] {'ok': True, ...}`

### The scheduler runs inside the server

`serve` also runs the scheduler: the recurring jobs (§5) run in the background, on their intervals, as in
production. **There is no second window to open and nothing to remember.**

- **Jobs start 5 seconds after the server.** Only jobs that are due run. A restart does not re-run everything, because
  the database records what ran and when.
- **`/health` shows `"scheduler": {"state": "running", "mode": "embedded", ...}`.** The server writes a heartbeat
  every 30 seconds, even while a long job runs.
- **If a job hangs for more than 30 minutes, the banner reads "Scheduler stuck (job name)".** If the scheduler stops
  altogether, it reads "Scheduler stopped". Neither can happen quietly.
- **An error in a job is recorded and retried, and the other jobs carry on.** If the scheduler thread itself ever
  stops, it is restarted automatically.
- **Running a separate scheduler as well is safe** (`python -m soc_platform scheduler`). The database decides what is
  due, and a lease stops any job from running twice.

To run the server **without** background jobs (for example, to keep every figure still while you present), start it
with `$env:SOC_EMBEDDED_SCHEDULER = "0"`. The buttons in §6.4 still run any job on demand.

### Signing in (admin and every other user)

Open http://127.0.0.1:8080. In a demo there are no passwords: the **development sign-in** form asks who you are
and which role to act in. (It works only with `SOC_AUTH_MODE=dev`, only from this machine, and never in production,
where people sign in with Microsoft Entra ID and MFA.)

| Field | What to enter |
|---|---|
| **Work email** | Any address at the organisation's domain, e.g. `lena@acme-demo.com`. It does not need to exist anywhere; it is the name that appears in approvals, notes and the audit log. |
| **Role** | Lead, Analyst, Auditor, Automation admin or Admin (what each can do is below). |
| **Data scope** | *All domains* (normal), or *Phishing only* / *Incident only* / *Vulnerability only* to show a person limited to one team's data. |

Press **Continue**. The sidebar footer shows the role and scope you are signed in with. A sign-in lasts 8 hours and
includes MFA, so approvals and other step-up actions work.

**Switch user:** click your name (top right) → **Sign out**, then sign in as someone else.

**Two users side by side** (needed for four-eyes): tabs of one browser share the sign-in, so signing in on a
second tab replaces the first. Use a **private / InPrivate window**, a **second browser profile**, or a different
browser (Edge and Chrome) for the second person.

#### Demo accounts

Use these so the names match the rest of this guide and the presenter guide:

| Sign in as | Role | Scope | What they can do | Use it to show |
|---|---|---|---|---|
| `lena@acme-demo.com` | **Lead** | All domains | Everything an analyst can, plus approve high-impact actions, assign cases to others, roll back, approve policy changes, kill switch, export evidence | The main walkthrough (default on the form) |
| `alice@acme-demo.com` | **Lead** | All domains | Same as Lena | A second Lead, e.g. to approve an action Lena requested herself |
| `ann@acme-demo.com` | **Analyst** | All domains | Investigate, take cases and add notes, request and approve normal actions, resolve entities, read the audit log | Day-to-day triage; an analyst cannot approve high-impact actions or reassign someone else's case |
| `pia@acme-demo.com` | **Analyst** | Phishing only | As Ann, but sees only phishing | Data scoping: other domains disappear from the menu and their records answer "not found" |
| `ada@acme-demo.com` | **Admin** | All domains | Manage access (grant / revoke roles, service-account keys), connectors (test, run jobs), kill switch, export evidence | Access management and separation of duties |
| `max@acme-demo.com` | **Automation admin** | All domains | Propose automation-policy changes, connectors and jobs, kill switch | Policy change control: they propose, a Lead approves |
| `audrey@acme-demo.com` | **Auditor** | All domains | Read everything, audit log and verification, compliance pack and audit export | Audit and compliance, read-only |

The permissions of every role are listed on **Access → Role permissions**, so you can show them on screen.

#### Logging in as admin

1. Sign in as `ada@acme-demo.com` with role **Admin**.
2. Open **Access** (under *Govern*). An admin sees:
   - **Role assignments**: grant a role to anyone (for example `sam@acme-demo.com` → Analyst, scope, days, and a
     required justification). It applies on that person's next click. *Revoke* removes it.
   - **Service accounts**: create an API key for an integration (Auditor, Analyst or Automation admin only). The key
     is shown once.
   - **Role permissions**: what every role may do.
3. Show separation of duties: the admin has **no Approve buttons** (Approvals, case pages) and cannot change their
   own access. Administering the platform and approving changes to security tools are different jobs.
4. **Integrations** as admin: *Preflight* a connector, *Configure* one (change a setting, propose; sign in as a lead to approve it) and *Run now* any job.

To show a grant working: as Ada, grant `sam@acme-demo.com` the **Lead** role for 1 day. In a private window, sign
in as `sam@acme-demo.com` with role **Auditor**. Sam now has the Lead's permissions too (for example the Approve
buttons), and the grant is in the audit log with Ada's justification.

#### The approvals and four-eyes demo

The platform recommends actions; nothing runs until a person with the right role approves.
- **Normal actions** (e.g. create a ticket, block an indicator): an Analyst or a Lead may approve.
- **High-impact actions** need a **Lead**: host isolation and account disable (both marked *four-eyes* in the
  policy), actions on VIP targets, and anything over its blast-radius limit.
- **Four-eyes** means the approver must be a different person from whoever requested the action. When a person
  (not the platform) requests an isolation or an account disable, they can never approve it themselves.

1. Window 1: `ann@acme-demo.com`, Analyst. **Approvals** → find an **Isolate host** (`endpoint.isolate`) action
   and press *Approve*. It is refused: an analyst cannot approve a high-impact action.
2. Window 2 (private): `lena@acme-demo.com`, Lead. **Approvals** → approve the same action. It executes (in fake
   mode, against the fixture EDR).
3. Approve a normal action as Ann (e.g. **Create ticket**) to show that routine work does not wait for a Lead.
   Signed in as Ada (Admin), Max (Automation admin) or Audrey (Auditor), the same Approve is refused.
4. **Audit log**: the recommendation, Lena's approval and the execution, in the hash chain.

#### Showing data scope

Sign in as `pia@acme-demo.com`, Analyst, **Phishing only**.
- The menu loses Vulnerabilities, Cloud posture and Shadow IT.
- Cases and Approvals list only phishing.
- Intelligence (which spans every domain) is refused with "cross-domain data requires all-domain access"; the
  self-check and notifications cards on Integrations are not shown.
- Open an incident case's address (copy it from Lena's window): it answers "not found", which also hides that the
  record exists.

#### Tokens for scripts and the API

The same people and roles are available as tokens for the API (§7):
`python -m soc_platform token ada@acme-demo.com admin`, or with a scope,
`/api/v1/dev/token?user=pia@acme-demo.com&roles=analyst&domains=phishing`.

---

## 5. What the sample data contains

After `demo`:

| Where | What you should see |
|---|---|
| **Cases** | 10 cases: 7 phishing, 3 incidents |
| **Approvals** | 34 actions awaiting a decision (incident 15, phishing 16, vulnerability 3), with or without the ML engine |
| **Vulnerabilities** | 6 open findings; the CVE-2021-44228 (Log4Shell) campaign |
| **Cloud posture** | Misconfigurations routed to their owning teams |
| **Intelligence** | A situation brief, correlated findings, the riskiest users and hosts |
| **Phishing** | The reported credential-phishing campaign (8 recipients, Jane clicked), supplier fraud, CEO fraud, QR phishing, a genuine invoice (safe, auto-closed), marketing spam. With the ML engine each case's *Analysis* card shows the models' and the rules' verdicts and every model's score |
| **Suppliers** | Krishna Logistics: account compromise, look-alike domain, payment diversion |
| **Audit log** | "Chain verified" |

### The 2-minute health check before you present

1. http://127.0.0.1:8080/health shows `"status":"ok"` and `"audit_chain":true`.
2. Overview loads with no error toast. *Awaiting approval* equals the Approvals badge.
3. Open the case *"Reported: Action required: your password expires today"*, then **Attack story**. It shows
   *Confirmed compromise*.
4. If showing the LLM: Reports shows *"Narrative is written by the approved LLM (azure_foundry)"*. Run one **Deep
   analysis** so it is cached.

---

## 6. Ingesting data live during a demo

Four ways to feed new data, from most visual to most technical. Each one runs the same pipeline the connectors use
in production.

### 6.1 Upload a reported e-mail (the most visual)

**Console:** **Phishing** → *Analyse a message* → choose a `.eml` file → **Analyse**. Within a few seconds the new
case opens, with verdict, evidence, campaign scope, user impact, MITRE techniques and recommended actions.

**Samples not yet loaded by `demo`** (in `artifacts\phishing\corpus\`), so each one creates a *new* case:

| File | Expected verdict | What it shows |
|---|---|---|
| `cred_phish_lookalike.eml` | malicious | Look-alike sender domain, DMARC fail, credential lure |
| `html_attachment_phish.eml` | malicious | An HTML attachment posing as a document to sign |
| `iso_dropper.eml` | malicious | A disk-image attachment (risky extension) behind a parcel lure |
| `malspam_macro.eml` | malicious | An Office attachment with macro indicators |
| `legit_github.eml` | safe | A genuine notification: auto-closed, reporter thanked |
| `legit_internal.eml` | safe | An authenticated internal message: auto-closed |

**Worth showing:** upload a file that is *already* loaded (for example `marketing_spam.eml`). The platform returns
the **same** case, never a duplicate. A re-sent or re-reported message is recognised.

**Your own e-mail:** save a message as `.eml`.
- In the new Outlook or Outlook on the web: *More actions (…) → Download* (or drag the message to a folder).
- In Gmail: *⋮ → Download message*.
- Classic Outlook's *Save As* gives `.msg`, which is not accepted. Forward the message to a web mailbox and download
  it from there.

Use only **test messages or ones you may share**. A real message contains real people's addresses. Real inbox
exports stay local, in `test_reports\private\`, which git ignores.

**From the command line** (PowerShell; `curl.exe` ships with Windows):

```powershell
$tok = (Invoke-RestMethod "http://127.0.0.1:8080/api/v1/dev/token?user=lena@acme-demo.com&roles=lead").token
curl.exe -s -X POST http://127.0.0.1:8080/api/v1/phishing/submit -H "Authorization: Bearer $tok" `
  -F "file=@artifacts/phishing/corpus/iso_dropper.eml"
```

**A whole folder at once:**

```powershell
Get-ChildItem .\my_emails\*.eml | ForEach-Object {
  $r = curl.exe -s -X POST http://127.0.0.1:8080/api/v1/phishing/submit -H "Authorization: Bearer $tok" -F "file=@$($_.FullName)" | ConvertFrom-Json
  "{0,-40} {1,-11} {2}" -f $_.Name, $r.case.verdict, $r.case.title
}
```

Limits: 30 MB per message. Empty, binary or malformed files are refused with a clear error, never a crash.

### 6.2 Pull the reporting mailbox

**Console:** **Phishing** → **Pull reporting mailbox** (or **Cases** → **Pull reported email**).

This fetches messages users reported with the *Report* button in Outlook (Defender for Office 365) and analyses
them. In fake mode the sample mailbox holds the one campaign report, already loaded, so a second pull finds nothing
new. That shows the ingest is idempotent. With live connectors (§12) this pulls real reports.

### 6.3 Push an alert from a SIEM or any tool (a new incident appears)

Any tool that can send a webhook can push alerts to `POST /api/v1/ingest/alerts`. Push one, then run the incident
pipeline. The alert is resolved to the host and user it names, clustered with related alerts from the last
24 hours, and investigated across the tools.

```powershell
$tok = (Invoke-RestMethod "http://127.0.0.1:8080/api/v1/dev/token?user=lena@acme-demo.com&roles=lead").token
$H = @{ Authorization = "Bearer $tok" }
$alert = @{ alerts = @(@{
    id = "demo-001"                                  # the tool's own alert id (re-sending it is ignored)
    title = "Credential dumping tool detected"
    severity = "critical"                            # informational | low | medium | high | critical
    timestamp = "2026-09-27T10:05:00Z"
    host = "DB01"                                    # resolved to the known host
    user = "raj.mehta@acme-demo.com"                 # resolved to the known person
    source = "demo_siem"
}) } | ConvertTo-Json -Depth 5
Invoke-RestMethod -Method Post http://127.0.0.1:8080/api/v1/ingest/alerts -Headers $H -ContentType "application/json" -Body $alert
Invoke-RestMethod -Method Post http://127.0.0.1:8080/api/v1/incidents/run -Headers $H | Select-Object new_incidents
```

Then refresh **Cases**: the new incident is there, with severity, confidence, MITRE techniques and recommended
actions. Clicking **Cases → Run incident pipeline** in the console does the same as the second command.

**Fields an alert may carry:** `id`, `title`, `severity`, `timestamp`, `host`, `user`, `src_ip`, `dst_ip`, `domain`,
`url`, `sha256`, `source`. Other fields are kept as attributes. A tool with different field names is mapped once in
configuration (`field_map`), with no code change.

Hosts and people the platform already knows make the best demo (`WEB01`, `DB01`, `JANE-LT01`, `jane.doe@`,
`raj.mehta@`, `priya.nair@`...). Their history joins the new incident, and their risk score moves.

bash equivalent:

```bash
TOK=$(curl -s "http://127.0.0.1:8080/api/v1/dev/token?user=lena@acme-demo.com&roles=lead" | python -c "import sys,json;print(json.load(sys.stdin)['token'])")
curl -s -X POST http://127.0.0.1:8080/api/v1/ingest/alerts -H "Authorization: Bearer $TOK" -H "Content-Type: application/json" \
  -d '{"alerts":[{"id":"demo-001","title":"Credential dumping tool detected","severity":"critical","host":"DB01","user":"raj.mehta@acme-demo.com"}]}'
curl -s -X POST http://127.0.0.1:8080/api/v1/incidents/run -H "Authorization: Bearer $TOK"
```

### 6.4 Run the pipelines from the console

| Button | Screen | What it does |
|---|---|---|
| **Pull reported email** / **Pull reporting mailbox** | Cases / Phishing | Fetch and analyse newly reported e-mail |
| **Run incident pipeline** | Cases | Ingest alerts from every tool, cluster, investigate |
| **Refresh from scanners** | Vulnerabilities | Re-read the four scanners, consolidate, prioritise, update SLAs |
| **Start campaign** | Vulnerabilities | Open a remediation campaign for a CVE (notifications need approval) |
| **Sync tickets** | Vulnerabilities | Two-way ticket sync; catches false closures |
| **Route to owners** | Cloud posture | Send misconfigurations to their teams |
| **Re-correlate** | Intelligence | Recompute risk, the 12 correlation rules and the brief |
| **Run now** | Integrations | Run any scheduled job immediately (incident, phishing, vulnerability, intelligence, follow-up, daily report, retention, self-check) |
| **Test** | Integrations | Check a connector: authenticate and read one page |

Everything is idempotent: pressing a button twice never duplicates cases, campaigns or actions.

### 6.5 After ingesting: what to show

- **The new case:** verdict or severity, evidence (hover the E-numbers), recommended actions with their policy
  reasons. Nothing has executed.
- **Attack story** on the case: the new step appears in the kill chain.
- **Entity 360** for the host or person: the risk score and *Why this score* have moved.
- **Approvals:** the new actions are waiting. The count matches on every screen.
- **Audit log:** every step, verified.
- **Take the case and add a note:** on the case, *Take case*, then write a note and *Add note*. Cases → *Mine* now
  counts it. Sign in as a second analyst to show they can take an unassigned case but not someone else's; a Lead
  can reassign.
- **Search:** type a name, e-mail, hostname, CVE or part of a case title in the box at the top and press Enter.
- **With the LLM on and the jobs running:** a new case can briefly say *"The written explanation is being
  prepared"*. The verdict, evidence and recommendations are already final; refresh a few seconds later for the
  model's text.

### 6.6 Notifications to Teams or Slack (optional)

To show findings arriving in a chat channel:

1. Create an incoming webhook: in Teams, a channel's *Workflows* → "Post to a channel when a webhook request is
   received" (or a classic incoming webhook); in Slack, an app with *Incoming Webhooks*.
2. Add it to `.env` (or a vault file named by `SOC_NOTIFY_WEBHOOKS_FILE`) - it contains a secret, never commit it:

   ```
   SOC_NOTIFY_WEBHOOKS=teams|https://<your-webhook-url>
   SOC_NOTIFY_MIN_SEVERITY=high         # medium to see more during a demo
   SOC_PUBLIC_URL=http://127.0.0.1:8080  # messages link back to the console
   ```
   Several channels: separate them with commas (`teams|https://...,slack|https://...,json|https://...`).
3. Reload the environment and restart `serve`. Within a minute (the `notify` job) every open finding at or above the
   threshold is posted once. Push an alert (§6.3) or upload a phishing e-mail (§6.1) and the resulting finding
   follows.
4. **Integrations → Notifications** shows the channels (host only) and each delivery: sent, or failed with the
   error and attempt number. *Run now* on the `notify` job sends immediately.
5. **Send test message** on the same card (signed in as Admin or Automation admin) posts a clearly marked test
   message to every channel at once and says which worked - use it before the demo to prove the channel.

Only `https://` addresses are accepted (`http://` only to localhost, for testing with a local receiver).

---

## 7. Using the API directly

**A token for scripts:**

```powershell
python -m soc_platform token lena@acme-demo.com lead            # prints a token (8 hours)
# or, while the server runs (from this machine only):
(Invoke-RestMethod "http://127.0.0.1:8080/api/v1/dev/token?user=ann@acme-demo.com&roles=analyst").token
(Invoke-RestMethod "http://127.0.0.1:8080/api/v1/dev/token?user=pia@acme-demo.com&roles=analyst&domains=phishing").token   # phishing-only
```

**Roles:** `analyst`, `lead`, `auditor`, `automation_admin`, `admin`. Add `domains=phishing` (or `incident`,
`vulnerability`) to scope a user to one domain. The same user then sees 404 for everything else.

**API documentation (dev mode only):** http://127.0.0.1:8080/docs lists every endpoint. Production mode hides it.

**Useful endpoints:** `GET /api/v1/cases`, `GET /api/v1/cases/{id}/story`, `GET /api/v1/actions?status=pending_approval`,
`POST /api/v1/actions/{id}/approve` (body `{}`), `GET /api/v1/dashboard/overview`, `POST /api/v1/intelligence/ask`
(body `{"question": "..."}`), `GET /api/v1/audit/verify`, `GET /api/v1/search?q=jane`,
`POST /api/v1/cases/{id}/assign` (body `{"assignee": "ann@acme-demo.com"}`, or `null` to clear),
`POST /api/v1/cases/{id}/notes` (body `{"text": "..."}`), `GET /api/v1/cases?assignee=me`,
`GET /api/v1/admin/notifications`.

---

## 8. With and without the LLM

- **Without** (`SOC_LLM_PROVIDER` unset or `none`): every figure, verdict, story and recommendation is identical.
  Narratives come from the deterministic writer. Screens say *"deterministic"*.
- **With** (your `.env` has the Azure AI Foundry settings): narratives, analyst answers, report text and deep
  analysis are written by gpt-4.1-mini, grounded on the evidence and cited.

**Check which mode you're in:** open **Reports**. It says either *"Narrative is written by the approved LLM
(azure_foundry)"* or *deterministic*. Or call `GET /api/v1/llm/status`, which also shows the measured model response
times per workflow (median and 95th percentile).

**If you expected the LLM but see deterministic:**
- The `.env` wasn't loaded in *this* window (run `. .\scripts\load_env.ps1` before `serve`), or
- `SOC_LLM_ENDPOINT` isn't listed in `SOC_LLM_APPROVED_ENDPOINTS`. Unapproved endpoints are refused by design.

**Cost:** a full demo uses well under a cent of tokens (§3 of [LLM_TOKENS_AND_COST.md](LLM_TOKENS_AND_COST.md)).

---

## 9. A different organisation

This proves nothing is tied to the sample organisation: a whole different company, with its own people, machines,
IP plan, suppliers and volumes.

```powershell
python scripts\build_estate_variant.py out\veridian --seed 7           # --seed 23 gives another one; --scale 3 a bigger one
(Get-Content out\veridian\estate.json | ConvertFrom-Json).org            # -> veridianfoods-demo.com
$env:SOC_FIXTURES_DIR = "out\veridian\fixtures"
$env:SOC_SUPPLIERS_FILE = "out\veridian\suppliers.yaml"
$env:SOC_SAMPLE_CORPUS_DIR = "out\veridian\corpus"
$env:SOC_ORG_DOMAINS = "veridianfoods-demo.com"
$env:SOC_DATABASE_URL = "sqlite:///./veridian.db"                        # keep it separate from the main demo
python -m soc_platform init-db; python -m soc_platform demo; python -m soc_platform serve
```

Sign in as `soc.lead@veridianfoods-demo.com` (Lead). Every workflow, the attack story and the reports work. No
screen mentions Acme.

To go back, open a new PowerShell window (these variables live only in the window that set them).

---

## 10. Resetting between demos

**Stop the server first** (Ctrl+C in its window). Then one command:

```powershell
python -m soc_platform reset-demo          # asks you to type RESET; add --yes to skip the question
python -m soc_platform serve
```

It empties the database in `SOC_DATABASE_URL`, deletes the raw payloads and generated reports, and reloads the
sample organisation (`init-db` + `demo`): about 15 seconds without the LLM (measured 14 s), longer with it because the model writes the explanations. It protects you from mistakes:
- it refuses to run while the server is running on `SOC_PORT` (on Windows the database file would be in use)
- it refuses with `SOC_ENVIRONMENT=prod`
- it deletes the raw-payload and report folders only when they are inside the current folder or the project
- without `--yes` it changes nothing unless you type `RESET`

It works on SQLite (the file is deleted) and PostgreSQL (every platform table is dropped and recreated). Only use
it on a demo database: the audit log goes too.

**Or keep a separate database per audience.** Your main database stays untouched:

```powershell
$env:SOC_DATABASE_URL = "sqlite:///./demo_$(Get-Date -Format yyyyMMdd_HHmm).db"
python -m soc_platform init-db; python -m soc_platform demo; python -m soc_platform serve
```

**Why numbers drift from yesterday's screenshots:** risk decays with time and SLA dates fall due, which is correct
behaviour. Re-running `demo` on the same database changes nothing; a fresh database gives today's numbers.

---

## 11. Running with Docker and PostgreSQL

For a production-like run: API, scheduler and PostgreSQL in containers. It needs Docker Desktop. Add to `.env`:

```ini
POSTGRES_PASSWORD=<a strong password>
SOC_DEV_JWT_SECRET=<as in §3>
```

```powershell
docker compose -f deploy\docker-compose.yml --env-file .env up -d --build        # api + scheduler + postgres
docker compose -f deploy\docker-compose.yml --env-file .env exec platform-api python -m soc_platform demo
docker compose -f deploy\docker-compose.yml logs -f platform-api                  # watch the logs (Ctrl+C to stop watching)
```

Open http://127.0.0.1:8080 as before (`SOC_API_PORT` changes the host port).

What you should see (checked end to end on Docker Desktop 29 / Compose 5, 2026-10-07): `/health` reports
`audit_chain: true` and the scheduler `running` in `service` mode; the scheduler's first pass runs the vulnerability
job first, then incidents and phishing; after `demo` the figures are the same as on a laptop (7 phishing and 3
incident cases, 34 actions awaiting approval, 6 open vulnerabilities), and they survive `docker compose restart`.

**With the phishing ML models in the container:** add `WITH_PHISHING_ENGINE=true` to `.env` before `up --build`. The
image then includes the model libraries (scikit-learn, XGBoost, LightGBM, LangGraph - no PyTorch; about 3.7 GB instead
of 1.7 GB) and the models run automatically (`SOC_PHISHING_ENGINE=auto`); `demo` then prints "analysis: ML engine +
heuristic" and gives the same figures and verdicts. Without it the rule-based analyser works alone.

The build context is the repository root; `.dockerignore` keeps `.env`, `.venv`, local databases, `data/`, `logs/`
and documents out of it (about 480 MB is sent, almost all of it the trained models).

**Stop, or wipe everything:**

```powershell
docker compose -f deploy\docker-compose.yml down        # stop (data kept)
docker compose -f deploy\docker-compose.yml down -v     # stop and delete the database volume
```

Here the jobs run in their own `platform-scheduler` container, and the API container's built-in scheduler is
switched off (`SOC_EMBEDDED_SCHEDULER=0`). That is one scheduler service per deployment; more replicas would still be
safe. The phishing ML microservices are a separate profile (`--profile engine`) and are not needed for the demo.

---

## 12. Connecting real tools

After the demo, when the client provides access. Summary here; the full procedure is in
[OPERATIONS.md](OPERATIONS.md).

1. For each tool, create a **read-only** service principal first. Write scopes come later, per action type.
2. Put its secrets in the vault or environment under the names **Integrations → Configure** shows (every secret `X`
   can come from `X_FILE`, for example a vault mount). Secrets are never typed into the console.
3. **Integrations → Configure**: the tool's settings and the stage **Recording** or **Read-only**; *Propose change*.
   The preflight runs on your proposal and says exactly what to fix if anything is wrong. A lead approves; it is in
   force within seconds, no restart. (From a shell: `python -m soc_platform preflight <name>`.)
4. Leave the server running: its scheduler pulls from each tool on schedule, and freshness is watched per stream.
5. Promote one stage at a time: **Recommend** (actions offered, a person approves each), later **Automate**.

Keep automation at L2 (recommend) until shadow mode shows agreement with your analysts.

---

## 13. Proving it works

```powershell
python -m pytest soc_platform\tests -q                          # full platform suite (~15 min)
python scripts\verify_features.py                               # feature-by-feature report -> docs\FEATURE_VERIFICATION.md
python scripts\verify_features.py --browser --engine --live --llm   # + real browser tour, engine suite, live feeds, real LLM (~25 min)
```

To run the same suite on PostgreSQL:

```powershell
pip install pgserver
python -c "import pgserver; print(pgserver.get_server('D:/pgtest_soc', cleanup_mode=None).get_uri())"   # prints a URI
$env:SOC_TEST_POSTGRES = "<that URI>"; python -m pytest soc_platform\tests -q
```

The browser tour needs Node.js and Chrome or Edge. It installs its own two packages on first run.

**Volume and traffic** (real data is larger and messier than the demo, and many people use the console at once):

```powershell
python scripts\measure_scale.py --scales 1,20,40                  # messy estates of growing size: time and SQL per stage, statements per record, review queue
python scripts\measure_scale.py --scales 20,40 --db <postgresql-url>   # the same on PostgreSQL (its tables are dropped and recreated)
python scripts\load_test.py --users 40 --seconds 60 --workers 4   # a real server, 40 analysts at once while the incident job runs: p50/p95/p99, errors, 429s
python scripts\build_estate_variant.py out --seed 7 --scale 40 --messy   # just the estate (people, machines, events, disorder)
```

The load test fails (exit 1) on any server error. Against a target environment, run it with the expected number of
analysts before go-live. To serve many analysts, start several processes: `$env:SOC_API_WORKERS = 4` before
`python -m soc_platform serve` (one per CPU core; the container image runs 4).

---

## 14. Troubleshooting

| Symptom | Cause and fix |
|---|---|
| Sign-in does nothing, or "not available" | `SOC_DEV_JWT_SECRET` is missing in this window. Add it to `.env` (§3), run `. .\scripts\load_env.ps1`, restart `serve`. |
| Signed in as the wrong person / the other window changed user | Tabs of one browser share the sign-in. Use a private window or another browser profile for the second person (§4, *Signing in*). |
| No Approve buttons | You are signed in as Admin, Auditor or Automation admin (none of them approve, by design), or the action needs a Lead. Sign in as `lena@acme-demo.com`, Lead. |
| A screen says it needs all-domain scope | You signed in with a *... only* data scope. Sign out and choose *All domains*. |
| Sign-in fails from another computer | By design, dev sign-in is served only to this machine. For a demo on a big screen, present from this laptop. |
| "Only one usage of each socket address" / port in use | Another server is on 8080. Find it with `netstat -ano \| findstr :8080`, then stop that process: `Stop-Process -Id <PID>`. Or use `$env:SOC_PORT = "8081"`. |
| Screens are empty | `demo` wasn't run on *this* database. Check `SOC_DATABASE_URL`, then run `init-db` and `demo`. |
| Internal senders flagged as external, or look-alikes missed | `SOC_ORG_DOMAINS` isn't set. Set it to the organisation's domain. |
| "deterministic" when you expected the LLM | See §8. |
| "Scheduler stopped" banner | No heartbeat for 3 minutes. The server was started with `SOC_EMBEDDED_SCHEDULER=0` and no separate scheduler runs, or the process stopped. Restart `serve` normally. |
| "Scheduler stuck (job)" banner | That job has run for more than 30 minutes, typically a tool that stopped answering. Check **Integrations** (job history and connector status); the job's lease expires and it is retried. |
| Notifications not arriving | Integrations → *Notifications*: "No channels configured" means `SOC_NOTIFY_WEBHOOKS` is not set in this window, or the entry was rejected (it must be `kind\|https://...`, kind `teams`, `slack` or `json`; the server log names the rejected entry). A *failed* row shows the channel's error; after 5 attempts it stops retrying. Only findings rated at or above `SOC_NOTIFY_MIN_SEVERITY` (default high) and still *new* are sent. |
| A case says "the written explanation is being prepared" for long | The model is slow or unavailable; the next incident / phishing job run retries it. The verdict and recommendations are already final. Check `GET /api/v1/llm/status`. |
| `reset-demo` says the server is running or the file is in use | Stop `serve` (Ctrl+C) - or the other program using the database - and run it again. Nothing was deleted. |
| "database is locked" | Two processes are writing one SQLite file (for example two servers). Stop one. Use PostgreSQL (§11) for more. |
| Upload refused (413) | The file is larger than 30 MB. |
| "rate limit exceeded" (429) while scripting | Default 20 requests/s per client. Slow the script, or set `SOC_RATE_LIMIT_RPS=200` for a local demo. |
| An approval is refused | Four-eyes or self-approval: approve as a *different* Lead. That's the control working. |
| Numbers differ from screenshots | Time has passed (§10). Correct behaviour. |
| `load_env.ps1` "cannot be loaded because running scripts is disabled" | `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`, once. |
| The server refuses to start: "the connector configuration has errors" | A typo in `config\connectors.yaml` (tool, key, stage, setting). The lines above the message name each one with its fix; `python -m soc_platform config check` lists them all. |
| A connector shows *misconfigured* | Its secret is missing or a setting is invalid - the reason is under the state. Every other tool keeps working. Fix the secret / setting (Configure), then *Preflight*. |
| A proposal is refused with a preflight report | The tool is not ready for a live stage: each failed check says what to fix (permission to grant, URL, proxy, certificate, clock). Fix it and propose again. |
| "another change was approved after this one was proposed" | Two people changed the configuration at once. Propose your change again so it is reviewed against the configuration now in force. |
| Variables "disappear" | `load_env.ps1` was run without the leading dot, or in another window. Each window needs `. .\scripts\load_env.ps1`. |

---

## 15. Quick reference card

```text
START        . .\scripts\load_env.ps1 ; python -m soc_platform init-db ; python -m soc_platform demo ; python -m soc_platform serve
OPEN         http://127.0.0.1:8080   (lena@acme-demo.com, Lead)      second approver: alice@acme-demo.com, Lead
USERS        ann Analyst · pia Analyst + "Phishing only" · ada Admin · max Automation admin · audrey Auditor  (@acme-demo.com)
SWITCH USER  your name (top right) > Sign out ; second person at once: private window
HEALTH       http://127.0.0.1:8080/health
UPLOAD       Phishing > Analyse a message > .eml       new samples: cred_phish_lookalike, html_attachment_phish,
                                                        iso_dropper, malspam_macro, legit_github, legit_internal
PUSH ALERT   POST /api/v1/ingest/alerts  then  Cases > Run incident pipeline
PIPELINES    run automatically inside the server; on demand: Cases / Phishing / Vulnerabilities / Cloud / Intelligence buttons; Integrations > Run now
SEARCH       box at the top of every screen (names, e-mails, hosts, CVEs, case titles)
OWN A CASE   case > Take case ; Cases > Mine / Unassigned ; notes on the case page
NOTIFY       SOC_NOTIFY_WEBHOOKS=teams|https://... (then Integrations > Notifications)
TOKEN        python -m soc_platform token lena@acme-demo.com lead
CONNECT TOOL Integrations > Configure (settings, stage) > Propose ; a Lead approves ; Preflight button checks a tool
CONFIG       python -m soc_platform config check | config export --out f.yaml | preflight --all
NEW TOOL     python -m soc_platform connector new <name> --category edr --tool "Vendor X" ; connector check <name>
LLM?         Reports page callout, or GET /api/v1/llm/status
RESET        stop server; python -m soc_platform reset-demo --yes ; serve
OTHER ORG    python scripts\build_estate_variant.py out\veridian --seed 7  (then §9)
DOCKER       docker compose -f deploy\docker-compose.yml --env-file .env up -d --build
TESTS        python -m pytest soc_platform\tests -q ; python scripts\verify_features.py
```
