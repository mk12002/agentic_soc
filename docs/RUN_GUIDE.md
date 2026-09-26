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
python -m soc_platform serve             # leave this window open
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

The optional phishing ML engine (`requirements\phishing.txt`, PyTorch and the ML agents) is **not** needed for the
demo. The platform's own deterministic analyser gives the verdicts shown in the demo.

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
and MFA, and it turns off the dev sign-in you use in the demo.

The other entries in your `.env` (for example `AZURE_OPENAI_*`, `RABBITMQ_*`, `GRAPH_*`) belong to the optional
phishing ML engine. The platform ignores them.

---

## 4. Start the platform

### Window 1 - the server (required)

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

### Window 2 - the scheduler (optional)

The scheduler runs the recurring jobs (§5 lists them) the way production would.

```powershell
cd "D:\Code_stuff\Agentic SOC"; .\.venv\Scripts\Activate.ps1; . .\scripts\load_env.ps1
python -m soc_platform scheduler
```

**Either keep it running for the whole demo, or don't start it.** After it has run once, the console expects a job
at least every 30 minutes. If you stop it, every screen shows a **"Scheduler stopped"** banner after 30 minutes. That
is the monitoring working, but not what you want mid-demo. Without a scheduler, you trigger the same work with
buttons (§6.4).

### Signing in

- **Work email:** any address at the organisation's domain, for example `lena@acme-demo.com`.
- **Role:** Lead, Analyst, Auditor, Automation admin or Admin.

For the four-eyes demo, open a second browser profile (or a private window) and sign in as a *different* person,
for example `alice@acme-demo.com` as Lead. Nobody can approve their own request.

---

## 5. What the sample data contains

After `demo`:

| Where | What you should see |
|---|---|
| **Cases** | 10 cases: 7 phishing, 3 incidents |
| **Approvals** | 34 actions awaiting a decision (incident 15, phishing 16, vulnerability 3) |
| **Vulnerabilities** | 6 open findings; the CVE-2021-44228 (Log4Shell) campaign |
| **Cloud posture** | Misconfigurations routed to their owning teams |
| **Intelligence** | A situation brief, correlated findings, the riskiest users and hosts |
| **Phishing** | The reported credential-phishing campaign (8 recipients, Jane clicked), supplier fraud, CEO fraud, QR phishing, a genuine invoice, marketing spam |
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
(body `{"question": "..."}`), `GET /api/v1/audit/verify`.

---

## 8. With and without the LLM

- **Without** (`SOC_LLM_PROVIDER` unset or `none`): every figure, verdict, story and recommendation is identical.
  Narratives come from the deterministic writer. Screens say *"deterministic"*.
- **With** (your `.env` has the Azure AI Foundry settings): narratives, analyst answers, report text and deep
  analysis are written by gpt-4.1-mini, grounded on the evidence and cited.

**Check which mode you're in:** open **Reports**. It says either *"Narrative is written by the approved LLM
(azure_foundry)"* or *deterministic*. Or call `GET /api/v1/llm/status`.

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

**Stop the server first** (Ctrl+C in its window). Then:

```powershell
Remove-Item .\soc_platform.db -ErrorAction SilentlyContinue       # the default database
Remove-Item .\data\raw, .\data\reports -Recurse -ErrorAction SilentlyContinue
python -m soc_platform init-db; python -m soc_platform demo
```

Only delete these if they hold nothing you want to keep. They're the demo database and its generated files.

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

Open http://127.0.0.1:8080 as before.

**Stop, or wipe everything:**

```powershell
docker compose -f deploy\docker-compose.yml down        # stop (data kept)
docker compose -f deploy\docker-compose.yml down -v     # stop and delete the database volume
```

The scheduler runs continuously in its own container here, so the "Scheduler stopped" banner won't appear. The
phishing ML microservices are a separate profile (`--profile engine`) and are not needed for the demo.

---

## 12. Connecting real tools

After the demo, when the client provides access. Summary here; the full procedure is in
[OPERATIONS.md](OPERATIONS.md).

1. For each tool, create a **read-only** service principal first. Write scopes come later, per action type.
2. Put its settings in `config\connectors.yaml` and its secrets in files. Every secret `X` can come from `X_FILE`,
   for example a vault mount.
3. Set `SOC_CONNECTOR_MODE=live` and restart.
4. **Integrations** → **Test** on each connector. It authenticates and reads one page.
5. Run the scheduler. Freshness is then watched per stream.

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

---

## 14. Troubleshooting

| Symptom | Cause and fix |
|---|---|
| Sign-in does nothing, or "not available" | `SOC_DEV_JWT_SECRET` is missing in this window. Add it to `.env` (§3), run `. .\scripts\load_env.ps1`, restart `serve`. |
| Sign-in fails from another computer | By design, dev sign-in is served only to this machine. For a demo on a big screen, present from this laptop. |
| "Only one usage of each socket address" / port in use | Another server is on 8080. Find it with `netstat -ano \| findstr :8080`, then stop that process: `Stop-Process -Id <PID>`. Or use `$env:SOC_PORT = "8081"`. |
| Screens are empty | `demo` wasn't run on *this* database. Check `SOC_DATABASE_URL`, then run `init-db` and `demo`. |
| Internal senders flagged as external, or look-alikes missed | `SOC_ORG_DOMAINS` isn't set. Set it to the organisation's domain. |
| "deterministic" when you expected the LLM | See §8. |
| "Scheduler stopped" banner | The scheduler ran earlier and has stopped. Start it (§4, window 2), or reset (§10). |
| "database is locked" | Two processes are writing one SQLite file (for example two servers). Stop one. Use PostgreSQL (§11) for more. |
| Upload refused (413) | The file is larger than 30 MB. |
| "rate limit exceeded" (429) while scripting | Default 20 requests/s per client. Slow the script, or set `SOC_RATE_LIMIT_RPS=200` for a local demo. |
| An approval is refused | Four-eyes or self-approval: approve as a *different* Lead. That's the control working. |
| Numbers differ from screenshots | Time has passed (§10). Correct behaviour. |
| `load_env.ps1` "cannot be loaded because running scripts is disabled" | `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`, once. |
| Variables "disappear" | `load_env.ps1` was run without the leading dot, or in another window. Each window needs `. .\scripts\load_env.ps1`. |

---

## 15. Quick reference card

```text
START        . .\scripts\load_env.ps1 ; python -m soc_platform init-db ; python -m soc_platform demo ; python -m soc_platform serve
OPEN         http://127.0.0.1:8080   (lena@acme-demo.com, Lead)      second approver: alice@acme-demo.com, Lead
HEALTH       http://127.0.0.1:8080/health
UPLOAD       Phishing > Analyse a message > .eml       new samples: cred_phish_lookalike, html_attachment_phish,
                                                        iso_dropper, malspam_macro, legit_github, legit_internal
PUSH ALERT   POST /api/v1/ingest/alerts  then  Cases > Run incident pipeline
PIPELINES    Cases / Phishing / Vulnerabilities / Cloud / Intelligence buttons; Integrations > Run now
TOKEN        python -m soc_platform token lena@acme-demo.com lead
LLM?         Reports page callout, or GET /api/v1/llm/status
RESET        stop server; delete soc_platform.db, data\raw, data\reports; init-db; demo
OTHER ORG    python scripts\build_estate_variant.py out\veridian --seed 7  (then §9)
DOCKER       docker compose -f deploy\docker-compose.yml --env-file .env up -d --build
TESTS        python -m pytest soc_platform\tests -q ; python scripts\verify_features.py
```
