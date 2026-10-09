# LLM tokens and cost

How many tokens each component uses, what that costs, how it grows with volume, and how to size and cap the budget.
All figures below were **measured** with the real model (Azure AI Foundry, `gpt-4.1-mini-2025-04-14`) through the
platform's own LLM call log, on three estates of different size and composition. Re-measure on your own data with
`python scripts/measure_llm_usage.py` (see [Measuring it yourself](#measuring-it-yourself)).

> **Everything works without an LLM.** Every figure, verdict, score and action is computed in code; the model only
> writes narrative. Turning it off costs nothing and changes no number.

> **On the client's own LLM platform** the token counts per component stay roughly the same (the prompts are the
> platform's), but other models tokenise differently and are priced differently: re-run `scripts/measure_llm_usage.py`
> against the client's gateway and reprice with its per-model rates. Connecting it:
> [CLIENT_DEPLOYMENT_GUIDE.md](CLIENT_DEPLOYMENT_GUIDE.md) section 5.

---

## 1. Tokens per component (one call)

Built-in estate, as shipped. "In" is the prompt (evidence + instructions, identities pseudonymised); "out" is the
model's answer. Means per call, with the largest call seen.

| Component | Trigger | Tier | Calls per trigger | In (mean / max) | Out (mean / max) |
|---|---|---|---|---|---|
| Incident summary | each incident investigated | large | 1 | 1,198 / 2,092 | 911 / 1,007 |
| Phishing explanation | each reported email **not** auto-closed | small | 1 | 504 / 803 | 682 / 1,004 |
| Correlated-finding narrative | each finding that is new or whose evidence / severity changed | small | 1 | 411 / 905 | 430 / 622 |
| Situation brief | when its facts change (cached otherwise) | large | 1 | 2,006 | 598 |
| Analyst question | each question asked | small + large | 2 (planner + answer) | 344 + 891 | 42 + 228 |
| Deep analysis | on request, per attack story (cached per evidence fingerprint) | large | 1 | 3,008 | 1,819 |
| Report section | each section of a generated report | large | 1 per section | 383 / 515 | 308 / 388 |
| Report plan | each report described in words | small | 1 | 359 | 141 |

**What drives the size of a call.** The prompt grows with the evidence behind the item. For example, an incident
touching more tools has more evidence rows, and a larger phishing campaign adds recipients. But each evidence item is
bounded (long values are truncated) and the model only receives evidence about that one item, so per-call size stays
in a narrow band. The output is bounded by the instruction (for example "3-5 sentences") and by the schema.

### The same components on different estates

| Component (mean in / out) | Built-in (3 incidents, 7 reports) | Variant seed 23 (+14 staff, +11 laptops) | Large variant (+30 staff, +24 laptops, +10 campaign recipients) |
|---|---|---|---|
| Incident summary | 1,198 / 911 | 1,164 / 841 | 1,177 / 849 |
| Phishing explanation | 504 / 682 | 350 / 482 | 466 / 641 |
| Finding narrative | 411 / 430 | 433 / 421 | 410 / 389 |
| Brief | 2,006 / 598 | 1,993 / 709 | 1,907 / 797 |
| Deep analysis | 3,008 / 1,819 | 2,586 / 1,713 | 2,598 / 1,998 |

**Tokens per item barely move as the organisation grows** (users, machines, campaign size). What grows cost is the
**number of items processed**: incidents, reported emails, changed findings, questions, reports.

---

## 2. Unit costs

Prices used, per million tokens (list prices at the time of writing; see [assumptions](#assumptions)):

| Model | Input | Output |
|---|---|---|
| gpt-4.1-mini (default, measured) | $0.40 | $1.60 |
| gpt-4.1-nano (cheap small tier) | $0.10 | $0.40 |
| gpt-4.1 (premium large tier) | $2.00 | $8.00 |

Cost of each unit of work at gpt-4.1-mini:

| Unit | Tokens in | Tokens out | Cost |
|---|---|---|---|
| Incident summary | 1,198 | 911 | $0.0019 |
| Phishing explanation (report not auto-closed) | 504 | 682 | $0.0013 |
| Correlated-finding narrative | 411 | 430 | $0.0009 |
| Situation brief (regenerated) | 2,006 | 598 | $0.0018 |
| Analyst question (planner + answer) | 1,235 | 270 | $0.0009 |
| Deep analysis | 3,008 | 1,819 | $0.0041 |
| Report section | 383 | 308 | $0.0007 |
| Report planned from a request | 359 | 141 | $0.0004 |

For example, a 6-section board report costs about **$0.004**, and 1,000 analyst questions about **$0.93**.
**Output tokens are about 45 % of the tokens but about 75 % of the cost** (output is priced 4× input).

---

## 3. What it costs at volume

The profiles below are daily volumes. They assume 70 % of reported email is clear-benign or bulk and auto-closes,
which is typical for user-reported mail.

| Profile (per day) | Reported emails | Incidents | Changed findings | Brief regenerations | Questions | Deep analyses | Report sections |
|---|---|---|---|---|---|---|---|
| Small SOC | 30 | 15 | 25 | 30 | 40 | 3 | 12 |
| Mid-size SOC | 300 | 80 | 150 | 60 | 250 | 20 | 60 |
| Large SOC | 3,000 | 500 | 800 | 96 | 1,500 | 100 | 240 |

Monthly (30 days):

| Profile | Tokens / month | gpt-4.1-mini (as shipped) | + gpt-4.1-nano small tier | gpt-4.1 large + nano small | Before the cost optimisations below |
|---|---|---|---|---|---|
| Small SOC | 6.7 M | **$5** | $4 | $21 | $11 (14.5 M tokens) |
| Mid-size SOC | 32 M | **$26** | $20 | $94 | $43 (54 M tokens) |
| Large SOC | 179 M | **$148** | $107 | $478 | $245 (276 M tokens) |

**How it changes with bulk usage:**

- **Linear in work items, not in organisation size.** Doubling incidents or questions doubles their line. Doubling
  users or machines changes little unless it creates more incidents or reports.
- **Sub-linear parts:**
  - The brief is cached while its facts are unchanged, so it costs at most one call per 15 minutes, however many
    people open the Intelligence screen.
  - Deep analysis is cached per attack story, so re-opening it is free.
  - Finding narratives are rewritten only when a finding's evidence or severity changes, not on every
    10-minute refresh.
- **Auto-closed reports cost nothing:** clear-benign and bulk reports get a deterministic, cited explanation.
  At 70 % auto-close, phishing explanation cost falls by 70 %.
- **The cheapest lever at scale is the small tier.** Point `SOC_LLM_DEPLOYMENT_SMALL` at a cheaper model (for
  example gpt-4.1-nano). Phishing explanations, finding narratives and planners then move to it, with no code
  change; the large SOC's bill drops by about 28 %.
- **Batch pricing.** Azure and OpenAI batch APIs are about 50 % cheaper for work that can wait (nightly
  reports, bulk re-narration). The platform does not use batch mode today; it is a possible further saving for
  scheduled reports.
- **Prompt caching.** Providers discount repeated prompt prefixes of 1,024+ tokens. Only the largest calls (brief,
  deep analysis, big incidents) reach that size, so expect a small saving, not a large one.

---

## 4. Budgets and limits - set by administrators in the console

Everything below is set on the **AI usage** screen (*Govern -> AI usage*) by an administrator (`manage_access`; step-up
MFA in production). A change is a new version - who, when, why - kept in the history and the audit log, and in force
for the next model call; no restart. Anyone with `read_audit` (analysts, leads, auditors) sees the screen read-only.

| Limit | Default | Effect |
|---|---|---|
| Monthly tokens | `SOC_LLM_MONTHLY_TOKEN_BUDGET` (50,000,000) | Hard cap for the whole platform. A finding is raised at the warning level (80 %) and at 100 %; after the cap, model text falls back to the platform's own cited text until the month rolls over. |
| Daily tokens | a tenth of the month | No single day may use more, so a runaway script or a flood of incidents cannot spend the month in an afternoon. A finding is raised while today's budget is used up; it clears itself the next day. |
| Per person, per hour / per day | 100,000 / 400,000 | For what a person asks for: analyst questions, deep analysis, reports they build. An override per role (the most generous of a person's roles applies) and per person (wins over the role). **0 = no model text for that person.** Scheduled work (incident and phishing explanations, finding narratives, the brief, scheduled reports) counts only against the platform caps, so one person can never starve it. |
| Per feature: tier | the tier the code asks for (section 1) | `small` or `large` for that feature alone. |
| Per feature: max answer | small 1,500 / large 3,000 tokens | The most one answer may contain, sent to the provider (`max_tokens`; `SOC_LLM_MAX_TOKENS_FIELD=max_completion_tokens` for gateways or models that need that name). The largest answer measured was about 2,000 tokens (deep analysis), so the defaults never cut a normal answer; they stop a misbehaving model from writing - and billing - pages. |
| Per feature: on / off | on | Off = that feature always uses the platform's own text. |
| Prices per tier | gpt-4.1-mini list prices for both | Used only to show cost and what a tier change would save. |

**Over any limit nothing fails.** The call is not sent; the caller uses its deterministic, cited fallback (the same
figures and verdicts - only the wording differs); the refusal is logged with its reason (`budget_exceeded`,
`daily_budget_exceeded`, `user_limit`, `disabled_by_policy`). A person whose request was refused sees *"Written by the
platform without the model: your hourly AI limit (100,000 tokens) is reached."* on the answer, report or analysis.

| Other setting (environment) | Default | Effect |
|---|---|---|
| `SOC_LLM_DEPLOYMENT_SMALL` | = large deployment | The model behind the small tier. |
| `SOC_LLM_EXPLAIN_AUTO_CLOSED` | 0 | 1 = also have the model explain reports that auto-close (not recommended at volume). |
| `SOC_BRIEF_CACHE_SECONDS` | 900 | The longest time an unchanged brief is reused. |
| `SOC_LLM_TIMEOUT_SECONDS` / `SOC_LLM_TIMEOUT_LARGE_SECONDS` | 30 / 120 | Read timeouts: small-tier calls are short; large-tier calls (deep analysis, reports) can produce ~2,000 tokens, about 30 s at ~70 tokens/s. Connect timeout is 10 s. One retry is made on throttling or transient server errors. |
| `SOC_LLM_BREAKER_FAILURES` / `SOC_LLM_BREAKER_SECONDS` | 3 / 60 | After 3 consecutive failures, model calls are skipped for 60 s and screens answer instantly from the deterministic path. |
| `SOC_LLM_CONCURRENCY` | 4 | Narratives, report sections and the case explanations of a job run are sent in parallel, up to this many at once. It changes speed, not cost. |

**Sizing the monthly budget:** take the monthly tokens for your profile from section 3 and add 50 % headroom. The 50 M
default fits a small or mid-size SOC; a large SOC should set roughly 250-300 M. Keep the daily cap at 2-4 times an
average day (the default, a tenth of the month, is about three times an average day).

**Sizing per-person limits:** an analyst question costs about 1,500 tokens, a deep analysis about 5,000, a six-section
report about 4,000. The default 100,000 an hour is about 60 questions or 20 deep analyses - generous for a person,
small against a runaway script. Lower it for roles that rarely need the model (auditors); set 0 for accounts that
must not use it.

---

## 4b. Choosing the small or the large model for each feature

The **By feature** table on the AI usage screen shows, per feature, over the last 30 days: calls, mean tokens in and
out, cost on its tier and what it would cost on the other, how often an answer the model gave was **usable** (it
parsed; calls the endpoint failed to answer - down, slow, circuit open - are shown separately as *not answered* and
kept out of the advice, because an outage says nothing about the tier), how many of its **statements the evidence check removed** (the grounding guardrail drops any
statement that cites no evidence or states a figure its evidence does not contain), and the 95th-percentile response
time. From those figures - computed in code, never by a model - it advises:

| Advice | When | What to do |
|---|---|---|
| **try small** | on large; at least 20 calls; at least 98 % usable; at most 5 % of statements removed; answers average 600 tokens or less | Switch the feature to small, then compare the same row a week later. If usable or removed statements get worse, switch back. |
| **use large** | on small; more than 5 % of answers unusable, or more than 15 % of statements removed | Switch to large: the small model is writing claims the evidence does not support, so readers get thinner text. |
| **keep** | anything else | Quality and cost are in balance. |
| **not enough data** | fewer than 20 calls in the period | Keep the code's default. |

How to think about it:

- **The large tier earns its price where the model must reason across a lot of evidence**: incident summaries (many
  tools), deep analysis of an attack story, the situation brief, the analyst's answer, report sections. Errors there
  are costly, and the guardrail removing statements means a thinner explanation for the person who needs it most.
- **The small tier is enough for short, single-source, templated text**: why one e-mail got its verdict, one
  correlated finding, choosing tools for a question (the planner), planning a report, short report commentary.
- **The figures that matter are the guardrail's removed-statement rate and the usable rate**, not the tone of the
  text: they say directly whether the cheaper model keeps to the evidence. Cost per call is in the same row.
- **Change one feature at a time**, for a week, and compare - every call is logged with its tier, so the table shows
  both periods.
- Nothing numeric changes either way: figures, verdicts, scores and actions are computed in code; the tier changes
  only the wording quality and the cost.

---

## 5. Measuring it yourself

```bash
python scripts/measure_llm_usage.py                                   # built-in estate, configured model
python scripts/build_estate_variant.py out/ --seed 42 --scale 3       # a bigger, different organisation
python scripts/measure_llm_usage.py --estate out/estate.json --out usage.json
```

The script runs every component above once, including a second brief view to show the cache. It then reports
calls, mean and max tokens per component and totals from the platform's call log. In production the same log
(`llm_calls`, retention `SOC_LLM_LOG_RETENTION_DAYS`) holds every call's workflow, tier, the person who asked (or
none for scheduled work), model, token counts, status, duration and how many statements the evidence check kept and
removed; the AI usage screen (`GET /api/v1/admin/llm/usage`) summarises it per feature and per person; `GET /api/v1/llm/budget` shows this month's use against the cap, and `GET /api/v1/llm/status` the median
and 95th-percentile response time per workflow over the last 30 days.

## Assumptions

- **Prices:** OpenAI list prices for gpt-4.1-mini, gpt-4.1-nano and gpt-4.1 at the time of writing. Azure OpenAI /
  AI Foundry Global Standard deployments have been priced the same; Data Zone and Regional deployments usually carry
  a premium. Check the Azure pricing page for your region, deployment type and currency before budgeting.
- **Token counts:** measured on the built-in estate and two seeded variants (46, 44 and 40-45 calls per run, all
  on the pinned model). Token counts for your organisation depend mostly on how much evidence your tools return per
  incident, so re-measure once your connectors are live.
- **Daily profiles:** illustrative. Replace them with your own volumes (reported emails, incidents, questions,
  reports) to get your number.
