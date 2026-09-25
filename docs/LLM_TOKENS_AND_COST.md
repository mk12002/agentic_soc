# LLM tokens and cost

How many tokens each component uses, what that costs, how it grows with volume, and how to size and cap the budget.
All figures below were **measured** with the real model (Azure AI Foundry, `gpt-4.1-mini-2025-04-14`) through the
platform's own LLM call log, on three estates of different size and composition. Re-measure on your own data with
`python scripts/measure_llm_usage.py` (see [Measuring it yourself](#measuring-it-yourself)).

> **Everything works without an LLM.** Every figure, verdict, score and action is computed in code; the model only
> writes narrative. Turning it off costs nothing and changes no number.

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

## 4. Budget, alerts and failure behaviour

| Setting | Default | Effect |
|---|---|---|
| `SOC_LLM_MONTHLY_TOKEN_BUDGET` | 50,000,000 | Hard monthly cap. A finding is raised at **80 %** and at **100 %**. After the cap, every screen, report and answer falls back to deterministic, cited text until the month rolls over. |
| `SOC_LLM_DEPLOYMENT_SMALL` | = large deployment | The model used for routine narrative and planners. |
| `SOC_LLM_EXPLAIN_AUTO_CLOSED` | 0 | 1 = also have the model explain reports that auto-close (not recommended at volume). |
| `SOC_BRIEF_CACHE_SECONDS` | 900 | The longest time an unchanged brief is reused. |
| `SOC_LLM_TIMEOUT_SECONDS` / `SOC_LLM_TIMEOUT_LARGE_SECONDS` | 30 / 120 | Read timeouts: small-tier calls are short; large-tier calls (deep analysis, reports) can produce ~2,000 tokens, about 30 s at ~70 tokens/s. Connect timeout is 10 s. One retry is made on throttling or transient server errors. |
| `SOC_LLM_BREAKER_FAILURES` / `SOC_LLM_BREAKER_SECONDS` | 3 / 60 | After 3 consecutive failures, model calls are skipped for 60 s and screens answer instantly from the deterministic path. |

**Sizing the budget:** take the monthly tokens for your profile from section 3 and add 50 % headroom. The 50 M
default fits a small or mid-size SOC. A large SOC should set roughly 250-300 M. (The previous default of 5 M would
have run out within days even for a small SOC.)

---

## 5. Measuring it yourself

```bash
python scripts/measure_llm_usage.py                                   # built-in estate, configured model
python scripts/build_estate_variant.py out/ --seed 42 --scale 3       # a bigger, different organisation
python scripts/measure_llm_usage.py --estate out/estate.json --out usage.json
```

The script runs every component above once, including a second brief view to show the cache. It then reports
calls, mean and max tokens per component and totals from the platform's call log. In production the same log
(`llm_calls`, retention `SOC_LLM_LOG_RETENTION_DAYS`) holds every call's workflow, model, token counts and status;
`GET /api/v1/llm/budget` shows this month's use against the cap.

## Assumptions

- **Prices:** OpenAI list prices for gpt-4.1-mini, gpt-4.1-nano and gpt-4.1 at the time of writing. Azure OpenAI /
  AI Foundry Global Standard deployments have been priced the same; Data Zone and Regional deployments usually carry
  a premium. Check the Azure pricing page for your region, deployment type and currency before budgeting.
- **Token counts:** measured on the built-in estate and two seeded variants (46, 44 and 40-45 calls per run, all
  on the pinned model). Token counts for your organisation depend mostly on how much evidence your tools return per
  incident, so re-measure once your connectors are live.
- **Daily profiles:** illustrative. Replace them with your own volumes (reported emails, incidents, questions,
  reports) to get your number.
