"""AI usage policy: budgets, per-user limits and per-feature model choice, decided by administrators (NFR-11).

The administrator sets, in the console (*AI usage* screen), without a restart:

* **monthly_tokens** - the hard cap for the whole platform (the old ``SOC_LLM_MONTHLY_TOKEN_BUDGET`` is the default)
* **daily_tokens** - no single day may use more (default: a tenth of the month), so a burst - a runaway script, a
  flood of incidents - cannot spend the month in an afternoon
* **per-user limits** (tokens per hour and per day) for what a person asks for: analyst questions, deep analysis,
  reports. A default for everyone, an override per role and per user; ``0`` means that user gets no model text
  (answers are written by the platform from the same evidence). Scheduled work (incident and phishing explanations,
  finding narratives, the brief, scheduled reports) counts only against the platform caps.
* **per-feature settings** - which **model** each feature uses (by name, from the model list: by default
  ``gpt-4.1-nano``, ``gpt-4.1-mini`` and ``gpt-4.1``; ``SOC_LLM_MODELS`` replaces the list), the most it may write
  (``max_output_tokens``), or ``enabled: false`` to switch the model off for that feature alone
* **prices** per model, so the usage screen can show cost and what another model would cost

The model list comes from the deployment's settings, not the console: a model can only be chosen where it is deployed.
``SOC_LLM_MODELS`` is a comma list of names, each optionally ``name=deployment`` when the deployment (Azure) or the
gateway's model id differs from the name shown. A deployment named in ``SOC_LLM_DEPLOYMENT`` / ``..._SMALL`` that is not
on the list is added to it, and those two remain the defaults a feature uses until the administrator picks a model.
Each model has a size (``small`` / ``large``) that sets its timeout and default answer cap.

Every change is a new version (who, when, why), audited; the history is kept. Over any limit the platform never
fails: the caller's deterministic, cited fallback is used and the refusal is logged with its reason.

``usage_report`` turns the call log into what an administrator needs to choose a model per feature: calls, tokens,
cost, how often the answer was usable (parsed, and claims kept by the evidence guardrail), speed - and a
recommendation computed from those figures (never by a model).
"""

from __future__ import annotations

import copy
import math
import os
import re
from datetime import timedelta
from typing import Any

from sqlalchemy import JSON, Integer, String, func, select
from sqlalchemy.orm import Mapped, Session, mapped_column

from soc_platform.core.db import Base, BoundedText, UTCDateTime
from soc_platform.core.models import LLMCall, utcnow

TIERS = ("small", "large")           # model sizes: the timeout and the default answer cap
# The models offered per feature when SOC_LLM_MODELS is not set: name, size, list price in USD per million tokens
# (input, output) - editable on the AI usage screen.
DEFAULT_MODELS = (("gpt-4.1-nano", "small", 0.10, 0.40), ("gpt-4.1-mini", "small", 0.40, 1.60),
                  ("gpt-4.1", "large", 2.00, 8.00))
ANTHROPIC_MODELS = (("claude-haiku-4-5", "small"), ("claude-opus-5", "large"))   # the Anthropic provider's defaults
KNOWN_PRICES = {name: (inp, out) for name, _, inp, out in DEFAULT_MODELS}
COMPUTED = ("models", "default_models")   # derived from the settings on every read; never stored
ROLES = ("analyst", "lead", "auditor", "automation_admin", "admin")

# Every feature that calls the model: the tier its code asks for, and what it does (for the usage screen).
KNOWN_WORKFLOWS: dict[str, tuple[str, str, str]] = {
    "incident.summary": ("large", "scheduled", "Incident summary: reasons over evidence from several tools"),
    "phishing.explanation": ("small", "scheduled", "Why a reported e-mail got its verdict"),
    "intelligence.narrate": ("small", "scheduled", "Correlated-finding narrative"),
    "intelligence.brief": ("large", "scheduled", "Situation brief (shared, cached)"),
    "intelligence.plan": ("small", "person", "Analyst assistant: chooses which read-only tools answer a question"),
    "intelligence.answer": ("large", "person", "Analyst assistant: the answer"),
    "intelligence.deep_analysis": ("large", "person", "Deep analysis of an attack story"),
    "report.plan": ("small", "person", "Plans a report described in words"),
    "tuning.draft": ("small", "person", "Turns a lead's tuning request in words into a draft rule to check"),
    "report.section.*": ("large", "person", "One section of a generated report"),
    "report.daily_exposure": ("small", "scheduled", "Daily exposure report commentary"),
    "report.weekly_vm": ("small", "scheduled", "Weekly vulnerability report commentary"),
    "llm.model_check": ("small", "person", "An administrator's check that each listed model answers"),
}

MIN_CALLS_FOR_ADVICE = 20
REFUSED = ("budget_exceeded", "daily_budget_exceeded", "user_limit", "disabled_by_policy")


class LLMUsagePolicy(Base):
    """Versioned AI usage policy; the newest row is in force."""

    __tablename__ = "llm_usage_policies"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    document: Mapped[dict[str, Any]] = mapped_column(JSON)
    set_by: Mapped[str] = mapped_column(String(256))
    note: Mapped[str] = mapped_column(BoundedText(2000), default="")
    created_at: Mapped[Any] = mapped_column(UTCDateTime(), default=utcnow)


def _size(name: str) -> str:
    return "small" if re.search(r"mini|nano|haiku|small|lite|flash", name, re.IGNORECASE) else "large"


def models(settings: Any) -> list[dict[str, str]]:
    """The models a feature may use, in the order offered: ``{name, deployment, size}``."""
    raw = (os.environ.get("SOC_LLM_MODELS") or "").strip()
    out: list[dict[str, str]] = []
    if raw:
        for part in raw.split(","):
            name, _, dep = part.strip().partition("=")
            if name.strip():
                out.append({"name": name.strip()[:64], "deployment": (dep.strip() or name.strip())[:128],
                            "size": _size(name)})
    elif (getattr(settings, "llm_provider", "") or "").lower() == "anthropic":
        out = [{"name": n, "deployment": n, "size": s} for n, s in ANTHROPIC_MODELS]
    else:
        out = [{"name": n, "deployment": n, "size": s} for n, s, _, _ in DEFAULT_MODELS]
    for dep in (os.environ.get("SOC_LLM_DEPLOYMENT_SMALL"), getattr(settings, "llm_deployment", None)):
        if dep and not any(dep in (m["name"], m["deployment"]) for m in out):
            out.append({"name": dep[:64], "deployment": dep[:128], "size": _size(dep)})
    seen: set[str] = set()
    return [m for m in out if not (m["name"] in seen or seen.add(m["name"]))]


def default_models(settings: Any, cat: list[dict[str, str]]) -> dict[str, str]:
    """The model each size of work uses until the administrator chooses: the configured deployments (one deployment
    serves both, as before), else gpt-4.1-mini for routine narrative and gpt-4.1 for summaries and reports."""
    def find(dep: str | None) -> str | None:
        return next((m["name"] for m in cat if dep and dep in (m["name"], m["deployment"])), None)

    big, small_dep = getattr(settings, "llm_deployment", None), os.environ.get("SOC_LLM_DEPLOYMENT_SMALL")
    names = [m["name"] for m in cat]
    large = (find(big) or ("gpt-4.1" if "gpt-4.1" in names else None)
             or next((m["name"] for m in reversed(cat) if m["size"] == "large"), names[-1] if names else ""))
    small = (find(small_dep) or find(big) or ("gpt-4.1-mini" if "gpt-4.1-mini" in names else None)
             or next((m["name"] for m in cat if m["size"] == "small"), names[0] if names else ""))
    return {"small": small, "large": large}


def defaults(settings: Any) -> dict[str, Any]:
    monthly = int(settings.llm_monthly_token_budget or 0)
    cat = models(settings)
    return {
        "monthly_tokens": monthly,
        "daily_tokens": monthly // 10 if monthly else 0,
        "alert_at": 0.8,
        "user_default": {"hourly_tokens": 100_000, "daily_tokens": 400_000},
        "roles": {},
        "users": {},
        "workflows": {},
        "max_output_tokens": {"small": 1_500, "large": 3_000},
        "prices": {m["name"]: {"input": KNOWN_PRICES.get(m["name"], (0.0, 0.0))[0],
                               "output": KNOWN_PRICES.get(m["name"], (0.0, 0.0))[1]} for m in cat},
        "models": cat,
        "default_models": default_models(settings, cat),
    }


def _nonneg_int(v: Any) -> bool:
    return isinstance(v, int) and not isinstance(v, bool) and 0 <= v <= 10**15


def _number(v: Any) -> bool:
    """A real, finite number (JSON lets NaN and Infinity through; neither is a budget or a price)."""
    return isinstance(v, (int, float)) and not isinstance(v, bool) and math.isfinite(v)


def validate(doc: Any, model_names: list[str] | None = None) -> list[str]:
    """Problems with a policy document, each saying what to fix (empty = valid). ``model_names``: the models that may
    be chosen (the deployment's list); None accepts any name."""
    if not isinstance(doc, dict):
        return ["the policy must be an object"]
    out: list[str] = []
    allowed = {"monthly_tokens", "daily_tokens", "alert_at", "user_default", "roles", "users", "workflows",
               "max_output_tokens", "prices", *COMPUTED}
    names = list(model_names) if model_names is not None else None

    def known(m: Any) -> bool:
        return isinstance(m, str) and 0 < len(m) <= 64 and (names is None or m in names)
    out += [f"unknown setting '{k}'" for k in doc if k not in allowed]
    for k in ("monthly_tokens", "daily_tokens"):
        if k in doc and not _nonneg_int(doc[k]):
            out.append(f"{k} must be a whole number of tokens, 0 or more (0 = no cap)")
    if (_nonneg_int(doc.get("monthly_tokens")) and _nonneg_int(doc.get("daily_tokens")) and doc["monthly_tokens"]
            and doc["daily_tokens"] > doc["monthly_tokens"]):
        out.append("daily_tokens cannot be more than monthly_tokens")
    if "alert_at" in doc and not (_number(doc["alert_at"]) and 0 < doc["alert_at"] <= 1):
        out.append("alert_at is a fraction between 0 and 1 (0.8 = warn at 80 %)")

    def limits(where: str, v: Any) -> None:
        if not isinstance(v, dict):
            out.append(f"{where}: expected hourly_tokens / daily_tokens")
            return
        for k, x in v.items():
            if k not in ("hourly_tokens", "daily_tokens"):
                out.append(f"{where}.{k}: unknown limit (hourly_tokens or daily_tokens)")
            elif not _nonneg_int(x):
                out.append(f"{where}.{k} must be a whole number, 0 or more (0 = no model text for them)")

    if "user_default" in doc:
        limits("user_default", doc["user_default"])
    for k in ("roles", "users", "workflows", "max_output_tokens", "prices"):
        if k in doc and not isinstance(doc[k], dict):
            out.append(f"{k} must be an object (name -> settings)")
    maps = {k: doc[k] if isinstance(doc.get(k), dict) else {} for k in ("roles", "users", "workflows",
                                                                         "max_output_tokens", "prices")}
    for r, v in maps["roles"].items():
        if r not in ROLES:
            out.append(f"roles.{r}: unknown role ({', '.join(ROLES)})")
        limits(f"roles.{r}", v)
    for u, v in maps["users"].items():
        if "@" not in str(u) and not str(u).startswith(("cli:", "svc")):
            out.append(f"users.{u}: expected the person's sign-in name (e-mail)")
        limits(f"users.{u}", v)
    for wf, rule in maps["workflows"].items():
        if wf not in KNOWN_WORKFLOWS:
            out.append(f"workflows.{wf}: unknown feature ({', '.join(sorted(KNOWN_WORKFLOWS))})")
            continue
        if not isinstance(rule, dict):
            out.append(f"workflows.{wf}: expected model / max_output_tokens / enabled")
            continue
        for k, x in rule.items():
            if k == "model" and not known(x):
                out.append(f"workflows.{wf}.model must be one of the deployed models: {', '.join(names or [])}")
            elif k == "tier" and x not in TIERS:
                out.append(f"workflows.{wf}.tier must be small or large")
            elif k == "enabled" and not isinstance(x, bool):
                out.append(f"workflows.{wf}.enabled must be true or false")
            elif k == "max_output_tokens" and not (_nonneg_int(x) and 200 <= x <= 16_000):
                out.append(f"workflows.{wf}.max_output_tokens must be between 200 and 16000")
            elif k not in ("model", "tier", "enabled", "max_output_tokens"):
                out.append(f"workflows.{wf}.{k}: unknown (model, max_output_tokens, enabled)")
    for t, x in maps["max_output_tokens"].items():
        if t not in TIERS or not (_nonneg_int(x) and 200 <= x <= 16_000):
            out.append(f"max_output_tokens.{t}: a tier (small / large) and a number between 200 and 16000")
    for t, p in maps["prices"].items():
        if not known(t) or not isinstance(p, dict) or not all(
                _number(p.get(k)) and 0 <= p.get(k) <= 10_000 for k in ("input", "output")):
            out.append(f"prices.{t}: a deployed model with input and output prices per million tokens, 0 or more")
    return out


def _upgrade(doc: dict[str, Any], base: dict[str, Any]) -> dict[str, Any]:
    """A version saved before models had names: a feature's tier becomes that size's default model; prices kept
    per tier are dropped (the models' prices apply)."""
    names = {m["name"] for m in base["models"]}
    for rule in (doc.get("workflows") or {}).values():
        if isinstance(rule, dict) and "tier" in rule and "model" not in rule:
            rule["model"] = base["default_models"].get(rule.pop("tier"), base["default_models"]["large"])
    if isinstance(doc.get("prices"), dict):
        doc["prices"] = {**base["prices"], **{k: v for k, v in doc["prices"].items() if k in names}}
    return doc


class UsagePolicyStore:
    def __init__(self, session: Session, settings: Any) -> None:
        self.s, self.settings = session, settings

    def active_row(self) -> LLMUsagePolicy | None:
        return self.s.execute(select(LLMUsagePolicy).order_by(LLMUsagePolicy.id.desc()).limit(1)).scalars().first()

    def active(self) -> dict[str, Any]:
        """The policy in force: the defaults with the newest saved version on top (the model list and the default
        models always come from the settings)."""
        base = defaults(self.settings)
        doc = copy.deepcopy(base)
        row = self.active_row()
        if row:
            for k, v in _upgrade(copy.deepcopy(row.document or {}), base).items():
                if k not in COMPUTED:
                    doc[k] = v
        return doc

    def save(self, doc: dict[str, Any], by: Any, note: str = "") -> LLMUsagePolicy:
        from soc_platform.core.audit import AuditLog
        from soc_platform.core.auth import Perm

        if by.is_service or by.is_agent or not by.can(Perm.MANAGE_ACCESS):
            raise PermissionError("an administrator (manage_access) sets AI usage limits")
        doc = {k: v for k, v in (doc or {}).items() if k not in COMPUTED} if isinstance(doc, dict) else doc
        problems = validate(doc, [m["name"] for m in models(self.settings)])
        if problems:
            raise ValueError("; ".join(problems))
        before = self.active()
        row = LLMUsagePolicy(document=copy.deepcopy(doc), set_by=by.id, note=(note or "")[:2000])
        self.s.add(row)
        self.s.flush()
        after = self.active()
        changes = {k: {"from": before.get(k), "to": after.get(k)} for k in sorted(set(before) | set(after))
                   if before.get(k) != after.get(k)}
        AuditLog(self.s).append(actor_type=by.actor_type, actor_id=by.id, event_type="llm_policy.changed",
                               subject_type="llm_policy", subject_id=str(row.id), payload={"note": note[:500],
                                                                                           "changes": changes})
        return row

    def history(self, limit: int = 30) -> list[dict[str, Any]]:
        return [{"id": r.id, "set_by": r.set_by, "note": r.note, "created_at": r.created_at.isoformat(),
                 "document": r.document}
                for r in self.s.execute(select(LLMUsagePolicy).order_by(LLMUsagePolicy.id.desc()).limit(limit)).scalars()]


# ---------------------------------------------------------------------------------------------- applying it


def workflow_key(workflow: str) -> str:
    if workflow in KNOWN_WORKFLOWS:
        return workflow
    head = workflow.rsplit(".", 1)[0] + ".*"
    return head if head in KNOWN_WORKFLOWS else workflow


def rule_for(policy: dict[str, Any], workflow: str, asked_tier: str) -> dict[str, Any]:
    """Model, size, output cap and on/off for one call. A feature without a chosen model (or with one no longer
    deployed) uses the default model for the size its code asks for."""
    r = (policy.get("workflows") or {}).get(workflow_key(workflow)) or {}
    cat = {m["name"]: m for m in policy.get("models") or []}
    name = r.get("model")
    if name not in cat:
        tier = r.get("tier") or asked_tier
        name = (policy.get("default_models") or {}).get(tier if tier in TIERS else "large")
    m = cat.get(name) or {"name": name or "", "deployment": None,
                          "size": r.get("tier") if r.get("tier") in TIERS else asked_tier if asked_tier in TIERS else "large"}
    # A model chosen for the feature brings its size's cap. Without a choice the default model serves the size of work
    # the code asks for, and the cap follows that work: one small deployment serving both sizes (the usual demo and
    # many gateways) otherwise capped a deep analysis at the small answer size and cut its JSON off mid-sentence.
    caps = policy.get("max_output_tokens") or {}
    work = r.get("tier") if r.get("tier") in TIERS else asked_tier if asked_tier in TIERS else "large"
    cap = r.get("max_output_tokens") or caps.get(m["size"] if r.get("model") in cat else work)
    return {"model": m["name"], "deployment": m["deployment"], "tier": m["size"], "max_output_tokens": cap,
            "enabled": r.get("enabled", True)}


def limits_for(policy: dict[str, Any], user_id: str, roles: list[str]) -> dict[str, int]:
    """A person's limits: their own override, else the most generous of their roles' overrides, else the default."""
    if user_id in (policy.get("users") or {}):
        base = {**policy.get("user_default", {}), **policy["users"][user_id]}
        return {k: int(base.get(k, 0)) for k in ("hourly_tokens", "daily_tokens")}
    role_limits = [policy["roles"][r] for r in roles if r in (policy.get("roles") or {})]
    out = dict(policy.get("user_default") or {})
    if role_limits:
        for k in ("hourly_tokens", "daily_tokens"):
            vals = [rl[k] for rl in role_limits if k in rl]
            if vals:
                out[k] = max(vals)
    return {k: int(out.get(k, 0)) for k in ("hourly_tokens", "daily_tokens")}


def tokens_since(session: Session, since: Any, actor: str | None = None) -> int:
    q = select(func.coalesce(func.sum(LLMCall.prompt_tokens + LLMCall.completion_tokens), 0)).where(LLMCall.ts >= since)
    if actor is not None:
        q = q.where(LLMCall.actor == actor)
    return int(session.execute(q).scalar() or 0)


def day_start(now: Any) -> Any:
    return now.replace(hour=0, minute=0, second=0, microsecond=0)


# ---------------------------------------------------------------------------------------------- the usage screen


def _cost(policy: dict[str, Any], model: str, tin: int, tout: int) -> float:
    p = (policy.get("prices") or {}).get(model) or {"input": 0, "output": 0}
    return (tin * float(p["input"]) + tout * float(p["output"])) / 1_000_000


def _ladder(policy: dict[str, Any]) -> list[str]:
    """The models from least to most capable: by size, then by output price (dearer = more capable)."""
    prices = policy.get("prices") or {}
    return [m["name"] for m in sorted(policy.get("models") or [], key=lambda m: (
        m["size"] != "small", float((prices.get(m["name"]) or {}).get("output") or 0)))]


def _advice(model: str, ladder: list[str], n: int, fallback: float, dropped: float | None,
            mean_out: float) -> tuple[str, str, str | None]:
    """A model recommendation from measured figures only: (advice, why, the model it points to). The guardrail's
    dropped-claim rate is the quality signal: a model that writes statements the evidence does not support loses
    them, and the reader gets less."""
    i = ladder.index(model) if model in ladder else -1
    smaller = ladder[i - 1] if i > 0 else None
    bigger = ladder[i + 1] if 0 <= i < len(ladder) - 1 else None
    if n < MIN_CALLS_FOR_ADVICE:
        return "not enough data", f"fewer than {MIN_CALLS_FOR_ADVICE} calls in this period - keep the default", None
    d = dropped if dropped is not None else 0.0
    if smaller and fallback <= 0.02 and d <= 0.05 and mean_out <= 600:
        return f"try {smaller}", (f"short answers that pass the evidence check: {smaller} is likely enough - switch, "
                                  "then compare this table after a week"), smaller
    if bigger and (fallback > 0.05 or d > 0.15):
        return f"use {bigger}", (f"{round(100 * max(fallback, d))} % of answers fail or lose statements to the "
                                 f"evidence check on {model}"), bigger
    return "keep", f"quality and cost are in balance on {model}", None


def usage_report(session: Session, policy: dict[str, Any], *, days: int = 30) -> dict[str, Any]:
    now = utcnow()
    since = now - timedelta(days=days)
    rows = session.execute(select(LLMCall.workflow, LLMCall.tier, LLMCall.status, LLMCall.prompt_tokens,
                                  LLMCall.completion_tokens, LLMCall.latency_ms, LLMCall.claims_kept,
                                  LLMCall.claims_dropped, LLMCall.actor, LLMCall.ts, LLMCall.requested_model)
                           .where(LLMCall.ts >= since)).all()
    by_size = policy.get("default_models") or {}
    ladder = _ladder(policy)
    per: dict[str, dict[str, Any]] = {}
    users: dict[str, dict[str, int]] = {}
    hour_ago, today = now - timedelta(hours=1), day_start(now)
    for wf, tier, status, pt, ct, ms, kept, dropped, actor, ts, chosen in rows:
        a = per.setdefault(workflow_key(wf), {"calls": 0, "answered": 0, "refused": 0, "failed": 0, "unparseable": 0,
                                              "tiers": {}, "lat": [], "kept": 0, "dropped": 0})
        if status in REFUSED:
            a["refused"] += 1
            continue
        a["calls"] += 1
        a["answered"] += status in ("ok", "model_version_mismatch")
        a["unparseable"] += status == "unparseable"
        # the endpoint down or slow is availability, not the model tier's quality: counted, kept out of the advice
        a["failed"] += status in ("error", "circuit_open")
        # calls logged before models had names count against their size's default model
        tt = a["tiers"].setdefault(chosen or by_size.get(tier or "large") or tier or "large", [0, 0])
        tt[0] += int(pt or 0)
        tt[1] += int(ct or 0)
        if ms is not None and status == "ok":
            a["lat"].append(int(ms))
        if kept is not None:
            a["kept"] += int(kept)
            a["dropped"] += int(dropped or 0)
        if actor:
            u = users.setdefault(actor, {"period": 0, "today": 0, "hour": 0, "calls": 0})
            tok = int(pt or 0) + int(ct or 0)
            ts = ts if ts.tzinfo else ts.replace(tzinfo=now.tzinfo)
            u["period"] += tok
            u["calls"] += 1
            u["today"] += tok if ts >= today else 0
            u["hour"] += tok if ts >= hour_ago else 0
    features = []
    for key in sorted(set(KNOWN_WORKFLOWS) | set(per)):
        default_tier, who, what = KNOWN_WORKFLOWS.get(key, ("large", "scheduled", key))
        rule = rule_for(policy, key, default_tier)
        default_model = rule_for({**policy, "workflows": {}}, key, default_tier)["model"]
        a = per.get(key) or {"calls": 0, "answered": 0, "refused": 0, "failed": 0, "unparseable": 0, "tiers": {},
                             "lat": [], "kept": 0, "dropped": 0}
        n = a["calls"]
        tin = sum(v[0] for v in a["tiers"].values())
        tout = sum(v[1] for v in a["tiers"].values())
        replied = a["answered"] + a["unparseable"]           # calls the model actually answered
        fallback = a["unparseable"] / replied if replied else 0.0
        claims = a["kept"] + a["dropped"]
        dropped = a["dropped"] / claims if claims else None
        mean_out = tout / n if n else 0.0
        verdict, why, alternative = _advice(rule["model"], ladder, replied, fallback, dropped, mean_out)
        if alternative is None:          # still show what the neighbouring model would have cost
            i = ladder.index(rule["model"]) if rule["model"] in ladder else -1
            alternative = (ladder[i - 1] if i > 0 else ladder[i + 1] if 0 <= i < len(ladder) - 1 else None)
        lat = sorted(a["lat"])
        features.append({
            "workflow": key, "description": what, "triggered_by": who, "code_default_tier": default_tier,
            "default_model": default_model, "model": rule["model"], "tier": rule["tier"],
            "max_output_tokens": rule["max_output_tokens"], "enabled": rule["enabled"],
            "by_model": {m: v[0] + v[1] for m, v in sorted(a["tiers"].items())},
            "calls": n, "refused": a["refused"], "failed": a["failed"], "tokens_in": tin, "tokens_out": tout,
            "mean_in": round(tin / n) if n else 0, "mean_out": round(mean_out),
            "cost": round(sum(_cost(policy, t, v[0], v[1]) for t, v in a["tiers"].items()), 4),
            "alternative": alternative,
            "cost_on_alternative": round(_cost(policy, alternative, tin, tout), 4) if alternative else None,
            "usable_rate": round(1 - fallback, 3) if replied else None,
            "claims_dropped_rate": round(dropped, 3) if dropped is not None else None,
            "median_ms": lat[len(lat) // 2] if lat else None,
            "p95_ms": lat[min(len(lat) - 1, round(0.95 * (len(lat) - 1)))] if lat else None,
            "advice": verdict, "why": why})
    month_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    budget = {"month_used": tokens_since(session, month_start), "monthly_tokens": policy.get("monthly_tokens") or 0,
              "today_used": tokens_since(session, today), "daily_tokens": policy.get("daily_tokens") or 0}
    out_users = []
    for u, v in sorted(users.items(), key=lambda x: (-x[1]["period"], x[0])):
        out_users.append({"user": u, **v})
    return {"days": days, "budget": budget, "features": features, "models": policy.get("models") or [],
            "cost_total": round(sum(f["cost"] for f in features), 4), "users": out_users}
