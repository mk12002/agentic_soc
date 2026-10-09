"""AI usage policy: budgets, per-user limits and per-feature model choice, decided by administrators (NFR-11).

The administrator sets, in the console (*AI usage* screen), without a restart:

* **monthly_tokens** - the hard cap for the whole platform (the old ``SOC_LLM_MONTHLY_TOKEN_BUDGET`` is the default)
* **daily_tokens** - no single day may use more (default: a tenth of the month), so a burst - a runaway script, a
  flood of incidents - cannot spend the month in an afternoon
* **per-user limits** (tokens per hour and per day) for what a person asks for: analyst questions, deep analysis,
  reports. A default for everyone, an override per role and per user; ``0`` means that user gets no model text
  (answers are written by the platform from the same evidence). Scheduled work (incident and phishing explanations,
  finding narratives, the brief, scheduled reports) counts only against the platform caps.
* **per-feature settings** - which model tier (``small`` / ``large``) each feature uses, the most it may write
  (``max_output_tokens``), or ``enabled: false`` to switch the model off for that feature alone
* **prices** per tier, so the usage screen can show cost and what a tier change would save

Every change is a new version (who, when, why), audited; the history is kept. Over any limit the platform never
fails: the caller's deterministic, cited fallback is used and the refusal is logged with its reason.

``usage_report`` turns the call log into what an administrator needs to choose a tier per feature: calls, tokens,
cost, how often the answer was usable (parsed, and claims kept by the evidence guardrail), speed - and a
recommendation computed from those figures (never by a model).
"""

from __future__ import annotations

import copy
import math
from datetime import timedelta
from typing import Any

from sqlalchemy import JSON, Integer, String, func, select
from sqlalchemy.orm import Mapped, Session, mapped_column

from soc_platform.core.db import Base, BoundedText, UTCDateTime
from soc_platform.core.models import LLMCall, utcnow

TIERS = ("small", "large")
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
    "report.section.*": ("large", "person", "One section of a generated report"),
    "report.daily_exposure": ("small", "scheduled", "Daily exposure report commentary"),
    "report.weekly_vm": ("small", "scheduled", "Weekly vulnerability report commentary"),
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


def defaults(settings: Any) -> dict[str, Any]:
    monthly = int(settings.llm_monthly_token_budget or 0)
    return {
        "monthly_tokens": monthly,
        "daily_tokens": monthly // 10 if monthly else 0,
        "alert_at": 0.8,
        "user_default": {"hourly_tokens": 100_000, "daily_tokens": 400_000},
        "roles": {},
        "users": {},
        "workflows": {},
        "max_output_tokens": {"small": 1_500, "large": 3_000},
        "prices": {"small": {"input": 0.40, "output": 1.60}, "large": {"input": 0.40, "output": 1.60}},
    }


def _nonneg_int(v: Any) -> bool:
    return isinstance(v, int) and not isinstance(v, bool) and 0 <= v <= 10**15


def _number(v: Any) -> bool:
    """A real, finite number (JSON lets NaN and Infinity through; neither is a budget or a price)."""
    return isinstance(v, (int, float)) and not isinstance(v, bool) and math.isfinite(v)


def validate(doc: Any) -> list[str]:
    """Problems with a policy document, each saying what to fix (empty = valid)."""
    if not isinstance(doc, dict):
        return ["the policy must be an object"]
    out: list[str] = []
    allowed = {"monthly_tokens", "daily_tokens", "alert_at", "user_default", "roles", "users", "workflows",
               "max_output_tokens", "prices"}
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
            out.append(f"workflows.{wf}: expected tier / max_output_tokens / enabled")
            continue
        for k, x in rule.items():
            if k == "tier" and x not in TIERS:
                out.append(f"workflows.{wf}.tier must be small or large")
            elif k == "enabled" and not isinstance(x, bool):
                out.append(f"workflows.{wf}.enabled must be true or false")
            elif k == "max_output_tokens" and not (_nonneg_int(x) and 200 <= x <= 16_000):
                out.append(f"workflows.{wf}.max_output_tokens must be between 200 and 16000")
            elif k not in ("tier", "enabled", "max_output_tokens"):
                out.append(f"workflows.{wf}.{k}: unknown (tier, max_output_tokens, enabled)")
    for t, x in maps["max_output_tokens"].items():
        if t not in TIERS or not (_nonneg_int(x) and 200 <= x <= 16_000):
            out.append(f"max_output_tokens.{t}: a tier (small / large) and a number between 200 and 16000")
    for t, p in maps["prices"].items():
        if t not in TIERS or not isinstance(p, dict) or not all(
                _number(p.get(k)) and 0 <= p.get(k) <= 10_000 for k in ("input", "output")):
            out.append(f"prices.{t}: a tier with input and output prices per million tokens, 0 or more")
    return out


class UsagePolicyStore:
    def __init__(self, session: Session, settings: Any) -> None:
        self.s, self.settings = session, settings

    def active_row(self) -> LLMUsagePolicy | None:
        return self.s.execute(select(LLMUsagePolicy).order_by(LLMUsagePolicy.id.desc()).limit(1)).scalars().first()

    def active(self) -> dict[str, Any]:
        """The policy in force: the defaults with the newest saved version on top."""
        doc = defaults(self.settings)
        row = self.active_row()
        if row:
            for k, v in (row.document or {}).items():
                doc[k] = copy.deepcopy(v)
        return doc

    def save(self, doc: dict[str, Any], by: Any, note: str = "") -> LLMUsagePolicy:
        from soc_platform.core.audit import AuditLog
        from soc_platform.core.auth import Perm

        if by.is_service or by.is_agent or not by.can(Perm.MANAGE_ACCESS):
            raise PermissionError("an administrator (manage_access) sets AI usage limits")
        problems = validate(doc)
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
    """Tier, output cap and on/off for one call."""
    r = (policy.get("workflows") or {}).get(workflow_key(workflow)) or {}
    tier = r.get("tier") or asked_tier
    tier = tier if tier in TIERS else "large"
    cap = r.get("max_output_tokens") or (policy.get("max_output_tokens") or {}).get(tier)
    return {"tier": tier, "max_output_tokens": cap, "enabled": r.get("enabled", True)}


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


def _cost(policy: dict[str, Any], tier: str, tin: int, tout: int) -> float:
    p = (policy.get("prices") or {}).get(tier) or {"input": 0, "output": 0}
    return (tin * float(p["input"]) + tout * float(p["output"])) / 1_000_000


def _advice(tier: str, n: int, fallback: float, dropped: float | None, mean_out: float) -> tuple[str, str]:
    """A tier recommendation from measured figures only. The guardrail's dropped-claim rate is the quality signal: a
    model that writes statements the evidence does not support loses them, and the reader gets less."""
    if n < MIN_CALLS_FOR_ADVICE:
        return "not enough data", f"fewer than {MIN_CALLS_FOR_ADVICE} calls in this period - keep the default"
    d = dropped if dropped is not None else 0.0
    if tier == "large" and fallback <= 0.02 and d <= 0.05 and mean_out <= 600:
        return "try small", ("short answers that pass the evidence check: the small tier is likely enough - switch, "
                             "then compare this table after a week")
    if tier == "small" and (fallback > 0.05 or d > 0.15):
        return "use large", (f"{round(100 * max(fallback, d))} % of answers fail or lose statements to the evidence "
                             "check on the small tier")
    return "keep", "quality and cost are in balance on this tier"


def usage_report(session: Session, policy: dict[str, Any], *, days: int = 30) -> dict[str, Any]:
    now = utcnow()
    since = now - timedelta(days=days)
    rows = session.execute(select(LLMCall.workflow, LLMCall.tier, LLMCall.status, LLMCall.prompt_tokens,
                                  LLMCall.completion_tokens, LLMCall.latency_ms, LLMCall.claims_kept,
                                  LLMCall.claims_dropped, LLMCall.actor, LLMCall.ts)
                           .where(LLMCall.ts >= since)).all()
    per: dict[str, dict[str, Any]] = {}
    users: dict[str, dict[str, int]] = {}
    hour_ago, today = now - timedelta(hours=1), day_start(now)
    for wf, tier, status, pt, ct, ms, kept, dropped, actor, ts in rows:
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
        tt = a["tiers"].setdefault(tier or "large", [0, 0])
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
        other = "small" if rule["tier"] == "large" else "large"
        verdict, why = _advice(rule["tier"], replied, fallback, dropped, mean_out)
        lat = sorted(a["lat"])
        features.append({
            "workflow": key, "description": what, "triggered_by": who, "code_default_tier": default_tier,
            "tier": rule["tier"], "max_output_tokens": rule["max_output_tokens"], "enabled": rule["enabled"],
            "calls": n, "refused": a["refused"], "failed": a["failed"], "tokens_in": tin, "tokens_out": tout,
            "mean_in": round(tin / n) if n else 0, "mean_out": round(mean_out),
            "cost": round(sum(_cost(policy, t, v[0], v[1]) for t, v in a["tiers"].items()), 4),
            "cost_on_other_tier": round(_cost(policy, other, tin, tout), 4), "other_tier": other,
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
    return {"days": days, "budget": budget, "features": features,
            "cost_total": round(sum(f["cost"] for f in features), 4), "users": out_users}
