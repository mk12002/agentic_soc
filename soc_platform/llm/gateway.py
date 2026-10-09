"""Governed, evidence-grounded LLM access (NFR-11, IM-T05, IM-T11, VM-T07, R02, R11).

Every model call in the platform goes through ``LLMGateway``:
  * approved endpoints only, pinned model version, tiered routing (small/large)
  * personal data pseudonymised before the prompt leaves the platform
  * prompt and response logged to ``llm_calls``; monthly token budget enforced
  * ``grounded()`` returns claims that each cite evidence ids; claims citing
    nothing valid are dropped; no evidence -> explicit insufficient-evidence
    answer with no model call; model unavailable -> deterministic fallback.
The model never produces figures: callers pass computed numbers in as evidence.
"""

from __future__ import annotations

import json
import os
import re
import statistics
import threading
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any

import httpx
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from soc_platform.config import Settings, secret
from soc_platform.core.models import LLMCall
from soc_platform.llm.redaction import Redactor

GROUNDING_RULES = (
    "You are a SOC analysis assistant. Use ONLY the evidence provided. Every claim MUST cite one or "
    "more evidence ids (e.g. E3). Mark each claim kind as 'fact' (directly observed in evidence) or "
    "'inference' (your reasoning from facts). Do not invent hosts, users, indicators, counts or "
    "percentages. If the evidence does not support a conclusion, set insufficient_evidence to true and "
    "say what is missing. Respond with JSON only."
)


@dataclass
class Completion:
    text: str
    prompt_tokens: int
    completion_tokens: int
    model: str


def llm_timeout(tier: str = "large") -> httpx.Timeout:
    """Connect fast (a down endpoint is known in seconds); allow the read to match the answer's length: routine
    small-tier narrative is short, large-tier reviews and reports can be ~2,000 tokens (~30 s at ~70 tokens/s)."""
    read = float(os.environ.get("SOC_LLM_TIMEOUT_SECONDS", "30") if tier == "small"
                 else os.environ.get("SOC_LLM_TIMEOUT_LARGE_SECONDS", "120"))
    return httpx.Timeout(read, connect=float(os.environ.get("SOC_LLM_CONNECT_TIMEOUT_SECONDS", "10")))


def llm_extra_headers() -> dict[str, str]:
    """SOC_LLM_EXTRA_HEADERS: a JSON object of fixed, non-secret headers an organisation's own LLM gateway may require
    (application id, cost centre...)."""
    raw = os.environ.get("SOC_LLM_EXTRA_HEADERS", "").strip()
    if not raw:
        return {}
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise TypeError("SOC_LLM_EXTRA_HEADERS must be a JSON object")
    return {str(k): str(v) for k, v in value.items()}


def llm_verify() -> dict[str, Any]:
    """SOC_LLM_CA_BUNDLE: CA file for an internal gateway whose certificate a corporate CA issued."""
    ca = os.environ.get("SOC_LLM_CA_BUNDLE", "").strip()
    return {"verify": __import__("ssl").create_default_context(cafile=ca)} if ca else {}


def max_tokens_field() -> str:
    """The request field that caps the answer: ``max_tokens`` (most gateways, gpt-4.1) or ``max_completion_tokens``
    (reasoning models, some newer gateways): SOC_LLM_MAX_TOKENS_FIELD."""
    return os.environ.get("SOC_LLM_MAX_TOKENS_FIELD", "").strip() or "max_tokens"


def post_with_retry(url: str, *, headers: dict[str, str], json: dict[str, Any], tier: str = "large") -> Any:
    """POST to a model endpoint: bounded timeouts, one retry on throttling / transient server errors."""
    import time as _time

    resp = httpx.post(url, headers=headers, json=json, timeout=llm_timeout(tier), **llm_verify())
    code = getattr(resp, "status_code", 200)
    if code in (429, 500, 502, 503, 504):
        wait = getattr(resp, "headers", {}).get("retry-after", "2") if hasattr(resp, "headers") else "2"
        try:
            wait_s = min(5.0, max(0.5, float(wait)))
        except ValueError:
            wait_s = 2.0
        _time.sleep(wait_s)
        resp = httpx.post(url, headers=headers, json=json, timeout=llm_timeout(tier), **llm_verify())
    resp.raise_for_status()
    return resp


def llm_concurrency() -> int:
    """How many model calls a batch (narratives, report sections) may have in flight. Keep it under the provider's
    rate limit; throttled calls are retried once and then fall back to deterministic text."""
    return max(1, int(os.environ.get("SOC_LLM_CONCURRENCY", "4")))


class _Breaker:
    """After repeated failures stop calling the model for a while: screens fall back to the deterministic path at
    once instead of each waiting for a timeout (per process; resets on the first success)."""

    failures = 0
    open_until = 0.0
    _lock = threading.Lock()

    @classmethod
    def is_open(cls) -> bool:
        import time as _time

        return _time.monotonic() < cls.open_until

    @classmethod
    def record(cls, ok: bool) -> None:
        import time as _time

        with cls._lock:
            if ok:
                cls.failures, cls.open_until = 0, 0.0
                return
            cls.failures += 1
            if cls.failures >= int(os.environ.get("SOC_LLM_BREAKER_FAILURES", "3")):
                cls.open_until = _time.monotonic() + float(os.environ.get("SOC_LLM_BREAKER_SECONDS", "60"))


class Provider(ABC):
    name = "none"

    @abstractmethod
    def complete(self, system: str, user: str, *, tier: str, max_tokens: int | None = None) -> Completion | None:
        """``max_tokens``: the most the answer may contain (from the AI usage policy); None = the provider's default."""


class NullProvider(Provider):
    """No model configured: callers use their deterministic fallback."""

    def complete(self, system: str, user: str, *, tier: str, max_tokens: int | None = None) -> Completion | None:
        return None


class AzureOpenAIProvider(Provider):
    name = "azure_openai"

    def __init__(self, settings: Settings) -> None:
        self.endpoint = (settings.llm_endpoint or "").rstrip("/")
        self.api_version = settings.llm_api_version
        self.deployments = {
            "large": settings.llm_deployment or "",
            "small": os.environ.get("SOC_LLM_DEPLOYMENT_SMALL") or settings.llm_deployment or "",
        }
        self.key = secret("SOC_LLM_API_KEY")
        approved = settings.llm_approved_endpoints
        if approved and self.endpoint not in approved:
            raise ValueError(f"LLM endpoint {self.endpoint} is not on the approved list")

    def complete(self, system: str, user: str, *, tier: str, max_tokens: int | None = None) -> Completion | None:
        deployment = self.deployments.get(tier) or self.deployments["large"]
        if not (self.endpoint and deployment and self.key):
            return None
        url = f"{self.endpoint}/openai/deployments/{deployment}/chat/completions?api-version={self.api_version}"
        resp = post_with_retry(
            url,
            headers={**llm_extra_headers(), "api-key": self.key},
            json={"messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
                  "temperature": 0.1, "response_format": {"type": "json_object"},
                  **({max_tokens_field(): max_tokens} if max_tokens else {})},
            tier=tier,
        )
        body = resp.json()
        usage = body.get("usage") or {}
        return Completion(body["choices"][0]["message"]["content"], int(usage.get("prompt_tokens", 0)),
                          int(usage.get("completion_tokens", 0)), str(body.get("model", deployment)))


def build_provider(settings: Settings) -> Provider:
    """Provider factory: none | azure_openai | azure_foundry | anthropic | openai_compatible (SOC_LLM_PROVIDER)."""
    name = (settings.llm_provider or "none").lower()
    if name == "azure_openai":
        return AzureOpenAIProvider(settings)
    if name == "anthropic":
        from soc_platform.llm.providers.anthropic_provider import AnthropicProvider

        return AnthropicProvider(settings)
    if name == "openai_compatible":
        from soc_platform.llm.providers.openai_compatible import OpenAICompatibleProvider

        return OpenAICompatibleProvider(settings)
    if name == "azure_foundry":
        from soc_platform.llm.providers.openai_compatible import AzureFoundryProvider

        return AzureFoundryProvider(settings)
    return NullProvider()


class BudgetExceeded(Exception):
    """The model may not be used for this call (monthly or daily cap, the person's limit, or the feature switched off
    in the AI usage policy). Every caller falls back to its deterministic, cited text."""


class UserLimitExceeded(BudgetExceeded):
    pass


def _accepts_max_tokens(provider: Any) -> bool:
    import inspect

    try:
        return "max_tokens" in inspect.signature(provider.complete).parameters
    except (TypeError, ValueError):
        return False


class LLMGateway:
    def __init__(self, session: Session, settings: Settings, provider: Provider | None = None,
                 redactor: Redactor | None = None, *, actor: Any = None) -> None:
        """``actor``: the person whose request this is (analyst questions, deep analysis, reports) - their limits
        apply; None for scheduled work, which counts only against the platform caps."""
        self.s = session
        self.actor = actor
        self.notice: str | None = None        # why the model was not used for the last refused call (shown to people)
        self._policy: dict[str, Any] | None = None
        # The session is used only for the budget check and the call log, under this lock. The model calls themselves
        # run outside it, so several can be in flight at once (parallel narratives and report sections).
        self._lock = threading.RLock()
        self.settings = settings
        if provider is None:
            provider = build_provider(settings)
        self.provider = provider
        base_domains = set(settings.org_domains) | (set(redactor.internal_domains) if redactor else set())
        base_names = set(redactor.known_names) if redactor else set()
        # Default redaction always knows the organisation's domains, so no caller can forget it.
        self.redactor_factory = lambda: Redactor(internal_domains=set(base_domains), known_names=set(base_names))

    # ------------------------------------------------------------------ budget

    def tokens_this_month(self) -> int:
        from soc_platform.core.models import utcnow

        now = utcnow()
        start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        with self._lock:
            total = self.s.execute(select(func.coalesce(func.sum(LLMCall.prompt_tokens + LLMCall.completion_tokens), 0))
                                   .where(LLMCall.ts >= start)).scalar()
        return int(total or 0)

    def latency_status(self, *, days: int = 30) -> dict[str, dict[str, Any]]:
        """Measured model response times per workflow over the last ``days``: calls, median and 95th percentile."""
        from datetime import timedelta

        from soc_platform.core.models import utcnow

        with self._lock:
            rows = self.s.execute(select(LLMCall.workflow, LLMCall.latency_ms).where(
                LLMCall.ts >= utcnow() - timedelta(days=days), LLMCall.latency_ms.is_not(None),
                LLMCall.status == "ok")).all()
        per: dict[str, list[int]] = {}
        for wf, ms in rows:
            per.setdefault(wf, []).append(int(ms))
        return {wf: {"calls": len(xs), "median_ms": round(statistics.median(xs)),
                     "p95_ms": sorted(xs)[min(len(xs) - 1, round(0.95 * (len(xs) - 1)))]}
                for wf, xs in sorted(per.items())}

    def policy(self) -> dict[str, Any]:
        """The AI usage policy in force (read once per gateway: one request or one job run)."""
        if self._policy is None:
            from soc_platform.llm.usage_policy import UsagePolicyStore

            with self._lock:
                self._policy = UsagePolicyStore(self.s, self.settings).active()
        return self._policy

    def budget_status(self) -> dict[str, Any]:
        from soc_platform.core.models import utcnow
        from soc_platform.llm.usage_policy import day_start, tokens_since

        pol = self.policy()
        used = self.tokens_this_month()
        budget = int(pol.get("monthly_tokens") or 0)
        with self._lock:
            today = tokens_since(self.s, day_start(utcnow()))
        daily = int(pol.get("daily_tokens") or 0)
        alert_at = float(pol.get("alert_at") or 0.8)
        return {"used": used, "budget": budget, "fraction": round(used / budget, 4) if budget else None,
                "alert": bool(budget and used >= alert_at * budget), "exceeded": bool(budget and used >= budget),
                "today": today, "daily_budget": daily, "daily_exceeded": bool(daily and today >= daily)}

    def _refusal(self, workflow: str) -> tuple[str, str] | None:
        """(status, reason) when this call may not use the model, else None."""
        from datetime import timedelta

        from soc_platform.core.models import utcnow
        from soc_platform.llm.usage_policy import day_start, limits_for, rule_for, tokens_since

        pol = self.policy()
        if not rule_for(pol, workflow, "large")["enabled"]:
            return "disabled_by_policy", "the model is switched off for this feature (AI usage policy)"
        b = self.budget_status()
        if b["exceeded"]:
            return "budget_exceeded", "the monthly AI budget is used up"
        if b["daily_exceeded"]:
            return "daily_budget_exceeded", "today's AI budget is used up"
        if self.actor is not None:
            uid = getattr(self.actor, "id", str(self.actor))
            roles = sorted(getattr(r, "value", str(r)) for r in getattr(self.actor, "roles", ()))
            lim = limits_for(pol, uid, roles)
            now = utcnow()
            with self._lock:
                hour = tokens_since(self.s, now - timedelta(hours=1), uid)
                day = tokens_since(self.s, day_start(now), uid)
            if lim["hourly_tokens"] == 0 or lim["daily_tokens"] == 0:
                return "user_limit", "AI text is not enabled for your account (AI usage policy)"
            if hour >= lim["hourly_tokens"]:
                return "user_limit", f"your hourly AI limit ({lim['hourly_tokens']:,} tokens) is reached"
            if day >= lim["daily_tokens"]:
                return "user_limit", f"your daily AI limit ({lim['daily_tokens']:,} tokens) is reached"
        return None

    # ------------------------------------------------------------------ calls

    def complete_json(self, workflow: str, system: str, user: str, *, tier: str = "large",
                      redactor: Redactor | None = None) -> dict[str, Any] | None:
        return self._complete(workflow, system, user, tier=tier, redactor=redactor)[0]

    def _complete(self, workflow: str, system: str, user: str, *, tier: str = "large",
                  redactor: Redactor | None = None) -> tuple[dict[str, Any] | None, LLMCall | None]:
        """The model call: the usage policy decides whether it may run, on which tier and how long its answer may be.
        Returns the parsed answer and its log row (grounded() records how many statements survived the evidence
        check on it). Raises BudgetExceeded when the policy refuses - every caller falls back."""
        from soc_platform.llm.usage_policy import rule_for

        red = redactor or self.redactor_factory()
        red.internal_domains |= set(self.settings.org_domains)
        prompt = red.redact(user) if self.settings.llm_redact_pii else user
        rule = rule_for(self.policy(), workflow, tier)
        refused = self._refusal(workflow)
        if refused:
            self.notice = refused[1]
            self._log(workflow, prompt, refused[1], 0, 0, "none", status=refused[0], tier=rule["tier"])
            raise (UserLimitExceeded if refused[0] == "user_limit" else BudgetExceeded)(f"{refused[1]} ({workflow})")
        if _Breaker.is_open():
            self._log(workflow, prompt, "model endpoint failing - circuit open, deterministic path used", 0, 0, "none",
                      status="circuit_open", tier=rule["tier"])
            return None, None
        kwargs: dict[str, Any] = {"tier": rule["tier"]}
        if rule["max_output_tokens"] and _accepts_max_tokens(self.provider):
            kwargs["max_tokens"] = int(rule["max_output_tokens"])
        started = time.perf_counter()
        try:
            out = self.provider.complete(system, prompt, **kwargs)
        except Exception as exc:  # noqa: BLE001 - logged; the caller falls back to the deterministic text
            _Breaker.record(False)
            self._log(workflow, prompt, f"{type(exc).__name__}: {exc}", 0, 0, "error", status="error",
                      latency_ms=round((time.perf_counter() - started) * 1000), tier=rule["tier"],
                      max_tokens=kwargs.get("max_tokens"))
            return None, None
        latency = round((time.perf_counter() - started) * 1000)
        if out is None:
            return None, None
        _Breaker.record(True)
        pinned = self.settings.llm_model_version
        parsed = _parse_json(out.text)
        status = ("unparseable" if parsed is None else
                  "ok" if not pinned or pinned in out.model else "model_version_mismatch")
        row = self._log(workflow, prompt, out.text, out.prompt_tokens, out.completion_tokens, out.model, status=status,
                        latency_ms=latency, tier=rule["tier"], max_tokens=kwargs.get("max_tokens"))
        if parsed is None:
            return None, row
        return json.loads(red.restore(json.dumps(parsed))), row

    def grounded(self, workflow: str, question: str, evidence: list[dict[str, Any]], *,
                 tier: str = "large", redactor: Redactor | None = None,
                 extra_schema: str = "") -> dict[str, Any]:
        """Evidence-grounded answer. ``evidence`` items need ``id`` and ``claim`` (plus any detail)."""
        valid = {str(e["id"]) for e in evidence if e.get("id")}
        if not valid:
            return {"summary": "Insufficient evidence: no evidence was retrieved for this question.",
                    "claims": [], "grounded": True, "insufficient_evidence": True, "source": "deterministic"}
        lines = "\n".join(f"[{e['id']}] ({e.get('source', e.get('dimension', ''))}) {e['claim']}" for e in evidence)
        user = (f"QUESTION:\n{question}\n\nEVIDENCE (cite by id):\n{lines}\n\n"
                'Return JSON: {"summary": "...", "insufficient_evidence": false, "missing": ["..."], '
                '"claims": [{"text": "...", "kind": "fact|inference", "evidence_ids": ["E1"]}]'
                f"{extra_schema}}}")
        try:
            data, row = self._complete(workflow, GROUNDING_RULES, user, tier=tier, redactor=redactor)
        except BudgetExceeded:
            data, row = None, None
        if data:
            claims = validate_claims(data.get("claims"), valid)
            by_id = {str(e["id"]): f"{e['claim']} {json.dumps({k: v for k, v in e.items() if k not in {'id', 'claim'}}, default=str)}"
                     for e in evidence}
            everything = question + " " + " ".join(by_id.values())
            checked = [c for c in claims
                       if not unsupported_numbers(c["text"], question + " " + " ".join(by_id[i] for i in c["evidence_ids"]))]
            summary, removed = supported_summary(data["summary"] if isinstance(data.get("summary"), str) else "",
                                                 everything)
            insufficient = data.get("insufficient_evidence") is True     # "false" as text is not true
            if row is not None:              # quality signal for tier advice, and the diagnosis of this call
                raw = model_list(data.get("claims"))
                kept_cited = {c["text"] for c in claims}
                kept = {c["text"] for c in checked}
                dropped = [{"text": str(c.get("text", ""))[:300], "reason": "cites no evidence that was provided"}
                           for c in raw if isinstance(c, dict) and str(c.get("text", "")).strip()
                           and str(c.get("text", "")).strip() not in kept_cited]
                dropped += [{"text": c["text"][:300], "reason": "states a figure its cited evidence does not contain"}
                            for c in claims if c["text"] not in kept]
                with self._lock:
                    row.claims_kept, row.claims_dropped = len(checked), len(dropped) + removed
                    row.guardrail = {"kept": len(checked), "dropped": dropped[:50],
                                     "summary_sentences_removed": removed}
                    self.s.flush()
            if checked or insufficient:
                missing = [str(m)[:300] for m in model_list(data.get("missing")) if isinstance(m, (str, int, float))]
                return {**data, "summary": summary, "claims": checked, "grounded": True, "missing": missing[:20],
                        "insufficient_evidence": insufficient, "source": "llm",
                        "dropped_unsupported_figures": len(claims) - len(checked) + removed}
        return deterministic_grounded(evidence)

    def _log(self, workflow: str, prompt: str, response: str, pt: int, ct: int, model: str, *, status: str,
             latency_ms: int | None = None, tier: str | None = None, max_tokens: int | None = None) -> LLMCall:
        from soc_platform.core.observability import current_trace, event

        actor = getattr(self.actor, "id", self.actor) if self.actor is not None else None
        with self._lock:
            row = LLMCall(workflow=workflow, provider=self.provider.name, model=model, prompt_redacted=prompt,
                          response=response, prompt_tokens=pt, completion_tokens=ct, status=status, grounded=True,
                          latency_ms=latency_ms, tier=tier, actor=str(actor)[:256] if actor else None,
                          max_tokens=max_tokens, trace_id=current_trace())
            self.s.add(row)
            self.s.flush()
        event("llm.call", 30 if status in ("error", "unparseable", "model_version_mismatch") else 20,
              call_id=row.id, workflow=workflow, tier=tier, status=status, model=model, prompt_tokens=pt,
              completion_tokens=ct, latency_ms=latency_ms, actor=row.actor,
              detail=response[:300] if status not in ("ok", "model_version_mismatch") else None)
        return row


# Standalone quantities in model text (counts, scores, percentages, times). Digits inside names, IPs, CVE ids,
# hashes or dates (host01, 10.2.3.4, CVE-2021-44228, 2026-09-20) are identifiers, not figures, and are ignored.
_QTY = re.compile(r"(?<![\w.\-])\d+(?:\.\d+)?(?![\w\-]|\.\d)")
_TRIVIAL = {"0", "1"}


def _norm(n: str) -> str:
    return str(int(n)) if n.isdigit() else n.rstrip("0").rstrip(".")


# timestamps in evidence are split into their parts so a statement may quote the time ("09:05") or the date
_ISO = re.compile(r"(\d{4})-(\d{2})-(\d{2})(?:[T ](\d{2}):(\d{2})(?::(\d{2}))?(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)?")


def _quantities(text: str) -> set[str]:
    """Standalone quantities in a text - the same notion for statements and evidence, so digits buried in ids and
    hashes (``9a87b999...``) never make an invented figure look supported."""
    text = _ISO.sub(lambda m: " " + " ".join(g for g in m.groups() if g) + " ", text)
    return {_norm(x) for x in _QTY.findall(text)}


def unsupported_numbers(text: str, support: str) -> list[str]:
    """Figures a model statement contains that appear nowhere in the evidence it rests on (R02: numbers come from
    code, never from the model). ``support`` is the text of the cited evidence (plus the question)."""
    have = _quantities(support)
    return [n for n in (_norm(x) for x in _QTY.findall(text)) if n not in _TRIVIAL and n not in have]


def _split_sentences(text: str) -> list[str]:
    return [p for p in re.split(r"(?<=[.!?])\s+", text.strip()) if p]


def supported_summary(summary: str, support: str) -> tuple[str, int]:
    """Drop summary sentences that state a figure absent from all the evidence; returns (text, removed)."""
    keep, removed = [], 0
    for sent in _split_sentences(summary):
        if unsupported_numbers(sent, support):
            removed += 1
        else:
            keep.append(sent)
    return " ".join(keep), removed


# Model JSON is untrusted input: any field may arrive in any type (a list where a word belongs, a number for a list).
# These read it defensively, so odd output costs that item - never the answer, which then falls back to the
# deterministic one.
def model_list(v: Any) -> list[Any]:
    """A list the model returned, or [] (a string, number or object in its place is not a list of items)."""
    return v if isinstance(v, list) else []


def model_choice(v: Any, allowed: Any, default: Any) -> Any:
    """One of ``allowed`` (a set or mapping of words), or ``default`` - also for unhashable values."""
    return v if isinstance(v, str) and v in allowed else default


def model_ids(item: dict[str, Any], valid_ids: set[str]) -> list[str]:
    """The evidence ids an item cites that were actually provided (one id may come as a bare string)."""
    raw = item.get("evidence_ids")
    ids = [raw] if isinstance(raw, (str, int)) and not isinstance(raw, bool) else model_list(raw)
    return [str(i) for i in ids if isinstance(i, (str, int)) and not isinstance(i, bool) and str(i) in valid_ids]


def validate_claims(claims: Any, valid_ids: set[str]) -> list[dict[str, Any]]:
    out = []
    for c in model_list(claims):
        if not isinstance(c, dict) or not isinstance(c.get("text"), str) or not c["text"].strip():
            continue
        cited = model_ids(c, valid_ids)
        if not cited:
            continue
        out.append({"text": c["text"].strip(), "kind": model_choice(c.get("kind"), {"fact", "inference"}, "inference"),
                    "evidence_ids": cited})
    return out


def deterministic_grounded(evidence: list[dict[str, Any]], limit: int = 8) -> dict[str, Any]:
    ranked = sorted(evidence, key=lambda e: -float(e.get("weight", 0) or 0))[:limit]
    claims = [{"text": str(e["claim"]), "kind": "fact", "evidence_ids": [str(e["id"])]} for e in ranked]
    sources = sorted({str(e.get("source") or e.get("dimension") or "") for e in evidence} - {""})
    return {"summary": f"{len(evidence)} evidence item(s) from {len(sources)} source(s): {', '.join(sources)}.",
            "claims": claims, "grounded": True, "insufficient_evidence": False, "source": "deterministic"}


def _parse_json(text: str | None) -> dict[str, Any] | None:
    if not text:
        return None
    m = re.search(r"\{.*\}", text, re.DOTALL)
    if not m:
        return None
    try:
        v = json.loads(m.group(0))
        return v if isinstance(v, dict) else None
    except json.JSONDecodeError:
        return None
