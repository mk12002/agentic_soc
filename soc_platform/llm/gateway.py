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


def post_with_retry(url: str, *, headers: dict[str, str], json: dict[str, Any], tier: str = "large") -> Any:
    """POST to a model endpoint: bounded timeouts, one retry on throttling / transient server errors."""
    import time as _time

    resp = httpx.post(url, headers=headers, json=json, timeout=llm_timeout(tier))
    code = getattr(resp, "status_code", 200)
    if code in (429, 500, 502, 503, 504):
        wait = getattr(resp, "headers", {}).get("retry-after", "2") if hasattr(resp, "headers") else "2"
        try:
            wait_s = min(5.0, max(0.5, float(wait)))
        except ValueError:
            wait_s = 2.0
        _time.sleep(wait_s)
        resp = httpx.post(url, headers=headers, json=json, timeout=llm_timeout(tier))
    resp.raise_for_status()
    return resp


class _Breaker:
    """After repeated failures stop calling the model for a while: screens fall back to the deterministic path at
    once instead of each waiting for a timeout (per process; resets on the first success)."""

    failures = 0
    open_until = 0.0

    @classmethod
    def is_open(cls) -> bool:
        import time as _time

        return _time.monotonic() < cls.open_until

    @classmethod
    def record(cls, ok: bool) -> None:
        import time as _time

        if ok:
            cls.failures, cls.open_until = 0, 0.0
            return
        cls.failures += 1
        if cls.failures >= int(os.environ.get("SOC_LLM_BREAKER_FAILURES", "3")):
            cls.open_until = _time.monotonic() + float(os.environ.get("SOC_LLM_BREAKER_SECONDS", "60"))


class Provider(ABC):
    name = "none"

    @abstractmethod
    def complete(self, system: str, user: str, *, tier: str) -> Completion | None: ...


class NullProvider(Provider):
    """No model configured: callers use their deterministic fallback."""

    def complete(self, system: str, user: str, *, tier: str) -> Completion | None:
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

    def complete(self, system: str, user: str, *, tier: str) -> Completion | None:
        deployment = self.deployments.get(tier) or self.deployments["large"]
        if not (self.endpoint and deployment and self.key):
            return None
        url = f"{self.endpoint}/openai/deployments/{deployment}/chat/completions?api-version={self.api_version}"
        resp = post_with_retry(
            url,
            headers={"api-key": self.key},
            json={"messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
                  "temperature": 0.1, "response_format": {"type": "json_object"}},
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
    pass


class LLMGateway:
    def __init__(self, session: Session, settings: Settings, provider: Provider | None = None,
                 redactor: Redactor | None = None) -> None:
        self.s = session
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
        total = self.s.execute(select(func.coalesce(func.sum(LLMCall.prompt_tokens + LLMCall.completion_tokens), 0))
                               .where(LLMCall.ts >= start)).scalar()
        return int(total or 0)

    def budget_status(self) -> dict[str, Any]:
        used = self.tokens_this_month()
        budget = self.settings.llm_monthly_token_budget
        return {"used": used, "budget": budget, "fraction": round(used / budget, 4) if budget else None,
                "alert": bool(budget and used >= 0.8 * budget), "exceeded": bool(budget and used >= budget)}

    # ------------------------------------------------------------------ calls

    def complete_json(self, workflow: str, system: str, user: str, *, tier: str = "large",
                      redactor: Redactor | None = None) -> dict[str, Any] | None:
        red = redactor or self.redactor_factory()
        red.internal_domains |= set(self.settings.org_domains)
        prompt = red.redact(user) if self.settings.llm_redact_pii else user
        if self.budget_status()["exceeded"]:
            self._log(workflow, prompt, "", 0, 0, "none", status="budget_exceeded")
            raise BudgetExceeded(f"monthly LLM token budget exhausted ({workflow})")
        if _Breaker.is_open():
            self._log(workflow, prompt, "model endpoint failing - circuit open, deterministic path used", 0, 0, "none",
                      status="circuit_open")
            return None
        try:
            out = self.provider.complete(system, prompt, tier=tier)
        except Exception as exc:  # noqa: BLE001 - logged; the caller falls back to the deterministic text
            _Breaker.record(False)
            self._log(workflow, prompt, f"{type(exc).__name__}: {exc}", 0, 0, "error", status="error")
            return None
        if out is None:
            return None
        _Breaker.record(True)
        pinned = self.settings.llm_model_version
        status = "ok" if not pinned or pinned in out.model else "model_version_mismatch"
        self._log(workflow, prompt, out.text, out.prompt_tokens, out.completion_tokens, out.model, status=status)
        parsed = _parse_json(out.text)
        if parsed is None:
            return None
        return json.loads(red.restore(json.dumps(parsed)))

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
            data = self.complete_json(workflow, GROUNDING_RULES, user, tier=tier, redactor=redactor)
        except BudgetExceeded:
            data = None
        if data:
            claims = validate_claims(data.get("claims"), valid)
            by_id = {str(e["id"]): f"{e['claim']} {json.dumps({k: v for k, v in e.items() if k not in {'id', 'claim'}}, default=str)}"
                     for e in evidence}
            everything = question + " " + " ".join(by_id.values())
            checked = [c for c in claims
                       if not unsupported_numbers(c["text"], question + " " + " ".join(by_id[i] for i in c["evidence_ids"]))]
            summary, removed = supported_summary(str(data.get("summary", "")), everything)
            if checked or data.get("insufficient_evidence"):
                return {**data, "summary": summary, "claims": checked, "grounded": True,
                        "insufficient_evidence": bool(data.get("insufficient_evidence")), "source": "llm",
                        "dropped_unsupported_figures": len(claims) - len(checked) + removed}
        return deterministic_grounded(evidence)

    def _log(self, workflow: str, prompt: str, response: str, pt: int, ct: int, model: str, *, status: str) -> None:
        self.s.add(LLMCall(workflow=workflow, provider=self.provider.name, model=model, prompt_redacted=prompt,
                           response=response, prompt_tokens=pt, completion_tokens=ct, status=status,
                           grounded=True))
        self.s.flush()


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


def validate_claims(claims: Any, valid_ids: set[str]) -> list[dict[str, Any]]:
    out = []
    for c in claims or []:
        if not isinstance(c, dict) or not str(c.get("text", "")).strip():
            continue
        cited = [str(i) for i in (c.get("evidence_ids") or []) if str(i) in valid_ids]
        if not cited:
            continue
        kind = c.get("kind") if c.get("kind") in {"fact", "inference"} else "inference"
        out.append({"text": str(c["text"]).strip(), "kind": kind, "evidence_ids": cited})
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
