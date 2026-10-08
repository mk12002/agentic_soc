"""Anthropic Claude provider for the governed LLM gateway (official ``anthropic`` Python SDK).

Tiers (IM-T11 tiered model routing):
  * large - complex correlation / investigation reasoning. Default ``claude-opus-5``.
  * small - routine narrative (report commentary, notifications). Default ``claude-haiku-4-5``.
Override with SOC_LLM_DEPLOYMENT / SOC_LLM_DEPLOYMENT_SMALL.

Server-side refusal fallback is enabled for the large tier: if the model declines, the API re-runs the
same request on the fallback model inside the same call. A final refusal returns ``None`` so callers use
their deterministic path. Credentials: SOC_LLM_API_KEY (or *_FILE vault mount); otherwise the SDK's own
resolution (ANTHROPIC_API_KEY / ``ant auth login`` profile).
"""

from __future__ import annotations

import os

import anthropic
import httpx

from soc_platform.config import Settings, secret
from soc_platform.llm.gateway import Completion, Provider, llm_extra_headers, llm_verify

JSON_RULE = ("\n\nOutput format: reply with a single JSON object only - no prose before or after it, "
             "no markdown fences.")
REFUSAL_FALLBACK = {"claude-opus-5": "claude-opus-4-8", "claude-fable-5-1": "claude-opus-4-8"}


class AnthropicProvider(Provider):
    name = "anthropic"

    def __init__(self, settings: Settings) -> None:
        self.models = {"large": settings.llm_deployment or "claude-opus-5",
                       "small": os.environ.get("SOC_LLM_DEPLOYMENT_SMALL") or "claude-haiku-4-5"}
        base_url = (settings.llm_endpoint or "").rstrip("/") or None
        approved = settings.llm_approved_endpoints
        if approved and (base_url or "https://api.anthropic.com") not in approved:
            raise ValueError(f"LLM endpoint {base_url or 'https://api.anthropic.com'} is not on the approved list")
        key = secret("SOC_LLM_API_KEY")
        # None for either falls back to the SDK's own resolution (ANTHROPIC_API_KEY / profile, public endpoint)
        # an organisation's own gateway may need fixed headers and a corporate CA (SOC_LLM_EXTRA_HEADERS / _CA_BUNDLE)
        extra: dict = {"default_headers": llm_extra_headers()} if llm_extra_headers() else {}
        if llm_verify():
            extra["http_client"] = httpx.Client(**llm_verify())
        self.client = anthropic.Anthropic(api_key=key or None, base_url=base_url, **extra)

    def complete(self, system: str, user: str, *, tier: str, max_tokens: int | None = None) -> Completion | None:
        model = self.models.get(tier) or self.models["large"]
        request = {"model": model, "max_tokens": int(max_tokens or 16000), "system": system + JSON_RULE,
                   "messages": [{"role": "user", "content": user}]}
        # a gateway between us and the Claude API may not pass the beta fallback through: SOC_LLM_SERVER_FALLBACK=0
        use_fallback = os.environ.get("SOC_LLM_SERVER_FALLBACK", "1").strip().lower() not in {"0", "false", "no", "off"}
        fallback = REFUSAL_FALLBACK.get(model) if use_fallback else None
        if fallback:
            response = self.client.beta.messages.create(betas=["server-side-fallback-2026-06-01"],
                                                        fallbacks=[{"model": fallback}], **request)
        else:
            response = self.client.messages.create(**request)
        if response.stop_reason == "refusal":
            return None  # whole chain declined -> deterministic path
        text = "".join(block.text for block in response.content if block.type == "text")
        return Completion(text, int(response.usage.input_tokens or 0), int(response.usage.output_tokens or 0),
                          str(response.model))
