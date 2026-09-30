"""OpenAI-compatible chat-completions provider (OpenAI, or self-hosted vLLM / Ollama / LM Studio for
tenant-resident processing - PH-T06, NFR-10). SOC_LLM_ENDPOINT is the base URL (e.g. http://llm:8000),
SOC_LLM_DEPLOYMENT / SOC_LLM_DEPLOYMENT_SMALL are model names, SOC_LLM_API_KEY is optional for local servers.

``azure_foundry`` is the same protocol on Azure AI Foundry / Azure OpenAI's v1 API: SOC_LLM_ENDPOINT is
``https://<resource>.services.ai.azure.com/openai/v1`` (or ``https://<resource>.openai.azure.com/openai/v1``),
SOC_LLM_DEPLOYMENT is the deployment name (e.g. ``gpt-4.1-mini``), and SOC_LLM_API_KEY is sent as ``api-key``.

An organisation's own LLM gateway (one endpoint in front of several vendors' models) usually speaks this protocol
too; what differs is set without code changes:
  * SOC_LLM_AUTH_HEADER / SOC_LLM_AUTH_PREFIX - the header carrying SOC_LLM_API_KEY (default ``Authorization`` /
    ``Bearer ``; e.g. ``x-api-key`` with an empty prefix)
  * SOC_LLM_EXTRA_HEADERS - JSON object of fixed non-secret headers; SOC_LLM_CA_BUNDLE - corporate CA file
  * SOC_LLM_JSON_MODE=0 - for gateways or models that reject ``response_format``: JSON is then asked for in the
    instructions only (replies are parsed tolerantly either way)
"""

from __future__ import annotations

import os

import httpx  # noqa: F401 - kept importable here: tests patch httpx.post through this module

from soc_platform.config import Settings, secret
from soc_platform.llm.gateway import Completion, Provider, llm_extra_headers, post_with_retry

JSON_RULE = ("\n\nOutput format: reply with a single JSON object only - no prose before or after it, "
             "no markdown fences.")


class OpenAICompatibleProvider(Provider):
    name = "openai_compatible"
    requires_key = False

    def __init__(self, settings: Settings) -> None:
        self.base = (settings.llm_endpoint or "").rstrip("/")
        self.models = {"large": settings.llm_deployment or "",
                       "small": os.environ.get("SOC_LLM_DEPLOYMENT_SMALL") or settings.llm_deployment or ""}
        self.key = secret("SOC_LLM_API_KEY")
        approved = settings.llm_approved_endpoints
        if approved and self.base not in approved:
            raise ValueError(f"LLM endpoint {self.base} is not on the approved list")

    def _headers(self) -> dict[str, str]:
        name = os.environ.get("SOC_LLM_AUTH_HEADER", "").strip() or "Authorization"
        prefix = os.environ.get("SOC_LLM_AUTH_PREFIX", "Bearer ")
        return {**llm_extra_headers(), **({name: f"{prefix}{self.key}"} if self.key else {})}

    def complete(self, system: str, user: str, *, tier: str) -> Completion | None:
        model = self.models.get(tier) or self.models["large"]
        if not (self.base and model) or (self.requires_key and not self.key):
            return None
        url = self.base + ("/chat/completions" if self.base.endswith("/v1") else "/v1/chat/completions")
        headers = self._headers()
        body: dict = {"model": model, "temperature": 0.1,
                      "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}]}
        if os.environ.get("SOC_LLM_JSON_MODE", "1").strip().lower() in {"0", "false", "no", "off"}:
            body["messages"][0]["content"] = system + JSON_RULE
        else:
            body["response_format"] = {"type": "json_object"}
        resp = post_with_retry(url, headers=headers, json=body, tier=tier)
        body = resp.json()
        usage = body.get("usage") or {}
        return Completion(body["choices"][0]["message"]["content"], int(usage.get("prompt_tokens", 0) or 0),
                          int(usage.get("completion_tokens", 0) or 0), str(body.get("model", model)))


class AzureFoundryProvider(OpenAICompatibleProvider):
    """Azure AI Foundry / Azure OpenAI v1 API (OpenAI-compatible; key in the ``api-key`` header)."""

    name = "azure_foundry"
    requires_key = True

    def _headers(self) -> dict[str, str]:
        return {**llm_extra_headers(), "api-key": self.key or ""}
