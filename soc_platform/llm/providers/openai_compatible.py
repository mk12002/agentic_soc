"""OpenAI-compatible chat-completions provider (OpenAI, or self-hosted vLLM / Ollama / LM Studio for
tenant-resident processing - PH-T06, NFR-10). SOC_LLM_ENDPOINT is the base URL (e.g. http://llm:8000),
SOC_LLM_DEPLOYMENT / SOC_LLM_DEPLOYMENT_SMALL are model names, SOC_LLM_API_KEY is optional for local servers.

``azure_foundry`` is the same protocol on Azure AI Foundry / Azure OpenAI's v1 API: SOC_LLM_ENDPOINT is
``https://<resource>.services.ai.azure.com/openai/v1`` (or ``https://<resource>.openai.azure.com/openai/v1``),
SOC_LLM_DEPLOYMENT is the deployment name (e.g. ``gpt-4.1-mini``), and SOC_LLM_API_KEY is sent as ``api-key``.
"""

from __future__ import annotations

import os

import httpx

from soc_platform.config import Settings, secret
from soc_platform.llm.gateway import Completion, Provider


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
        return {"Authorization": f"Bearer {self.key}"} if self.key else {}

    def complete(self, system: str, user: str, *, tier: str) -> Completion | None:
        model = self.models.get(tier) or self.models["large"]
        if not (self.base and model) or (self.requires_key and not self.key):
            return None
        url = self.base + ("/chat/completions" if self.base.endswith("/v1") else "/v1/chat/completions")
        headers = self._headers()
        resp = httpx.post(url, headers=headers, timeout=120, json={
            "model": model, "temperature": 0.1, "response_format": {"type": "json_object"},
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}]})
        resp.raise_for_status()
        body = resp.json()
        usage = body.get("usage") or {}
        return Completion(body["choices"][0]["message"]["content"], int(usage.get("prompt_tokens", 0) or 0),
                          int(usage.get("completion_tokens", 0) or 0), str(body.get("model", model)))


class AzureFoundryProvider(OpenAICompatibleProvider):
    """Azure AI Foundry / Azure OpenAI v1 API (OpenAI-compatible; key in the ``api-key`` header)."""

    name = "azure_foundry"
    requires_key = True

    def _headers(self) -> dict[str, str]:
        return {"api-key": self.key or ""}
