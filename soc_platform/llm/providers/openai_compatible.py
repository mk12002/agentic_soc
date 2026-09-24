"""OpenAI-compatible chat-completions provider (OpenAI, or self-hosted vLLM / Ollama / LM Studio for
tenant-resident processing - PH-T06, NFR-10). SOC_LLM_ENDPOINT is the base URL (e.g. http://llm:8000),
SOC_LLM_DEPLOYMENT / SOC_LLM_DEPLOYMENT_SMALL are model names, SOC_LLM_API_KEY is optional for local servers.
"""

from __future__ import annotations

import os

import httpx

from soc_platform.config import Settings, secret
from soc_platform.llm.gateway import Completion, Provider


class OpenAICompatibleProvider(Provider):
    name = "openai_compatible"

    def __init__(self, settings: Settings) -> None:
        self.base = (settings.llm_endpoint or "").rstrip("/")
        self.models = {"large": settings.llm_deployment or "",
                       "small": os.environ.get("SOC_LLM_DEPLOYMENT_SMALL") or settings.llm_deployment or ""}
        self.key = secret("SOC_LLM_API_KEY")
        approved = settings.llm_approved_endpoints
        if approved and self.base not in approved:
            raise ValueError(f"LLM endpoint {self.base} is not on the approved list")

    def complete(self, system: str, user: str, *, tier: str) -> Completion | None:
        model = self.models.get(tier) or self.models["large"]
        if not (self.base and model):
            return None
        url = self.base + ("/chat/completions" if self.base.endswith("/v1") else "/v1/chat/completions")
        headers = {"Authorization": f"Bearer {self.key}"} if self.key else {}
        resp = httpx.post(url, headers=headers, timeout=120, json={
            "model": model, "temperature": 0.1, "response_format": {"type": "json_object"},
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}]})
        resp.raise_for_status()
        body = resp.json()
        usage = body.get("usage") or {}
        return Completion(body["choices"][0]["message"]["content"], int(usage.get("prompt_tokens", 0) or 0),
                          int(usage.get("completion_tokens", 0) or 0), str(body.get("model", model)))
