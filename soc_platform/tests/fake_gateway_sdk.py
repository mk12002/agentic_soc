"""A stand-in for the in-house LLM gateway's SDK, shaped like its documentation: ``Session(...)`` (async),
``await session.llm.chat(model=..., input=...)`` answering ``response.response_message.content``, plus a model list.

The real SDK is installed only in the organisation's environment; tests point ``SOC_LLM_GATEWAY_SDK`` here. ``STATE``
lets a test change what the gateway offers and how it answers: valid tokens, the models (and which are being retired),
models that answer badly, and whether answers report token usage.
"""

from __future__ import annotations

import asyncio
import json
import re
from typing import Any

STATE: dict[str, Any] = {}


def reset() -> None:
    STATE.clear()
    STATE.update({"tokens": {"svc-auth-token"}, "models": ["GPT 6 Sol", "GPT 6.1 Sol", "GPT 6 Luna"],
                  "retiring": set(), "bad_models": set(), "usage": True, "calls": [], "sessions": 0,
                  "delay": 0.0, "in_flight": 0, "max_in_flight": 0})


reset()


class AuthenticationError(Exception):
    """The gateway refused the service account's token."""


class _Message:
    def __init__(self, content: str) -> None:
        self.content = content


class _Response:
    def __init__(self, content: str, model: str, usage: dict[str, int] | None) -> None:
        self.response_message = _Message(content)
        self.model = model
        if usage is not None:
            self.usage = usage


def _answer(model: str, text: str) -> str:
    ids = re.findall(r"\[([A-Z]{1,3}\d{1,4})\]", text)       # E1, K3, S2... whatever the platform cites
    if model in STATE["bad_models"]:            # cites evidence that was never given: fails the platform's check
        return json.dumps({"summary": "Host H-1 was wiped.",
                           "claims": [{"text": "Host H-1 was wiped", "kind": "fact", "evidence_ids": ["E99"]}]})
    first = ids[0] if ids else "E1"
    claim = re.search(r"\[" + first + r"\] \([^)]*\) ([^\n]+)", text)
    said = claim.group(1) if claim else "The evidence was reviewed"
    return json.dumps({"summary": said, "insufficient_evidence": False,
                       "claims": [{"text": said, "kind": "fact", "evidence_ids": [first]}]})


class _LLM:
    def __init__(self, session: Session) -> None:
        self._s = session

    async def chat(self, model: str, input: str, **kwargs: Any) -> _Response:
        if self._s.auth_token not in STATE["tokens"]:
            raise AuthenticationError("token expired or revoked")
        STATE["in_flight"] += 1
        STATE["max_in_flight"] = max(STATE["max_in_flight"], STATE["in_flight"])
        try:
            if STATE["delay"]:
                await asyncio.sleep(STATE["delay"])
            STATE["calls"].append({"model": model, "input": input, **kwargs})
            if model not in STATE["models"]:
                raise ValueError(f"unknown model {model}")
            content = _answer(model, input)
            usage = {"input_tokens": len(input) // 4, "output_tokens": len(content) // 4} if STATE["usage"] else None
            return _Response(content, model, usage)
        finally:
            STATE["in_flight"] -= 1

    async def models(self) -> list[dict[str, Any]]:
        if self._s.auth_token not in STATE["tokens"]:
            raise AuthenticationError("token expired or revoked")
        return [{"name": m, "status": "deprecating" if m in STATE["retiring"] else "active"} for m in STATE["models"]]


class Session:
    def __init__(self, auth_token: str | None = None, session_token: str | None = None) -> None:
        self.auth_token, self.session_token = auth_token, session_token
        self.llm = _LLM(self)
        self.closed = False
        STATE["sessions"] += 1

    async def close(self) -> None:
        self.closed = True
