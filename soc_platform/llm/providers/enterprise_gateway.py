"""The organisation's in-house LLM gateway, reached through its own Python SDK with a service account.

The SDK is installed only in the organisation's environment (from its internal package index) - never in this
repository, its dependency locks or its images. Everything about it is a deployment setting, so nothing here names
it or guesses its location:

* ``SOC_LLM_GATEWAY_SDK`` - the module that exposes ``Session`` (required)
* ``SOC_LLM_GATEWAY_SESSION_ARGS`` - JSON: which ``Session(...)`` argument carries which credential entered in the
  console, e.g. ``{"auth_token": "auth_token", "session_token": "session_token"}`` (the default)
* ``SOC_LLM_GATEWAY_CHAT_ARGS`` - JSON: fixed extra arguments for ``llm.chat`` per size of work, e.g.
  ``{"small": {"reasoning_effort": "low"}, "large": {"reasoning_effort": "medium"}}`` (names as the SDK documents)
* ``SOC_LLM_GATEWAY_SYSTEM_ARG`` - the ``llm.chat`` argument for instructions; unset: they lead the input text
* ``SOC_LLM_GATEWAY_MAX_TOKENS_ARG`` - the ``llm.chat`` argument for the answer cap; unset: no cap is sent
* ``SOC_LLM_GATEWAY_MODELS_CALL`` - the session call that lists the models on offer (``llm.models``); unset: an
  administrator adds new model names in the console instead

The call, as the SDK documents it: ``session = Session(...)``; ``response = await session.llm.chat(model=...,
input=...)``; the text is ``response.response_message.content``. The SDK is asynchronous and the platform's model
calls are not: each call runs on one background event loop, so several can be in flight at once (parallel
narratives) under the usual timeouts. One session is kept per set of credentials and dropped when the gateway
refuses them.

The SDK's first sign-in on a desktop opens an interactive SSO window; a server cannot answer that, which is why the
platform uses the service account's tokens.
"""

from __future__ import annotations

import asyncio
import hashlib
import importlib
import json
import math
import os
import threading
from typing import Any, ClassVar

from soc_platform.config import Settings
from soc_platform.llm.gateway import Completion, Provider, llm_timeout

DEFAULT_SESSION_ARGS = {"auth_token": "auth_token", "session_token": "session_token"}


class GatewaySDKUnavailable(RuntimeError):
    """The gateway's SDK is not installed or not configured in this environment."""


def _json_setting(name: str, default: Any) -> Any:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise TypeError(f"{name} must be a JSON object")
    return value


class _Loop:
    """One event loop in a daemon thread for every gateway call of this process."""

    _loop: asyncio.AbstractEventLoop | None = None
    _lock = threading.Lock()

    @classmethod
    def get(cls) -> asyncio.AbstractEventLoop:
        with cls._lock:
            if cls._loop is None or cls._loop.is_closed():
                loop = asyncio.new_event_loop()
                threading.Thread(target=loop.run_forever, name="llm-gateway-loop", daemon=True).start()
                cls._loop = loop
            return cls._loop

    @classmethod
    def run(cls, coro: Any, timeout: float) -> Any:
        fut = asyncio.run_coroutine_threadsafe(coro, cls.get())
        try:
            return fut.result(timeout=timeout)
        except TimeoutError:
            fut.cancel()
            raise


def _attr(obj: Any, path: str) -> Any:
    for part in path.split("."):
        obj = obj.get(part) if isinstance(obj, dict) else getattr(obj, part, None)
        if obj is None:
            return None
    return obj


def _text(resp: Any) -> str:
    for path in ("response_message.content", "content", "text", "output_text"):
        v = _attr(resp, path)
        if isinstance(v, str):
            return v
    raise ValueError("the gateway's answer has no response_message.content")


def _usage(resp: Any) -> tuple[int, int] | None:
    for holder in ("usage", "token_usage", "tokens", "response_message.usage"):
        u = _attr(resp, holder)
        if u is None:
            continue
        pin = _attr(u, "prompt_tokens") or _attr(u, "input_tokens") or _attr(u, "prompt")
        pout = _attr(u, "completion_tokens") or _attr(u, "output_tokens") or _attr(u, "completion")
        if isinstance(pin, (int, float)) or isinstance(pout, (int, float)):
            return int(pin or 0), int(pout or 0)
    return None


class EnterpriseGatewayProvider(Provider):
    name = "enterprise_gateway"
    _sessions: ClassVar[dict[str, Any]] = {}
    _guard: ClassVar[threading.Lock] = threading.Lock()

    def __init__(self, settings: Settings, *, credentials: dict[str, str] | None = None) -> None:
        self.module_path = os.environ.get("SOC_LLM_GATEWAY_SDK", "").strip()
        self.credentials = dict(credentials or {})
        self.session_args = _json_setting("SOC_LLM_GATEWAY_SESSION_ARGS", DEFAULT_SESSION_ARGS)
        self.chat_args = _json_setting("SOC_LLM_GATEWAY_CHAT_ARGS", {})
        self.system_arg = os.environ.get("SOC_LLM_GATEWAY_SYSTEM_ARG", "").strip()
        self.max_tokens_arg = os.environ.get("SOC_LLM_GATEWAY_MAX_TOKENS_ARG", "").strip()
        self.models_call = os.environ.get("SOC_LLM_GATEWAY_MODELS_CALL", "").strip()
        self.models = {"large": settings.llm_deployment or "",
                       "small": os.environ.get("SOC_LLM_DEPLOYMENT_SMALL") or settings.llm_deployment or ""}

    # ------------------------------------------------------------------ the SDK and its session

    def sdk(self) -> Any:
        if not self.module_path:
            raise GatewaySDKUnavailable("the gateway's SDK module is not configured (SOC_LLM_GATEWAY_SDK)")
        try:
            module = importlib.import_module(self.module_path)
        except ImportError as exc:
            raise GatewaySDKUnavailable("the gateway's SDK is not installed in this environment "
                                        f"({type(exc).__name__}); install it from the organisation's package index") from exc
        if not hasattr(module, "Session"):
            raise GatewaySDKUnavailable("the configured SDK module has no Session (check SOC_LLM_GATEWAY_SDK)")
        return module

    def _kwargs(self) -> dict[str, str]:
        out = {}
        for arg, cred in self.session_args.items():
            if self.credentials.get(str(cred)):
                out[str(arg)] = self.credentials[str(cred)]
        return out

    def _key(self) -> str:
        material = json.dumps([self.module_path, sorted(self._kwargs().items())])
        return hashlib.sha256(material.encode()).hexdigest()

    async def _session(self) -> Any:
        key = self._key()
        with self._guard:
            sess = self._sessions.get(key)
        if sess is None:
            sess = self.sdk().Session(**self._kwargs())
            opener = getattr(sess, "__aenter__", None)
            if opener is not None:                  # a session that must be entered before use
                sess = await opener() or sess
            with self._guard:
                self._sessions[key] = sess
        return sess

    async def _drop(self) -> None:
        with self._guard:
            sess = self._sessions.pop(self._key(), None)
        closer = getattr(sess, "close", None)
        if closer is not None:
            try:
                res = closer()
                if asyncio.iscoroutine(res):
                    await res
            except Exception:  # closing a refused session; the next call opens a new one
                import logging

                logging.getLogger(__name__).debug("gateway session close failed", exc_info=True)

    # ------------------------------------------------------------------ calls

    async def _chat(self, system: str, user: str, model: str, tier: str, max_tokens: int | None) -> Any:
        sess = await self._session()
        kwargs: dict[str, Any] = {"model": model, **(self.chat_args.get(tier) or {})}
        if self.system_arg:
            kwargs[self.system_arg] = system
            kwargs["input"] = user
        else:
            kwargs["input"] = f"{system}\n\n{user}"
        if max_tokens and self.max_tokens_arg:
            kwargs[self.max_tokens_arg] = max_tokens
        try:
            return await sess.llm.chat(**kwargs)
        except Exception as exc:
            from soc_platform.llm.integration import is_auth_error

            if is_auth_error(exc):
                await self._drop()                  # the next call signs in afresh with the credentials in force
            raise

    def complete(self, system: str, user: str, *, tier: str, max_tokens: int | None = None,
                 model: str | None = None) -> Completion | None:
        model = model or self.models.get(tier) or self.models["large"]
        if not model or not self._kwargs():
            return None
        timeout = llm_timeout(tier)
        resp = _Loop.run(self._chat(system, user, model, tier, max_tokens), float(timeout.read or 120) + 5)
        text = _text(resp)
        used = _usage(resp)
        estimated = used is None
        if used is None:                            # budgets still need a figure: about four characters a token
            used = (math.ceil(len(system + user) / 4), math.ceil(len(text) / 4))
        answered = _attr(resp, "model") or _attr(resp, "response_message.model") or model
        return Completion(text, used[0], used[1], str(answered), estimated=estimated)

    def list_models(self) -> list[dict[str, Any]]:
        if not self.models_call:
            return []

        async def run() -> Any:
            sess = await self._session()
            fn = _attr(sess, self.models_call)
            if fn is None:
                raise GatewaySDKUnavailable(f"the SDK session has no {self.models_call} (SOC_LLM_GATEWAY_MODELS_CALL)")
            res = fn() if callable(fn) else fn
            return await res if asyncio.iscoroutine(res) else res

        items = _Loop.run(run(), float(llm_timeout("small").read or 30) + 5)
        out = []
        for it in items or []:
            name = it if isinstance(it, str) else (_attr(it, "name") or _attr(it, "display_name") or _attr(it, "id"))
            if not isinstance(name, str) or not name.strip():
                continue
            state = str(_attr(it, "status") or _attr(it, "lifecycle") or "").lower() if not isinstance(it, str) else ""
            out.append({"name": name.strip()[:128],
                        "deprecated": bool(not isinstance(it, str) and (_attr(it, "deprecated") or "deprecat" in state))})
        return out
