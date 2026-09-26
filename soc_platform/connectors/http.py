"""HTTP transport and auth strategies shared by all connectors.

Connectors talk to a ``Transport`` rather than to httpx directly, so the same
connector code (requests, pagination, normalisation) runs against the live API
(``HttpTransport``) or against recorded vendor-shaped fixtures (``FixtureTransport``).
"""

from __future__ import annotations

import base64
import json
import json as _json
import re
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

import httpx

from soc_platform.connectors.base import ConnectorError, RateLimited, TransientError


@dataclass
class Response:
    status: int
    body: Any
    headers: dict[str, str] = field(default_factory=dict)

    def json(self) -> Any:
        return self.body


class Transport(Protocol):
    def request(self, method: str, path: str, *, params: dict[str, Any] | None = None, json: Any = None,
                data: Any = None, headers: dict[str, str] | None = None) -> Response: ...


# ----------------------------------------------------------------------------- auth strategies


class Auth:
    def apply(self, headers: dict[str, str], params: dict[str, Any]) -> None:
        pass


class NoAuth(Auth):
    pass


@dataclass
class ApiKeyHeader(Auth):
    header: str
    value: str
    prefix: str = ""

    def apply(self, headers, params):
        headers[self.header] = f"{self.prefix}{self.value}"


@dataclass
class ApiKeyQuery(Auth):
    param: str
    value: str

    def apply(self, headers, params):
        params[self.param] = self.value


@dataclass
class BasicAuth(Auth):
    username: str
    password: str

    def apply(self, headers, params):
        token = base64.b64encode(f"{self.username}:{self.password}".encode()).decode()
        headers["Authorization"] = f"Basic {token}"


class OAuth2ClientCredentials(Auth):
    """Client-credentials (and password-grant) token with caching and early refresh."""

    def __init__(self, token_url: str, client_id: str, client_secret: str, *, scope: str | None = None,
                 extra: dict[str, str] | None = None, grant_type: str = "client_credentials",
                 json_body: bool = False, basic: bool = False) -> None:
        self.token_url = token_url
        self.client_id = client_id
        self.client_secret = client_secret
        self.scope = scope
        self.extra = extra or {}
        self.grant_type = grant_type
        self.json_body = json_body
        self.basic = basic
        self._token: str | None = None
        self._expires = 0.0
        self._lock = threading.Lock()

    def token(self) -> str:
        with self._lock:
            if self._token and time.time() < self._expires - 60:
                return self._token
            form = {"grant_type": self.grant_type, **self.extra}
            headers = {}
            if self.basic:
                headers["Authorization"] = "Basic " + base64.b64encode(
                    f"{self.client_id}:{self.client_secret}".encode()).decode()
            else:
                form.update({"client_id": self.client_id, "client_secret": self.client_secret})
            if self.scope:
                form["scope"] = self.scope
            resp = (httpx.post(self.token_url, json=form, headers=headers, timeout=30) if self.json_body
                    else httpx.post(self.token_url, data=form, headers=headers, timeout=30))
            if resp.status_code >= 400:
                raise ConnectorError(f"token request failed {resp.status_code}: {resp.text[:200]}")
            body = resp.json()
            self._token = body["access_token"]
            self._expires = time.time() + float(body.get("expires_in", 1800))
            return self._token

    def apply(self, headers, params):
        headers["Authorization"] = f"Bearer {self.token()}"


def entra_app_auth(tenant_id: str, client_id: str, client_secret: str, scope: str) -> OAuth2ClientCredentials:
    return OAuth2ClientCredentials(f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token",
                                   client_id, client_secret, scope=scope)


# ----------------------------------------------------------------------------- transports


class HttpTransport:
    def __init__(self, base_url: str, auth: Auth | None = None, *, timeout: float = 30.0, verify: bool = True,
                 default_headers: dict[str, str] | None = None) -> None:
        self.base_url = base_url.rstrip("/")
        self.auth = auth or NoAuth()
        self.client = httpx.Client(timeout=timeout, verify=verify)
        self.default_headers = {"Accept": "application/json", **(default_headers or {})}

    def request(self, method, path, *, params=None, json=None, data=None, headers=None) -> Response:
        url = path if path.startswith("http") else f"{self.base_url}/{path.lstrip('/')}"
        hdrs = {**self.default_headers, **(headers or {})}
        prm = dict(params or {})
        self.auth.apply(hdrs, prm)
        try:
            r = self.client.request(method, url, params=prm, json=json, data=data, headers=hdrs)
        except httpx.TransportError as exc:
            raise TransientError(str(exc)) from exc
        if r.status_code == 429:
            ra = r.headers.get("Retry-After")
            raise RateLimited(float(ra) if ra and ra.replace(".", "", 1).isdigit() else None)
        if r.status_code >= 500:
            raise TransientError(f"{method} {path} -> {r.status_code}")
        if r.status_code >= 400:
            raise ConnectorError(f"{method} {path} -> {r.status_code}: {r.text[:300]}")
        ctype = r.headers.get("content-type", "")
        body: Any = r.json() if "json" in ctype and r.content else r.text
        return Response(r.status_code, body, dict(r.headers))


class RoutingTransport:
    """Sends absolute URLs under a prefix to a dedicated transport (own base URL + token audience).

    Used where one vendor product spans APIs with different OAuth resources, e.g. Graph
    (``graph.microsoft.com``) and the Exchange Online admin API (``outlook.office365.com``)."""

    def __init__(self, default: Any, routes: dict[str, Any]) -> None:
        self.default = default
        self.routes = sorted(routes.items(), key=lambda kv: -len(kv[0]))

    def request(self, method, path, **kw) -> Response:
        for prefix, transport in self.routes:
            if path.startswith(prefix):
                return transport.request(method, path, **kw)
        return self.default.request(method, path, **kw)


class FixtureTransport:
    """Serves vendor-shaped fixture responses; records every call (writes included) for inspection.

    Fixture file format (``fixtures/<tool>.json``)::

        {"routes": [{"method": "GET", "path": "^/devices/queries", "body": {...}, "status": 200}, ...]}

    Routes match on method + regex over the path (query string excluded). Unmatched
    writes succeed with an echo so action flows can be exercised; unmatched reads 404.
    """

    def __init__(self, routes: list[dict[str, Any]], tool: str = "") -> None:
        self.tool = tool
        self.routes = [(r.get("method", "GET").upper(), re.compile(r["path"]), r) for r in routes]
        self.calls: list[dict[str, Any]] = []

    @classmethod
    def from_file(cls, path: str | Path, tool: str = "") -> FixtureTransport:
        p = Path(path)
        routes = json.loads(p.read_text(encoding="utf-8")).get("routes", []) if p.exists() else []
        return cls(routes, tool)

    def request(self, method, path, *, params=None, json=None, data=None, headers=None) -> Response:
        method = method.upper()
        clean = re.sub(r"^https?://[^/]+", "", path).split("?")[0]
        self.calls.append({"method": method, "path": clean, "params": params, "json": json, "data": data})
        for m, rx, route in self.routes:
            if m == method and rx.search(clean) and _params_match(route.get("params"), params)                     and _body_match(route.get("body_contains"), json if json is not None else data):
                status = int(route.get("status", 200))
                if status == 429:
                    raise RateLimited(0)
                if status >= 500:  # behave exactly like HttpTransport so outages are exercised in fake mode
                    raise TransientError(f"[fixture:{self.tool}] {method} {clean} -> {status}")
                if status >= 400:
                    raise ConnectorError(f"[fixture:{self.tool}] {method} {clean} -> {status}")
                body = json_copy(route.get("body"))
                sel = route.get("select")
                if sel and isinstance(body, dict):
                    body = _select(body, sel, params or {}, json or {})
                return Response(status, body)
        if method in {"POST", "PUT", "PATCH", "DELETE"}:
            return Response(200, {"fixture_echo": True, "method": method, "path": clean, "json": json})
        raise ConnectorError(f"[fixture:{self.tool}] no route for {method} {clean}")


def _body_match(needles: str | list[str] | None, payload: Any) -> bool:
    if not needles:
        return True
    hay = payload if isinstance(payload, str) else _json.dumps(payload, default=str)
    hay = hay.lower()
    return all(n.lower() in hay for n in ([needles] if isinstance(needles, str) else needles))


def _params_match(expected: dict[str, Any] | None, actual: dict[str, Any] | None) -> bool:
    if not expected:
        return True
    actual = actual or {}
    for k, v in expected.items():
        if v == "*":
            if actual.get(k) in (None, ""):
                return False
        elif isinstance(v, str) and v.startswith("~"):
            if not re.search(v[1:], str(actual.get(k) or ""), re.IGNORECASE):
                return False
        elif v == "!":
            if k in actual:
                return False
        elif str(actual.get(k)).lower() != str(v).lower():
            return False
    return True


def _select(body: dict[str, Any], sel: dict[str, Any], params: dict[str, Any], payload: Any) -> dict[str, Any]:
    """Filter a fixture list by values taken from the request, emulating "get by ids" APIs.

    ``sel = {"from": "json.ids" | "params.filter", "list": "resources", "key": "device_id",
             "regex": "optional regex with one group applied to the request value"}``
    """
    src, _, name = str(sel["from"]).partition(".")
    raw = (payload if src == "json" else params).get(name) if isinstance(payload if src == "json" else params, dict) else None
    if raw is None:
        return body
    wanted = raw if isinstance(raw, list) else [raw]
    if sel.get("split"):
        wanted = [x.strip() for w in wanted for x in str(w).split(sel["split"]) if x.strip()]
    if sel.get("regex"):
        rx = re.compile(sel["regex"])
        wanted = [m.group(1) for w in wanted for m in [rx.search(str(w))] if m]
    wanted_l = {str(w).lower() for w in wanted}
    items = body.get(sel.get("list", "resources")) or []
    key = sel["key"]
    body[sel.get("list", "resources")] = [i for i in items if str(_dig(i, key)).lower() in wanted_l]
    return body


def _dig(obj: Any, dotted: str) -> Any:
    for part in dotted.split("."):
        obj = obj.get(part) if isinstance(obj, dict) else None
    return obj


def json_copy(v: Any) -> Any:
    return json.loads(json.dumps(v)) if v is not None else None
