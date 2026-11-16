"""Every connector's *live* code path, on the wire, without a tenant.

Fake mode hands a connector's requests to ``FixtureTransport`` as Python objects. A live tool gets them through
``HttpTransport``: the sign-in (token endpoint), the base URL joined to the path, parameters encoded into a query
string, a JSON body, the answer parsed by content type. A mistake in any of those is invisible in fake mode and stops
the tool on the first day in production.

Here each connector is built exactly as the registry builds it for a live tool (``manifest.live_transport``), and its
HTTP client is pointed at a local responder that answers from the same fixtures. Every stream must then read the
same records as in fake mode, every request must carry the tool's credentials, and a sign-in that cannot complete must
surface as a connector error the platform knows how to handle.
"""

from __future__ import annotations

import json
from typing import Any
from urllib.parse import parse_qsl, urlsplit

import httpx
import pytest

from soc_platform.connectors.base import (
    AuthExpired,
    ConnectorError,
    PermissionDenied,
    RateLimited,
    TransientError,
)
from soc_platform.connectors.http import HttpTransport, OAuth2ClientCredentials
from soc_platform.connectors.registry import ConnectorRegistry, discover

MANIFESTS = discover()
MAX_PAGES = 25


def _live_settings(name: str) -> dict[str, Any]:
    """What an operator would enter: the sample estate's settings plus a value for every setting the tool declares."""
    m = MANIFESTS[name]
    s = dict(ConnectorRegistry.all_fake().settings_for(name))
    for f in m.config:
        if s.get(f.name) not in (None, "") or f.name == "client_certificate":
            continue
        if f.kind == "url" or f.name.endswith(("_url", "_base")):
            s[f.name] = f"https://{name.replace('_', '-')}.tool.example"
        elif f.kind in ("bool", "int", "map", "list", "choice", "path"):
            continue                                   # optional behaviour switches keep their defaults
        elif f.required or f.secret:
            s[f.name] = "wire-test-value"
    return s


def _transports(obj: Any, seen: set[int] | None = None) -> list[HttpTransport]:
    """Every HttpTransport a live transport holds (a routing transport and a per-source bundle hold several)."""
    seen = seen if seen is not None else set()
    if id(obj) in seen or obj is None or isinstance(obj, (str, bytes, int, float, bool)):
        return []
    seen.add(id(obj))
    if isinstance(obj, HttpTransport):
        return [obj]
    if isinstance(obj, dict):
        return [t for v in obj.values() for t in _transports(v, seen)]
    if isinstance(obj, (list, tuple, set)):
        return [t for v in obj for t in _transports(v, seen)]
    if type(obj).__module__.startswith("soc_platform.connectors"):
        return [t for v in vars(obj).values() for t in _transports(v, seen)]
    return []


def _wire(name: str, monkeypatch) -> tuple[Any, list[httpx.Request], list[str]]:
    """The connector as the registry builds it for a live tool, its HTTP client answered from the fixtures."""
    m = MANIFESTS[name]
    fixtures = m.fixture_transport()
    requests: list[httpx.Request] = []
    sign_ins: list[str] = []

    def token_post(url, **kw):
        sign_ins.append(url)
        return httpx.Response(200, json={"access_token": "wire-token", "expires_in": 3600, "data": {"token": "wire-token"}})

    monkeypatch.setattr("soc_platform.connectors.http.httpx.post", token_post)
    transport = m.live_transport(_live_settings(name))

    def responder(base_path: str):
        def handle(req: httpx.Request) -> httpx.Response:
            requests.append(req)
            path = req.url.path
            if base_path and path.startswith(base_path):
                path = path[len(base_path):] or "/"
            params: dict[str, Any] = {}
            for k, v in req.url.params.multi_items():
                params[k] = [*params[k], v] if isinstance(params.get(k), list) else ([params[k], v] if k in params else v)
            body, form = None, None
            if req.content:
                ctype = req.headers.get("content-type", "")
                if "json" in ctype:
                    body = json.loads(req.content)
                else:
                    form = dict(parse_qsl(req.content.decode()))
            try:
                r = fixtures.request(req.method, path, params=params, json=body, data=form)
            except RateLimited:
                return httpx.Response(429, headers={"Retry-After": "0"})
            except AuthExpired:
                return httpx.Response(401)
            except PermissionDenied:
                return httpx.Response(403)
            except TransientError:
                return httpx.Response(503)
            except ConnectorError:
                return httpx.Response(404, json={"error": "no such route in the sample data"})
            if isinstance(r.body, (dict, list)):
                return httpx.Response(r.status, json=r.body, headers=r.headers)
            return httpx.Response(r.status, text="" if r.body is None else str(r.body), headers=r.headers)
        return handle

    for t in _transports(transport):
        t.client = httpx.Client(transport=httpx.MockTransport(responder(urlsplit(t.base_url).path.rstrip("/"))))
    conn = m.factory(_live_settings(name), transport)
    conn._manifest = m
    conn.budget.rate = 1e6
    return conn, requests, sign_ins


def _read(conn: Any, stream: str) -> list[Any]:
    out, cursor = [], None
    for _ in range(MAX_PAGES):
        page = conn.fetch_page(stream, cursor)
        out += list(page.records or [])
        if not page.more:
            return out
        cursor = page.next_cursor
    raise AssertionError(f"{conn.name}.{stream} did not end within {MAX_PAGES} pages")


def _normalised(conn: Any, stream: str, raws: list[Any]) -> list[tuple[str, str]]:
    return sorted((r.kind, json.dumps(r.keys if hasattr(r, "keys") and isinstance(r.keys, dict) else {}, sort_keys=True, default=str))
                  for raw in raws for r in conn.normalize(stream, raw))


# tools the platform calls over the network (the CSV ownership file and the SIEM push endpoint make no outbound call)
NO_NETWORK = {"cmdb_csv", "generic_siem"}
PULLING = sorted(n for n, m in MANIFESTS.items() if n not in NO_NETWORK and ConnectorRegistry.all_fake().get(n).streams)


@pytest.mark.parametrize("name", PULLING)
def test_a_live_connector_reads_over_http_what_it_reads_from_the_fixtures(name, monkeypatch):
    fake = ConnectorRegistry.all_fake().get(name)
    fake.budget.rate = 1e6
    live, requests, _ = _wire(name, monkeypatch)
    assert tuple(live.streams) == tuple(fake.streams)
    for stream in fake.streams:
        expected = _read(fake, stream)
        got = _read(live, stream)
        assert got == expected, f"{name}.{stream}: live read {len(got)} record(s), the fixtures hold {len(expected)}"
        assert _normalised(live, stream, got) == _normalised(fake, stream, expected)
    if requests:
        # every call carried the tool's credentials: a header, or the key some APIs take in the query string
        bare = [f"{r.method} {r.url.path}" for r in requests
                if not ({"authorization", "x-api-key", "apikey", "key", "auth-key", "x-apikey"} & {h.lower() for h in r.headers})
                and "auth_token" not in r.url.params and "apiKey" not in r.url.params]
        public = {"nvd", "epss", "cisa_kev"}                    # public feeds (NVD's key is optional)
        assert not bare or name in public, f"{name}: request(s) without credentials: {bare[:3]}"


def test_a_sign_in_that_cannot_complete_is_a_connector_error(monkeypatch):
    """The token endpoint is the first thing a live tool calls. Blocked by the firewall it raised httpx's own error:
    the preflight called that "a defect in the connector" and code that degrades on ConnectorError crashed. A
    throttled or failing identity provider was not retried, and a page from a proxy was a JSON error."""
    from soc_platform.connectors.preflight import _classify

    auth = OAuth2ClientCredentials("https://login.example/token", "id", "secret")
    calls: list[int] = []

    def post(answer):
        def f(url, **kw):
            calls.append(1)
            if isinstance(answer, Exception):
                raise answer
            return answer
        monkeypatch.setattr("soc_platform.connectors.http.httpx.post", f)

    post(httpx.ConnectError("[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed"))
    with pytest.raises(TransientError) as e:
        auth.token()
    _status, detail, fix = _classify(e.value, [])
    assert "could not be reached" in detail and "SSL_CERT_FILE" in fix and "defect" not in fix

    post(httpx.ConnectTimeout("timed out"))
    with pytest.raises(TransientError) as e:
        auth.token()
    assert "allow-list" in _classify(e.value, [])[2]

    post(httpx.Response(429, headers={"Retry-After": "3"}))
    with pytest.raises(RateLimited) as r:
        auth.token()
    assert r.value.retry_after == 3
    post(httpx.Response(503))
    with pytest.raises(TransientError):
        auth.token()

    post(httpx.Response(401, json={"error": "invalid_client", "error_description": "AADSTS7000215: Invalid client secret provided.\r\nTrace ID: abc"}))
    with pytest.raises(AuthExpired) as a:
        auth.token()
    assert "invalid_client" in str(a.value) and "AADSTS7000215" in str(a.value) and "Trace ID" not in str(a.value)
    assert "client id / secret" in _classify(a.value, [])[2]

    post(httpx.Response(200, text="<html><body>Sign in to the proxy</body></html>", headers={"content-type": "text/html"}))
    with pytest.raises(ConnectorError) as c:
        auth.token()
    assert "HTML page" in str(c.value) and "proxy" in _classify(c.value, [])[2]
    post(httpx.Response(200, json={"token_type": "Bearer"}))
    with pytest.raises(ConnectorError, match="without a token"):
        auth.token()

    post(httpx.Response(200, json={"access_token": "t1", "expires_in": "3600"}))      # a lifetime sent as text
    assert auth.token() == "t1"
    before = len(calls)
    assert auth.token() == "t1" and len(calls) == before                               # cached, not fetched again


def test_a_sign_in_outage_is_retried_then_recovers(monkeypatch):
    """A connector call whose sign-in meets a brief outage succeeds once the identity provider answers again."""
    answers = [httpx.ConnectError("connection reset"), httpx.Response(502),
               httpx.Response(200, json={"access_token": "tok", "expires_in": 3600})]

    def post(url, **kw):
        a = answers.pop(0)
        if isinstance(a, Exception):
            raise a
        return a

    monkeypatch.setattr("soc_platform.connectors.http.httpx.post", post)
    monkeypatch.setattr("soc_platform.connectors.base.time.sleep", lambda _s: None)
    t = HttpTransport("https://api.example", OAuth2ClientCredentials("https://login.example/token", "id", "secret"))
    seen = []
    t.client = httpx.Client(transport=httpx.MockTransport(
        lambda req: (seen.append(req.headers.get("authorization")), httpx.Response(200, json={"ok": True}))[1]))
    conn = ConnectorRegistry.all_fake().get("canary")
    conn.http = t
    assert conn.get("/x") == {"ok": True} and seen == ["Bearer tok"] and not answers


def test_a_next_link_is_followed_only_to_the_tools_own_hosts():
    """Credentials go to the configured host, and - for the Defender API, which Microsoft serves from several hosts -
    to those; never to a host a response merely names."""
    from soc_platform.connectors.tools._microsoft import MDE_HOSTS

    hosts = []

    def handler(req):
        hosts.append(req.url.host)
        return httpx.Response(200, json={"value": []})

    t = HttpTransport("https://api.security.microsoft.com", sibling_hosts=MDE_HOSTS)
    t.client = httpx.Client(transport=httpx.MockTransport(handler))
    for ok in ("https://eu.api.security.microsoft.com/api/machines?$skip=10000",
               "https://api-eu.securitycenter.microsoft.com/api/machines?$skip=10000",
               "https://api.security.microsoft.com/api/alerts?$skiptoken=x"):
        t.request("GET", ok)
    for bad in ("https://api.security.microsoft.com.evil.example/api/machines",
                "https://evil.example/api.security.microsoft.com", "http://eu.api.security.microsoft.com/api/machines",
                "https://eu.api.security.microsoft.com:8443/api/machines", "https://notsecuritycenter.microsoft.com.evil.example/x"):
        with pytest.raises(ConnectorError, match="refused to follow"):
            t.request("GET", bad)
    assert hosts == ["eu.api.security.microsoft.com", "api-eu.securitycenter.microsoft.com", "api.security.microsoft.com"]
    plain = HttpTransport("https://graph.microsoft.com")
    with pytest.raises(ConnectorError, match="refused to follow"):
        plain.request("GET", "https://eu.api.security.microsoft.com/api/machines")


def test_entra_reads_azure_roles_when_the_azure_base_is_configured(monkeypatch):
    """With ``arm_base`` set (a national cloud) the Azure role look-ups were still addressed to the worldwide host,
    which the transport built for the configured base refused as another origin - and the tokens were requested for
    the worldwide audience from the worldwide sign-in host."""
    fake = ConnectorRegistry.all_fake().get("entra")
    fake.budget.rate = 1e6
    live, requests, sign_ins = _wire("entra", monkeypatch)             # _live_settings gives graph / arm / login bases
    settings = _live_settings("entra")
    a, b = fake.lookup("user", "jane.doe@acme-demo.com"), live.lookup("user", "jane.doe@acme-demo.com")
    assert a.signals["azure_privileged_roles"] and b.signals == a.signals and b.summary == a.summary
    assert urlsplit(settings["arm_base"]).hostname in {r.url.host for r in requests}
    assert sign_ins and all(u.startswith(settings["login_base"]) for u in sign_ins)
