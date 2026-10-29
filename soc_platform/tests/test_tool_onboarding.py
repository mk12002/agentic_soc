"""Vendor API behaviour found when each tool's integration was checked against its documentation before onboarding:
every test here failed (or could not be written) against the earlier connector code."""

from __future__ import annotations

import base64
import json
import re
import time
from datetime import UTC, datetime, timedelta
from itertools import pairwise

import pytest

from soc_platform.connectors.base import PermissionDenied
from soc_platform.connectors.http import FixtureTransport
from soc_platform.connectors.registry import ConnectorRegistry


@pytest.fixture()
def reg() -> ConnectorRegistry:
    return ConnectorRegistry.all_fake()


# ---------------------------------------------------------------------------------------------- Microsoft


def test_defender_findbyip_is_called_as_an_odata_function_with_a_timestamp(reg):
    """GET /api/machines/findbyip(ip='{IP}',timestamp={time}) - query parameters are not what the API takes."""
    conn = reg.get("defender_endpoint")
    calls = []
    real = conn.http.request

    def spy(method, path, **kw):
        calls.append((path, kw.get("params")))
        return real(method, path, **kw)

    conn.http.request = spy
    r = conn.lookup("ip", "10.20.1.15", at=datetime(2026, 9, 20, 9, 0, tzinfo=UTC))
    assert r.ok and r.records
    path, params = next(c for c in calls if "findbyip" in c[0])
    assert path == "/api/machines/findbyip(ip='10.20.1.15',timestamp=2026-09-20T09:00:00Z)" and not params


def test_defender_for_endpoint_uses_the_current_host_and_the_documented_token_audience(monkeypatch):
    from soc_platform.connectors.tools import _microsoft

    seen = {}
    monkeypatch.setattr(_microsoft, "entra_app_auth_from", lambda s, scope: seen.setdefault("scope", scope))
    t = _microsoft.mde_transport({"tenant_id": "t"})
    assert t.base_url == "https://api.security.microsoft.com"
    assert seen["scope"] == "https://api.securitycenter.microsoft.com/.default"


def test_registered_devices_come_from_the_audit_log_because_graph_refuses_app_access_to_device_lists(reg):
    entra = reg.get("entra")
    ctx = entra.identity_context("jane.doe@acme-demo.com", since_iso="2026-09-19T00:00:00Z")
    assert [d["displayName"] for d in ctx["new_devices"]] == ["DESKTOP-7H2K9Q"]
    assert entra.identity_context("bob.lee@acme-demo.com", since_iso="2026-09-19T00:00:00Z")["new_devices"] == []
    assert not any("registeredDevices" in c["path"] or "ownedDevices" in c["path"] for c in entra.http.calls)
    sent = next(c["params"]["$filter"] for c in entra.http.calls
                if c["path"].endswith("directoryAudits") and "registered owner" in str((c["params"] or {}).get("$filter")))
    assert sent == "activityDisplayName eq 'Add registered owner to device' and activityDateTime ge 2026-09-19T00:00:00Z"


def test_one_unlicensed_or_refused_part_does_not_fail_an_identity_lookup(reg):
    """Identity Protection without Entra ID P2, or a mailbox outside the app's scope, answers 403: the rest stays."""
    entra = reg.get("entra")
    entra.http.routes.insert(0, ("GET", re.compile(r"^/v1.0/identityProtection/riskyUsers$"),
                                 {"method": "GET", "path": "x", "status": 403, "body": {"error": "not licensed"}}))
    entra.http.routes.insert(0, ("GET", re.compile(r"/mailFolders/inbox/messageRules$"),
                                 {"method": "GET", "path": "x", "status": 403, "body": {}}))
    ctx = entra.identity_context("jane.doe@acme-demo.com")
    assert ctx["risky"] is None and ctx["inbox_rules"] == [] and ctx["signins"]
    assert sorted(u.split(" ")[0] for u in ctx["unavailable"]) == ["risky", "rules"]
    r = entra.lookup("user", "jane.doe@acme-demo.com")
    assert r.ok and "unavailable: " in r.summary
    entra.http.routes.insert(0, ("GET", re.compile(r"^/v1.0/users/jane.doe@acme-demo.com$"),
                                 {"method": "GET", "path": "x", "status": 403, "body": {}}))
    with pytest.raises(PermissionDenied):                     # the person themselves is not optional
        entra.identity_context("jane.doe@acme-demo.com")


def test_entra_needs_the_membership_permissions_or_role_names_come_back_blank():
    from soc_platform.connectors.tools.entra import EntraConnector

    assert {"GroupMember.Read.All", "RoleManagement.Read.Directory"} <= set(EntraConnector.read_scopes)


def test_audit_log_and_identity_protection_calls_keep_to_graphs_per_tenant_limits(reg, monkeypatch):
    """Sign-in / audit logs: 5 requests per 10 s; Identity Protection: 1 per second (no Retry-After on its 429s)."""
    from soc_platform.connectors.base import TokenBucket

    entra = reg.get("entra")
    taken: list[str] = []
    real = TokenBucket.acquire

    def acquire(self, timeout=30.0):
        taken.append(f"{self.rate}/{self.capacity}")
        return real(self, timeout)

    monkeypatch.setattr(TokenBucket, "acquire", acquire)
    fake = entra.http
    entra.http = type("Live", (), {"request": lambda s, m, p, **kw: fake.request(m, p, **kw)})()   # not a fixture
    entra.get("/v1.0/auditLogs/signIns", params={"$top": 1})
    entra.get("/v1.0/identityProtection/riskyUsers")
    entra.get("/v1.0/users", params={"$top": 1})
    assert taken.count("0.5/5") == 1 and taken.count("1.0/1") == 1    # one family bucket each, besides the overall one


# ---------------------------------------------------------------------------------------------- CrowdStrike


def test_rtr_collection_reads_each_queued_commands_output_and_closes_the_session(reg):
    cs = reg.get("crowdstrike")
    out = cs.rtr_collect({"commands": ["ps"]}, [{"type": "asset", "crowdstrike_aid": "cs-aid-jane01"}])
    result = out["collected"]["cs-aid-jane01"][0]
    assert result["complete"] and "powershell.exe" in result["stdout"] and result["cloud_request_id"] == "rtr-req-001"
    paths = [(c["method"], c["path"]) for c in cs.http.calls]
    assert ("GET", "/real-time-response/entities/command/v1") in paths
    assert paths[-1] == ("DELETE", "/real-time-response/entities/sessions/v1")


def test_rtr_without_a_session_says_why_instead_of_running_commands_nowhere(reg):
    cs = reg.get("crowdstrike")
    cs.http = FixtureTransport([{"method": "POST", "path": "^/real-time-response/entities/sessions/v1$",
                                 "body": {"resources": [], "errors": [{"message": "device offline"}]}}], "crowdstrike")
    from soc_platform.connectors.base import ConnectorError

    with pytest.raises(ConnectorError, match="response policy"):
        cs.rtr_collect({}, [{"type": "asset", "crowdstrike_aid": "cs-aid-x"}])


# ---------------------------------------------------------------------------------------------- NVD


def test_nvd_asks_with_both_dates_in_windows_of_at_most_120_days(monkeypatch):
    """NVD refuses lastModStartDate without lastModEndDate, and any range over 120 days."""
    from soc_platform.connectors.tools.vuln_intel import NvdConnector

    monkeypatch.setenv("SOC_CLOCK_FREEZE", "2026-10-29T00:00:00+00:00")
    t = FixtureTransport([{"method": "GET", "path": "^/rest/json/cves/2.0$", "body": {"totalResults": 0, "vulnerabilities": []}}],
                         "nvd")
    conn = NvdConnector({"since": "2026-01-01T00:00:00Z"}, t)
    windows, cursor = [], None
    for _ in range(10):
        page = conn.fetch_page("recent_cves", cursor)
        p = t.calls[-1]["params"]
        start, end = datetime.fromisoformat(p["lastModStartDate"]), datetime.fromisoformat(p["lastModEndDate"])
        windows.append((start, end))
        assert end - start <= timedelta(days=120) and p["lastModStartDate"].endswith(".000+00:00")
        if not page.more:
            break
        cursor = page.next_cursor
    assert windows[0][0] == datetime(2026, 1, 1, tzinfo=UTC) and windows[-1][1] == datetime(2026, 10, 29, tzinfo=UTC)
    assert all(a[1] == b[0] for a, b in pairwise(windows))       # contiguous, no gap
    assert len(windows) == 3


# ---------------------------------------------------------------------------------------------- Avanan


def _jwt(exp: float) -> str:
    part = base64.urlsafe_b64encode(json.dumps({"exp": exp}).encode()).decode().rstrip("=")
    return f"h.{part}.s"


def test_avanan_renews_its_token_before_the_tokens_own_expiry_and_on_a_401(monkeypatch):
    from soc_platform.connectors.tools import avanan

    issued = []

    class R:
        status_code = 200

        def __init__(self, tok):
            self.tok = tok

        def json(self):
            return {"data": {"token": self.tok}}

    def post(url, json=None, timeout=None):
        tok = _jwt(time.time() + 1800)                    # Infinity Portal tokens last about 30 minutes
        issued.append(tok)
        return R(tok)

    monkeypatch.setattr(avanan.httpx, "post", post)
    auth = avanan.HecAuth("https://gw.example", "id", "key")
    h: dict = {}
    auth.apply(h, {})
    assert auth._exp < time.time() + 1800 and auth._exp > time.time() + 1500      # renewed 2 minutes early, not at 50
    auth.apply(h, {})
    assert len(issued) == 1                                                       # reused while valid
    auth.invalidate()                                                             # what the transport does on a 401
    auth.apply(h, {})
    assert len(issued) == 2 and h["Authorization"] == f"Bearer {issued[-1]}"
