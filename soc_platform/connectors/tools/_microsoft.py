"""Shared Microsoft Graph / Defender API helpers (OData paging, advanced hunting)."""

from __future__ import annotations

from typing import Any

from soc_platform.connectors.base import Page
from soc_platform.connectors.http import HttpTransport, RoutingTransport, entra_app_auth_from
from soc_platform.connectors.registry import ConfigField
from soc_platform.connectors.tools._common import ToolConnector, Watermark

GRAPH = "https://graph.microsoft.com"
# Microsoft now documents api.security.microsoft.com (regional: us. / eu. / uk. / au.api.security.microsoft.com); the
# token is still issued for the securitycenter resource whichever host is called
MDE = "https://api.security.microsoft.com"
ARM = "https://management.azure.com"

APP_FIELDS = [
    ConfigField("tenant_id", "Entra tenant id"),
    ConfigField("client_id", "App registration (client) id", secret=True),
    ConfigField("client_secret", "App registration secret (or use client_certificate)", secret=True, required=False),
    ConfigField("client_certificate", "App registration certificate: one PEM with the private key and the certificate "
                "(recommended over a secret; mount it with <CONNECTOR>_CLIENT_CERTIFICATE_FILE)", secret=True,
                required=False),
    ConfigField("login_base", "Sign-in authority (national clouds only; default https://login.microsoftonline.com)",
                required=False, kind="url"),
]


def _base(settings: dict[str, Any], key: str, default: str) -> str:
    return str(settings.get(key) or default).rstrip("/")


def graph_transport(settings: dict[str, Any]) -> HttpTransport:
    # the token is asked for the host that is called: a national cloud's Graph refuses the worldwide one's token
    base = _base(settings, "graph_base", GRAPH)
    return HttpTransport(base, entra_app_auth_from(settings, f"{base}/.default"))


def graph_and_arm_transport(settings: dict[str, Any]) -> RoutingTransport:
    """Graph for Entra, plus Azure Resource Manager (own token audience) for Azure role assignments."""
    base = _base(settings, "arm_base", ARM)
    arm = HttpTransport(base, entra_app_auth_from(settings, f"{base}/.default"))
    return RoutingTransport(graph_transport(settings), {base: arm})


def arm_base(settings: dict[str, Any]) -> str:
    """Where Azure Resource Manager is called: the configured base, so the calls reach the transport built for it
    (with ``arm_base`` set they were still addressed to the worldwide host and refused as another origin)."""
    return _base(settings, "arm_base", ARM)


# The Defender API is served from several Microsoft hosts (global, regional, and the older securitycenter names), and
# a page's @odata.nextLink can name another of them than the one called. The token is for the same resource on all
# of them; a next link to any other host is still refused.
MDE_HOSTS = (".api.security.microsoft.com", "api.security.microsoft.com", ".securitycenter.microsoft.com",
             ".securitycenter.windows.com")


def mde_transport(settings: dict[str, Any]) -> HttpTransport:
    return HttpTransport(settings.get("mde_base") or MDE,
                         entra_app_auth_from(settings, "https://api.securitycenter.microsoft.com/.default"),
                         sibling_hosts=MDE_HOSTS)


def odata_page(conn: ToolConnector, path: str, cursor: str | None, params: dict[str, Any] | None = None, *,
               watermark: str | None = None, filter_field: str | None = None) -> Page:
    """One page of an OData list (Graph, Defender, Azure Resource Manager).

    The first call uses ``path`` + ``params``; later pages follow ``@odata.nextLink`` (``nextLink`` on ARM). When the
    list ends, the resume point is a ``@odata.deltaLink`` if the API gave one, else - for a stream with a
    ``watermark`` field - the newest value seen (``since:<time>``, sent next time as ``$filter=<field> ge <time>``),
    else nothing (the next sync reads the list again). A continuation link is never kept: they expire."""
    wm = Watermark.of(conn, path)
    if cursor and cursor.startswith("http"):
        body = conn.get(cursor)
    else:
        prm = dict(params or {})
        since = wm.start(cursor)
        if since and watermark:
            cond = f"{filter_field or watermark.replace('.', '/')} ge {since}"
            prm["$filter"] = f"({prm['$filter']}) and {cond}" if prm.get("$filter") else cond
        body = conn.get(path, params=prm)
    items = body.get("value") or []
    if watermark:
        wm.see(items, watermark)
    nxt = body.get("@odata.nextLink") or body.get("nextLink")
    if nxt:
        return Page(items, nxt, has_more=True)
    delta = body.get("@odata.deltaLink")
    return Page(items, delta or wm.finish(), has_more=False, reset=True)


class MicrosoftConnector(ToolConnector):
    def odata_page(self, path: str, cursor: str | None, params: dict[str, Any] | None = None, *,
                   watermark: str | None = None, filter_field: str | None = None) -> Page:
        return odata_page(self, path, cursor, params, watermark=watermark, filter_field=filter_field)

    def odata_all(self, path: str, params: dict[str, Any] | None = None, limit: int = 1000) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        cursor: str | None = None
        while len(out) < limit:
            page = self.odata_page(path, cursor, params)
            out += page.records
            if not page.more:
                break
            cursor = page.next_cursor
        return out[:limit]

    def graph_hunt(self, query: str) -> list[dict[str, Any]]:
        """Defender XDR advanced hunting through Graph (EmailEvents, UrlClickEvents, Device* tables)."""
        body = self.post("/v1.0/security/runHuntingQuery", json={"Query": query})
        return body.get("results") or body.get("Results") or []


def kql_str(v: str) -> str:
    return "'" + str(v).replace("\\", "\\\\").replace("'", "\\'") + "'"


def kql_list(values: list[str]) -> str:
    return "dynamic([" + ", ".join(kql_str(v) for v in values) + "])"
