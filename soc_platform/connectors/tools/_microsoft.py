"""Shared Microsoft Graph / Defender API helpers (OData paging, advanced hunting)."""

from __future__ import annotations

from typing import Any

from soc_platform.connectors.base import Page
from soc_platform.connectors.http import HttpTransport, entra_app_auth
from soc_platform.connectors.registry import ConfigField
from soc_platform.connectors.tools._common import ToolConnector

GRAPH = "https://graph.microsoft.com"
MDE = "https://api.securitycenter.microsoft.com"

APP_FIELDS = [
    ConfigField("tenant_id", "Entra tenant id"),
    ConfigField("client_id", "App registration (client) id", secret=True),
    ConfigField("client_secret", "App registration secret (prefer certificate-based auth in prod)", secret=True),
]


def graph_transport(settings: dict[str, Any]) -> HttpTransport:
    return HttpTransport(settings.get("graph_base") or GRAPH,
                         entra_app_auth(settings["tenant_id"], settings["client_id"], settings["client_secret"],
                                        "https://graph.microsoft.com/.default"))


def mde_transport(settings: dict[str, Any]) -> HttpTransport:
    return HttpTransport(settings.get("mde_base") or MDE,
                         entra_app_auth(settings["tenant_id"], settings["client_id"], settings["client_secret"],
                                        "https://api.securitycenter.microsoft.com/.default"))


class MicrosoftConnector(ToolConnector):
    def odata_page(self, path: str, cursor: str | None, params: dict[str, Any] | None = None) -> Page:
        """First call uses ``path``+``params``; subsequent pages follow ``@odata.nextLink``.
        A trailing ``@odata.deltaLink`` (delta queries) becomes the resume cursor."""
        if cursor and cursor.startswith("http"):
            body = self.get(cursor)
        else:
            body = self.get(path, params=params or {})
        items = body.get("value", [])
        nxt = body.get("@odata.nextLink")
        delta = body.get("@odata.deltaLink")
        return Page(items, nxt or delta or cursor, has_more=bool(nxt))

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
