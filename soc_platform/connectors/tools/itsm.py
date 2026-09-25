"""ITSM / case management and CMDB connectors (VM-T10, IM-T10, VM-F07, D06, D07).

CCI's ITSM, case-management and CMDB systems are unconfirmed (Q03, Q13), so three
interchangeable implementations share one interface:

  * ``servicenow``  - Table API (incident / sn_vul ticket tables, cmdb_ci)
  * ``jira``        - Jira Cloud REST v3 issues
  * ``cmdb_csv``    - a maintained CSV/XLSX-export ownership mapping (fallback for A04)

Every ticketing connector exposes ``create_ticket`` / ``update_ticket`` / ``get_ticket``
and the action types ``ticket.create`` / ``ticket.update``; every CMDB connector exposes
``owner_for(asset attributes)`` - so the VM/IM workflows never depend on the product.
"""

from __future__ import annotations

import csv
from pathlib import Path
from typing import Any

from soc_platform.connectors.base import LookupResult, Page
from soc_platform.connectors.http import BasicAuth, HttpTransport, NoAuth, OAuth2ClientCredentials
from soc_platform.connectors.registry import ConfigField, ConnectorManifest
from soc_platform.connectors.tools._common import ConnectorAction, ToolConnector, ok_lookup, parse_ts
from soc_platform.core.schema import NormalizedRecord

_SN_STATE = {"1": "new", "2": "in_progress", "3": "on_hold", "6": "resolved", "7": "closed", "8": "cancelled"}


class ServiceNowConnector(ToolConnector):
    name = "servicenow"
    tool = "servicenow"
    dimension = "ticketing"
    streams = ("tickets", "cmdb")
    lookups = ("host",)

    @property
    def table(self) -> str:
        return self.settings.get("ticket_table") or "incident"

    def fetch_page(self, stream: str, cursor: str | None) -> Page:
        offset = int(cursor or 0)
        table = self.table if stream == "tickets" else (self.settings.get("cmdb_table") or "cmdb_ci_computer")
        q = "sys_updated_on>javascript:gs.daysAgoStart(30)" if stream == "tickets" else ""
        body = self.get(f"/api/now/table/{table}", params={"sysparm_offset": offset, "sysparm_limit": 500,
                                                           "sysparm_query": q, "sysparm_display_value": "true"})
        rows = body.get("result") or []
        return Page(rows, str(offset + len(rows)), has_more=len(rows) == 500)

    def normalize(self, stream: str, r: dict[str, Any]) -> list[NormalizedRecord]:
        if stream == "cmdb":
            return [NormalizedRecord(
                kind="asset", tool=self.tool, source_type="cmdb_ci", source_id=r["sys_id"], dimension="ticketing",
                observed_at=parse_ts(r.get("sys_updated_on")),
                keys={"serial_number": r.get("serial_number"), "mac": r.get("mac_address")},
                attributes={"hostname": r.get("name"), "fqdn": r.get("fqdn") or None, "ip": r.get("ip_address"),
                            "os": r.get("os"), "owner": _dv(r.get("owned_by")), "support_group": _dv(r.get("support_group")),
                            "environment": r.get("environment") or r.get("used_for"),
                            "criticality": (r.get("business_criticality") or "").lower() or None,
                            "location": _dv(r.get("location"))})]
        return [NormalizedRecord(
            kind="ticket", tool=self.tool, source_type=self.table, source_id=r["sys_id"], dimension="ticketing",
            observed_at=parse_ts(r.get("sys_updated_on")), title=f"{r.get('number')}: {r.get('short_description')}",
            attributes={"number": r.get("number"), "state": _SN_STATE.get(str(r.get("state")), r.get("state")),
                        "assignment_group": _dv(r.get("assignment_group")), "correlation_id": r.get("correlation_id")})]

    # ticketing interface ------------------------------------------------------------------
    def create_ticket(self, *, title: str, description: str, group: str | None, priority: int = 3,
                      correlation_id: str | None = None, extra: dict[str, Any] | None = None) -> dict[str, Any]:
        body = self.post(f"/api/now/table/{self.table}", json={
            "short_description": title[:160], "description": description, "assignment_group": group,
            "priority": str(priority), "correlation_id": correlation_id, **(extra or {})})
        r = body.get("result") or {}
        return {"ticket_id": r.get("sys_id"), "number": r.get("number"), "url":
                f"{self.settings.get('instance_url', '')}/nav_to.do?uri={self.table}.do?sys_id={r.get('sys_id')}"}

    def update_ticket(self, ticket_id: str, *, comment: str | None = None, state: str | None = None) -> dict[str, Any]:
        payload: dict[str, Any] = {}
        if comment:
            payload["work_notes"] = comment
        if state:
            payload["state"] = {v: k for k, v in _SN_STATE.items()}.get(state, state)
        return self.req("PATCH", f"/api/now/table/{self.table}/{ticket_id}", json=payload).body.get("result") or {}

    def get_ticket(self, ticket_id: str) -> dict[str, Any]:
        r = self.get(f"/api/now/table/{self.table}/{ticket_id}").get("result") or {}
        return {"ticket_id": ticket_id, "number": r.get("number"), "state": _SN_STATE.get(str(r.get("state")), r.get("state")),
                "assignment_group": _dv(r.get("assignment_group")), "updated": r.get("sys_updated_on")}

    # CMDB interface -----------------------------------------------------------------------
    def owner_for(self, attrs: dict[str, Any]) -> dict[str, Any] | None:
        name = str(attrs.get("hostname") or "").split(".")[0]
        if not name:
            return None
        rows = self.get(f"/api/now/table/{self.settings.get('cmdb_table') or 'cmdb_ci_computer'}",
                        params={"sysparm_query": f"name={name}", "sysparm_display_value": "true", "sysparm_limit": 1}).get("result") or []
        if not rows:
            return None
        r = rows[0]
        return {"owner": _dv(r.get("owned_by")), "platform_team": _dv(r.get("support_group")),
                "environment": r.get("environment") or r.get("used_for"),
                "criticality": (r.get("business_criticality") or "").lower() or None, "location": _dv(r.get("location")),
                "source": "servicenow_cmdb"}

    def lookup(self, entity_type: str, value: str, **context: Any) -> LookupResult:
        return self.timed_lookup(lambda: ok_lookup(self, [], f"CMDB: {self.owner_for({'hostname': value}) or 'no CI found'}"))


class JiraConnector(ToolConnector):
    name = "jira"
    tool = "jira"
    dimension = "ticketing"
    streams = ("tickets",)

    def fetch_page(self, stream: str, cursor: str | None) -> Page:
        project = self.settings.get("project_key", "SEC")
        params = {"jql": f'project = "{project}" AND updated >= -30d ORDER BY updated ASC',
                  "maxResults": 100, "fields": "summary,status,components,updated,priority,resolution"}
        if cursor:
            params["nextPageToken"] = cursor
        body = self.get("/rest/api/3/search/jql", params=params)
        nxt = None if body.get("isLast", True) else body.get("nextPageToken")
        return Page(body.get("issues") or [], nxt, has_more=bool(nxt))

    def normalize(self, stream: str, i: dict[str, Any]) -> list[NormalizedRecord]:
        f = i.get("fields") or {}
        return [NormalizedRecord(kind="ticket", tool=self.tool, source_type="issue", source_id=i["id"], dimension="ticketing",
                                 observed_at=parse_ts(f.get("updated")), title=f"{i.get('key')}: {f.get('summary')}",
                                 attributes={"number": i.get("key"), "state": ((f.get("status") or {}).get("name") or "").lower(),
                                             "assignment_group": (f.get("components") or [{}])[0].get("name")})]

    def create_ticket(self, *, title: str, description: str, group: str | None, priority: int = 3,
                      correlation_id: str | None = None, extra: dict[str, Any] | None = None) -> dict[str, Any]:
        body = self.post("/rest/api/3/issue", json={"fields": {
            "project": {"key": self.settings.get("project_key", "SEC")}, "summary": title[:250],
            "issuetype": {"name": self.settings.get("issue_type", "Task")},
            "description": {"type": "doc", "version": 1, "content": [{"type": "paragraph", "content": [
                {"type": "text", "text": description[:30000]}]}]},
            "labels": [x for x in ["soc-platform", correlation_id] if x],
            **({"components": [{"name": group}]} if group else {})}})
        return {"ticket_id": body.get("id"), "number": body.get("key"),
                "url": f"{self.settings.get('base_url', '')}/browse/{body.get('key')}"}

    def update_ticket(self, ticket_id: str, *, comment: str | None = None, state: str | None = None) -> dict[str, Any]:
        if comment:
            self.post(f"/rest/api/3/issue/{ticket_id}/comment", json={"body": {"type": "doc", "version": 1, "content": [
                {"type": "paragraph", "content": [{"type": "text", "text": comment}]}]}})
        return {"ticket_id": ticket_id}

    def get_ticket(self, ticket_id: str) -> dict[str, Any]:
        i = self.get(f"/rest/api/3/issue/{ticket_id}")
        return self.normalize("tickets", i)[0].attributes | {"ticket_id": ticket_id}


class CsvCmdbConnector(ToolConnector):
    """Ownership mapping from a maintained CSV (hostname/pattern -> owner, platform team, env, criticality)."""

    name = "cmdb_csv"
    tool = "cmdb_csv"
    dimension = "ticketing"
    streams = ("cmdb",)
    lookups = ("host",)

    def rows(self) -> list[dict[str, str]]:
        p = self.settings.get("path")
        if p and Path(p).exists():
            return list(csv.DictReader(Path(p).open(encoding="utf-8")))
        return (self.http.request("GET", "/ownership").body or {}).get("rows", []) if self.http else []

    def fetch_page(self, stream, cursor):
        return Page(self.rows(), None, has_more=False)

    def normalize(self, stream, r):
        host = str(r.get("hostname") or "").strip()
        if not host or any(ch in host for ch in "*?[]"):
            return []  # ownership *rules* (patterns / subscriptions) are used by owner_for, they are not assets
        return [NormalizedRecord(kind="asset", tool=self.tool, source_type="ownership", source_id=r["hostname"],
                                 keys={"serial_number": r.get("serial_number")}, dimension="ticketing",
                                 attributes={"hostname": r["hostname"], "owner": r.get("owner"),
                                             "platform_team": r.get("platform_team"), "environment": r.get("environment"),
                                             "criticality": r.get("criticality")})]

    def owner_for(self, attrs: dict[str, Any]) -> dict[str, Any] | None:
        import fnmatch

        host = str(attrs.get("hostname") or attrs.get("fqdn") or "").lower().split(".")[0]
        sub = str(attrs.get("subscription") or "").lower()
        for r in self.rows():
            if host and r.get("hostname") and fnmatch.fnmatch(host, r["hostname"].lower()):
                return {"owner": r.get("owner"), "platform_team": r.get("platform_team"),
                        "environment": r.get("environment"), "criticality": r.get("criticality"), "source": "cmdb_csv"}
        for r in self.rows():  # cloud resources without a CI: owner of the subscription / account
            if sub and r.get("subscription") and fnmatch.fnmatch(sub, str(r["subscription"]).lower()):
                return {"owner": r.get("owner"), "platform_team": r.get("platform_team"),
                        "environment": r.get("environment"), "criticality": r.get("criticality"), "source": "cmdb_csv"}
        return None

    def lookup(self, entity_type, value, **context):
        return self.timed_lookup(lambda: ok_lookup(self, [], f"ownership: {self.owner_for({'hostname': value}) or 'unknown'}"))


def _dv(v: Any) -> Any:
    return v.get("display_value") if isinstance(v, dict) else v


def _ticket_actions(c: Any) -> list:
    def create(params: dict, targets: list) -> dict:
        return {"provider": c.name} | c.create_ticket(title=params["title"], description=params.get("description", ""),
                               group=params.get("group"), priority=int(params.get("priority", 3)),
                               correlation_id=params.get("correlation_id"))

    def update(params: dict, targets: list) -> dict:
        return c.update_ticket(params["ticket_id"], comment=params.get("comment"), state=params.get("state"))

    return [ConnectorAction("ticket.create", c, create, description=f"Create {c.tool} ticket"),
            ConnectorAction("ticket.update", c, update, description=f"Update {c.tool} ticket")]


def _sn_live(s: dict[str, Any]) -> HttpTransport:
    base = s["instance_url"].rstrip("/")
    auth = (OAuth2ClientCredentials(f"{base}/oauth_token.do", s["client_id"], s["client_secret"])
            if s.get("client_id") else BasicAuth(s["username"], s["password"]))
    return HttpTransport(base, auth)


MANIFESTS = [
    ConnectorManifest(
        name="servicenow", tool="ServiceNow (ITSM + CMDB)", vendor="ServiceNow", category="itsm", dimension="ticketing",
        description="Remediation/incident tickets with bidirectional status; CMDB ownership and criticality.",
        factory=lambda s, t: ServiceNowConnector(s, t, rate_per_sec=3, burst=6), live_transport=_sn_live,
        config=[ConfigField("instance_url", "https://<instance>.service-now.com"),
                ConfigField("client_id", "OAuth client id", secret=True, required=False),
                ConfigField("client_secret", "OAuth client secret", secret=True, required=False),
                ConfigField("username", "Basic-auth integration user", secret=True, required=False),
                ConfigField("password", "Basic-auth password", secret=True, required=False),
                ConfigField("ticket_table", "incident | sn_vul_vulnerable_item | custom", required=False),
                ConfigField("cmdb_table", "CMDB CI table", required=False)],
        actions=_ticket_actions, confidence="Unknown", to_confirm="Which ITSM system; API access; workflow ownership (Q03)",
        fake_settings={"instance_url": "https://cci-demo.service-now.com"},
        focus_areas=("vulnerability", "incident")),
    ConnectorManifest(
        name="jira", tool="Jira (ITSM)", vendor="Atlassian", category="itsm", dimension="ticketing",
        description="Remediation tickets as Jira issues with comments/status sync.",
        factory=lambda s, t: JiraConnector(s, t, rate_per_sec=3, burst=6),
        live_transport=lambda s: HttpTransport(s["base_url"], BasicAuth(s["email"], s["api_token"])),
        config=[ConfigField("base_url", "https://<site>.atlassian.net"), ConfigField("email", "Integration user email"),
                ConfigField("api_token", "API token", secret=True), ConfigField("project_key", "Project key", required=False)],
        actions=_ticket_actions, confidence="Unknown", to_confirm="Only if CCI uses Jira (Q03)",
        focus_areas=("vulnerability", "incident")),
    ConnectorManifest(
        name="cmdb_csv", tool="Ownership mapping (CSV)", vendor="internal", category="cmdb", dimension="ticketing",
        description="Maintained hostname-pattern to owner/platform-team/criticality mapping (fallback for A04/D06).",
        factory=lambda s, t: CsvCmdbConnector(s, t, rate_per_sec=100, burst=100),
        live_transport=lambda s: HttpTransport("http://localhost", NoAuth()),
        config=[ConfigField("path", "CSV path: hostname,owner,platform_team,environment,criticality,serial_number")],
        confidence="High", focus_areas=("vulnerability", "incident")),
]
