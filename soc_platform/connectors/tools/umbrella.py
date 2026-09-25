"""Cisco Umbrella connector (IM-T01, PH-F06, PH-F11, IM-F09, U11).

Read: Reports API v2 DNS / proxy activity (did the user actually reach the site?),
domain categorisation. Write (policy-gated): add / remove domains in a block
destination list via the Policies API.
"""

from __future__ import annotations

from typing import Any

from soc_platform.connectors.base import LookupResult, Page
from soc_platform.connectors.http import HttpTransport, OAuth2ClientCredentials
from soc_platform.connectors.registry import ConfigField, ConnectorManifest
from soc_platform.connectors.tools._common import ConnectorAction, ToolConnector, ok_lookup, parse_ts
from soc_platform.core.identity import user_ref
from soc_platform.core.schema import EntityRef, NormalizedRecord

API = "https://api.umbrella.com"


class UmbrellaConnector(ToolConnector):
    name = "umbrella"
    tool = "umbrella"
    dimension = "dns"
    streams = ("dns_activity",)
    lookups = ("domain", "host", "ip")
    read_scopes = ("reports.aggregations:read", "reports.customerDNS:read", "policies.destinationLists:read")
    write_scopes = ("policies.destinations:write",)

    def fetch_page(self, stream: str, cursor: str | None) -> Page:
        offset = int(cursor or 0)
        body = self.get("/reports/v2/activity/dns", params={"from": self.settings.get("sync_from", "-1days"), "to": "now",
                                                            "limit": 1000, "offset": offset})
        rows = body.get("data") or []
        return Page(rows, str(offset + len(rows)), has_more=len(rows) == 1000)

    def normalize(self, stream: str, raw: dict[str, Any]) -> list[NormalizedRecord]:
        ident = next((i for i in raw.get("identities") or [] if (i.get("type") or {}).get("type") in {"roaming", "anyconnect",
                                                                                                          "network_devices"}), {})
        user = next((i for i in raw.get("identities") or [] if (i.get("type") or {}).get("type") in {"directory_user"}), {})
        refs = [EntityRef(kind="indicator", role="destination", keys={"value": raw.get("domain", "")}, attributes={"type": "domain"})]
        if ident.get("label"):
            refs.append(EntityRef(kind="asset", role="host", attributes={"hostname": ident["label"],
                                                                          "ip": raw.get("internalip")}))
        u = user_ref(user.get("label"))
        if u is not None and u.keys.get("upn"):  # Umbrella directory labels are only trusted when they carry a UPN
            refs.append(u)
        ts = raw.get("timestamp") or f"{raw.get('date')}T{raw.get('time')}Z"
        return [NormalizedRecord(
            kind="dns", tool=self.tool, source_type="dns_request",
            source_id=f"{ts}|{raw.get('internalip')}|{raw.get('domain')}", observed_at=parse_ts(ts),
            title=f"DNS {raw.get('verdict')} {raw.get('domain')}",
            severity="high" if any(c.get("type") == "security" for c in raw.get("categories") or [])
            and raw.get("verdict") == "allowed" else "informational",
            dimension="dns", refs=refs,
            attributes={"domain": raw.get("domain"), "verdict": raw.get("verdict"), "internal_ip": raw.get("internalip"),
                        "external_ip": raw.get("externalip"), "query_type": raw.get("querytype"),
                        "categories": [c.get("label") for c in raw.get("categories") or []],
                        "identity": ident.get("label"), "user": user.get("label")},
            deep_link="https://dashboard.umbrella.com/o/reports/activity-search")]

    def activity(self, *, domain: str | None = None, identity: str | None = None, ip: str | None = None,
                 since: str = "-7days") -> list[dict[str, Any]]:
        params: dict[str, Any] = {"from": since, "to": "now", "limit": 500}
        if domain:
            params["domains"] = domain
        if ip:
            params["ip"] = ip
        if identity:
            params["identityids"] = identity
        return self.get("/reports/v2/activity/dns", params=params).get("data") or []

    def activity_all(self, *, since: str = "-7days", max_rows: int = 50_000) -> tuple[list[dict[str, Any]], bool]:
        """Every DNS activity row in the window (offset paging); returns (rows, truncated)."""
        rows: list[dict[str, Any]] = []
        offset = 0
        while len(rows) < max_rows:
            page = self.get("/reports/v2/activity/dns", params={"from": since, "to": "now", "limit": 1000,
                                                                "offset": offset}).get("data") or []
            rows += page
            if len(page) < 1000:
                return rows, False
            offset += len(page)
        return rows[:max_rows], True

    def lookup(self, entity_type: str, value: str, **context: Any) -> LookupResult:
        def run() -> LookupResult:
            if entity_type == "domain":
                rows = self.activity(domain=value, since=context.get("since", "-7days"))
                allowed = [r for r in rows if r.get("verdict") == "allowed"]
                ids = sorted({i.get("label") for r in rows for i in r.get("identities") or []})
                recs = [x for r in rows for x in self.normalize("dns_activity", r)]
                return ok_lookup(self, recs, f"{value}: {len(rows)} request(s) ({len(allowed)} allowed, "
                                             f"{len(rows) - len(allowed)} blocked) from {ids or 'no identities'}",
                                 requests=len(rows), allowed=len(allowed), identities=ids)
            if entity_type in {"host", "ip"}:
                rows = self.activity(ip=value) if entity_type == "ip" else [
                    r for r in self.activity() if any(str(i.get("label", "")).lower() == value.lower()
                                                      for i in r.get("identities") or [])]
                security = [r for r in rows if any(c.get("type") == "security" for c in r.get("categories") or [])]
                recs = [x for r in security for x in self.normalize("dns_activity", r)]
                return ok_lookup(self, recs, f"{len(rows)} DNS request(s); {len(security)} to security-categorised "
                                             f"destinations: {sorted({r.get('domain') for r in security})}",
                                 security_requests=len(security),
                                 allowed=sum(1 for r in security if r.get("verdict") == "allowed"))
            raise ValueError(entity_type)

        return self.timed_lookup(run)

    def block(self, params: dict, targets: list) -> dict:
        dl = self.settings.get("block_list_id")
        domains = [t["value"] for t in targets if t.get("type") == "indicator" and t.get("indicator_type") in {"domain", "url"}]
        body = self.post(f"/policies/v2/destinationlists/{dl}/destinations",
                         json=[{"destination": d, "comment": params.get("reason", "SOC platform")} for d in domains])
        return {"blocked": domains, "destination_list": dl, "response": body}

    def unblock(self, params: dict, targets: list) -> dict:
        dl = self.settings.get("block_list_id")
        domains = [t["value"] for t in targets if t.get("type") == "indicator"]
        current = self.get(f"/policies/v2/destinationlists/{dl}/destinations").get("data") or []
        ids = [c["id"] for c in current if c.get("destination") in domains]
        self.req("DELETE", f"/policies/v2/destinationlists/{dl}/destinations/remove", json=ids)
        return {"unblocked": domains}


def _has_domain(params: dict, targets: list) -> list[str]:
    return [] if any(t.get("type") == "indicator" and t.get("indicator_type") in {"domain", "url"} for t in targets) \
        else ["no domain/url indicator targets"]


def _actions(c: UmbrellaConnector) -> list:
    return [ConnectorAction("dns.block_domain", c, c.block, preconditions=_has_domain, reverse_type="dns.unblock_domain",
                            description="Add domain to Umbrella block destination list"),
            ConnectorAction("dns.unblock_domain", c, c.unblock, preconditions=_has_domain,
                            description="Remove domain from Umbrella block destination list")]


def _live(s: dict[str, Any]) -> HttpTransport:
    return HttpTransport(API, OAuth2ClientCredentials(f"{API}/auth/v2/token", s["api_key"], s["api_secret"], basic=True))


MANIFEST = ConnectorManifest(
    name="umbrella", tool="Cisco Umbrella", vendor="Cisco", category="dns", dimension="dns",
    description="DNS/proxy activity (did the user reach the site?), categories, domain blocking via destination lists.",
    factory=lambda s, t: UmbrellaConnector(s, t, rate_per_sec=3, burst=6), live_transport=_live,
    config=[ConfigField("api_key", "Umbrella API key", secret=True), ConfigField("api_secret", "API secret", secret=True),
            ConfigField("block_list_id", "Destination list id used for blocks", required=False)],
    actions=_actions, confidence="Medium-High", to_confirm="API key provisioning; reporting retention window",
    fake_settings={"block_list_id": "blk-soc-001"},
    focus_areas=("phishing", "incident"),
)
