"""Wiz connector (VM-T01, IM-T01, U03). GraphQL API with a service account.

Streams: cloud resources (VMs/containers), vulnerability findings, issues (misconfiguration
and toxic-combination findings, used for the cloud misconfiguration use case U03).
"""

from __future__ import annotations

from typing import Any

from soc_platform.connectors.base import LookupResult, Page
from soc_platform.connectors.http import HttpTransport, OAuth2ClientCredentials
from soc_platform.connectors.registry import ConfigField, ConnectorManifest
from soc_platform.connectors.tools._common import ToolConnector, ok_lookup, parse_ts, sev_name
from soc_platform.core.schema import EntityRef, NormalizedRecord

Q_RESOURCES = """query CloudResources($first: Int, $after: String) {
  cloudResources(first: $first, after: $after, filterBy: {type: [VIRTUAL_MACHINE, CONTAINER_IMAGE]}) {
    nodes { id name type externalId providerUniqueId region subscriptionExternalId updatedAt
            graphEntity { properties } }
    pageInfo { hasNextPage endCursor } totalCount } }"""
Q_VULNS = """query VulnerabilityFindings($first: Int, $after: String) {
  vulnerabilityFindings(first: $first, after: $after, filterBy: {status: [OPEN]}) {
    nodes { id name CVSSSeverity score exploitabilityScore hasExploit hasCisaKevExploit status firstDetectedAt
            lastDetectedAt fixedVersion detailedName version remediation portalUrl
            vulnerableAsset { ... on VulnerableAssetVirtualMachine { id name type providerUniqueId ipAddresses
                              operatingSystem hasWideInternetExposure } } }
    pageInfo { hasNextPage endCursor } } }"""
Q_VULNS_BY_CVE = Q_VULNS.replace("VulnerabilityFindings($first: Int, $after: String)",
                                 "VulnerabilityFindingsByCve($first: Int, $after: String, $cve: [String!])") \
    .replace("filterBy: {status: [OPEN]}", "filterBy: {status: [OPEN], vulnerabilityExternalId: $cve}")
Q_ISSUES = """query Issues($first: Int, $after: String) {
  issuesV2(first: $first, after: $after, filterBy: {status: [OPEN, IN_PROGRESS]}) {
    nodes { id severity status createdAt type sourceRule { name } entitySnapshot { id name type providerId region
            cloudPlatform subscriptionExternalId } }
    pageInfo { hasNextPage endCursor } } }"""


class WizConnector(ToolConnector):
    name = "wiz"
    tool = "wiz"
    dimension = "cloud"
    streams = ("resources", "vulnerabilities", "issues")
    lookups = ("host", "cve")
    read_scopes = ("read:resources", "read:vulnerabilities", "read:issues")

    def gql(self, query: str, variables: dict[str, Any]) -> dict[str, Any]:
        body = self.post("/graphql", json={"query": query, "variables": variables})
        if body.get("errors"):
            raise RuntimeError(f"Wiz GraphQL error: {body['errors'][0].get('message')}")
        return body.get("data") or {}

    def fetch_page(self, stream: str, cursor: str | None) -> Page:
        q, key = {"resources": (Q_RESOURCES, "cloudResources"), "vulnerabilities": (Q_VULNS, "vulnerabilityFindings"),
                  "issues": (Q_ISSUES, "issuesV2")}[stream]
        data = self.gql(q, {"first": 500, "after": cursor})[key]
        info = data.get("pageInfo") or {}
        return Page(data.get("nodes") or [], info.get("endCursor") or cursor, source_total=data.get("totalCount"),
                    has_more=bool(info.get("hasNextPage")))

    def normalize(self, stream: str, raw: dict[str, Any]) -> list[NormalizedRecord]:
        if stream == "resources":
            props = (raw.get("graphEntity") or {}).get("properties") or {}
            return [NormalizedRecord(
                kind="asset", tool=self.tool, source_type="cloud_resource", source_id=raw["id"], dimension="cloud",
                observed_at=parse_ts(raw.get("updatedAt") or props.get("updatedAt")),
                keys={"wiz_id": raw["id"], "cloud_resource_id": raw.get("providerUniqueId") or raw.get("externalId")},
                attributes={"hostname": props.get("hostname") or raw.get("name"), "ip": (props.get("privateIpAddresses") or [None])[0],
                            "ips": props.get("privateIpAddresses") or [], "os": props.get("operatingSystem"),
                            "cloud_type": raw.get("type"), "region": raw.get("region"),
                            "subscription": raw.get("subscriptionExternalId"),
                            "internet_exposed": bool(props.get("hasWideInternetExposure"))},
                deep_link=f"https://app.wiz.io/graph#~(entity~'{raw['id']})")]
        if stream == "vulnerabilities":
            va = raw.get("vulnerableAsset") or {}
            return [NormalizedRecord(
                kind="finding", tool=self.tool, source_type="vulnerability_finding", source_id=raw["id"],
                observed_at=parse_ts(raw.get("lastDetectedAt")), title=f"{raw.get('name')} on {va.get('name')}",
                severity=sev_name(raw.get("CVSSSeverity")), dimension="exposure",
                refs=[EntityRef(kind="asset", role="host",
                                keys={"wiz_id": va.get("id"), "cloud_resource_id": va.get("providerUniqueId")},
                                attributes={"hostname": va.get("name"), "ip": (va.get("ipAddresses") or [None])[0],
                                            "os": va.get("operatingSystem")})],
                attributes={"cve": raw.get("name") if str(raw.get("name", "")).startswith("CVE-") else None,
                            "cvss": raw.get("score"), "has_exploit": raw.get("hasExploit"),
                            "kev": raw.get("hasCisaKevExploit"), "status": "open", "first_seen": raw.get("firstDetectedAt"),
                            "product": f"{raw.get('detailedName', '')} {raw.get('version', '')}".strip(),
                            "fixed_version": raw.get("fixedVersion"), "remediation": raw.get("remediation"),
                            "internet_exposed": bool(va.get("hasWideInternetExposure"))},
                deep_link=raw.get("portalUrl"))]
        es = raw.get("entitySnapshot") or {}
        return [NormalizedRecord(
            kind="cloud_issue", tool=self.tool, source_type="issue", source_id=raw["id"], dimension="cloud",
            observed_at=parse_ts(raw.get("createdAt")), title=(raw.get("sourceRule") or {}).get("name", "Wiz issue"),
            severity=sev_name(raw.get("severity")),
            refs=[EntityRef(kind="asset", role="resource", keys={"wiz_id": es.get("id"), "cloud_resource_id": es.get("providerId")},
                            attributes={"hostname": es.get("name")})],
            attributes={"status": raw.get("status"), "issue_type": raw.get("type"), "resource_type": es.get("type"),
                        "cloud": es.get("cloudPlatform"), "region": es.get("region"),
                        "subscription": es.get("subscriptionExternalId")},
            deep_link=f"https://app.wiz.io/issues#~(issue~'{raw['id']})")]

    def _all(self, query: str, key: str, variables: dict[str, Any] | None = None) -> tuple[list[dict[str, Any]], bool]:
        """Follow pageInfo cursors up to ``lookup_max_pages``; returns (nodes, truncated)."""
        nodes: list[dict[str, Any]] = []
        after = None
        for _ in range(int(self.settings.get("lookup_max_pages") or 20)):
            data = self.gql(query, {"first": 500, "after": after, **(variables or {})}).get(key) or {}
            nodes += data.get("nodes") or []
            info = data.get("pageInfo") or {}
            if not info.get("hasNextPage"):
                return nodes, False
            after = info.get("endCursor")
        return nodes, True

    def lookup(self, entity_type: str, value: str, **context: Any) -> LookupResult:
        def run() -> LookupResult:
            if entity_type == "host":
                data, truncated = self._all(Q_VULNS, "vulnerabilityFindings")
                mine = [n for n in data if str((n.get("vulnerableAsset") or {}).get("name", "")).lower().split(".")[0]
                        == value.lower().split(".")[0]]
                recs = [r for n in mine for r in self.normalize("vulnerabilities", n)]
                exposed = any((n.get("vulnerableAsset") or {}).get("hasWideInternetExposure") for n in mine)
                return ok_lookup(self, recs, f"Wiz: {len(mine)} open vulnerability finding(s); "
                                             f"internet-exposed={exposed}" + (" (partial: page limit)" if truncated else ""),
                                 findings=len(mine), internet_exposed=exposed, truncated=truncated)
            if entity_type == "cve":
                data, truncated = self._all(Q_VULNS_BY_CVE, "vulnerabilityFindings", {"cve": [value.upper()]})
                hits = [n for n in data if str(n.get("name", "")).upper() == value.upper()]
                assets = sorted({(n.get("vulnerableAsset") or {}).get("name") for n in hits} - {None})
                return ok_lookup(self, [r for n in hits for r in self.normalize("vulnerabilities", n)],
                                 f"{value}: {len(hits)} Wiz finding(s) on {len(assets)} asset(s)",
                                 findings=len(hits), assets=assets, truncated=truncated)
            raise ValueError(entity_type)

        return self.timed_lookup(run)


def _live(s: dict[str, Any]) -> HttpTransport:
    return HttpTransport(s["api_url"], OAuth2ClientCredentials(
        s.get("auth_url") or "https://auth.app.wiz.io/oauth/token", s["client_id"], s["client_secret"],
        extra={"audience": "wiz-api"}))


MANIFEST = ConnectorManifest(
    name="wiz", tool="Wiz", vendor="Wiz", category="cloud", dimension="cloud",
    description="Cloud inventory, vulnerability findings, internet exposure and misconfiguration issues (GraphQL).",
    factory=lambda s, t: WizConnector(s, t, rate_per_sec=3, burst=6), live_transport=_live,
    config=[ConfigField("api_url", "Tenant API endpoint, e.g. https://api.eu1.app.wiz.io"),
            ConfigField("client_id", "Service account client id", secret=True),
            ConfigField("client_secret", "Service account secret", secret=True),
            ConfigField("auth_url", "Token URL", required=False),
            ConfigField("lookup_max_pages", "Max GraphQL pages per lookup (default 20)", required=False)],
    confidence="High", to_confirm="Service account provisioning; scope of cloud coverage",
    focus_areas=("vulnerability", "incident"),
)
