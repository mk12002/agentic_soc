"""Delinea Secret Server and Privilege Manager connectors (IM-T01, IM-F04 privileged access, IM-F09, U07).

Secret Server: secret access audit, privileged session activity, credential rotation.
Privilege Manager: elevation / application-control events.
Endpoints follow the documented REST APIs; exact report/event endpoints vary by
version and must be verified against CCI's deployment (section 10: Medium).
"""

from __future__ import annotations

from typing import Any

from soc_platform.connectors.base import LookupResult, Page
from soc_platform.connectors.http import HttpTransport, OAuth2ClientCredentials
from soc_platform.connectors.registry import ConfigField, ConnectorManifest
from soc_platform.connectors.tools._common import ConnectorAction, ToolConnector, ok_lookup, parse_ts
from soc_platform.core.schema import EntityRef, NormalizedRecord

SENSITIVE_ACTIONS = {"VIEW", "COPY PASSWORD", "LAUNCH", "CHECK OUT", "PASSWORD DISPLAYED", "EXPORT"}


def _uref(username: str | None, domain: str | None) -> EntityRef | None:
    if not username:
        return None
    u = username.split("\\")[-1]
    keys = {"upn": u.lower()} if "@" in u else ({"upn": f"{u}@{domain}".lower()} if domain else {})
    return EntityRef(kind="identity", role="user", keys=keys, attributes={"display_name": u})


class SecretServerConnector(ToolConnector):
    name = "delinea_secret_server"
    tool = "delinea_secret_server"
    dimension = "privileged_access"
    streams = ("secret_audits",)
    lookups = ("user",)
    read_scopes = ("View Secret Audit", "View Launched Sessions")
    write_scopes = ("Change Password Now on target secrets",)

    def fetch_page(self, stream: str, cursor: str | None) -> Page:
        skip = int(cursor or 0)
        body = self.get("/api/v1/secret-audits", params={"skip": skip, "take": 500,
                                                         "filter.startDate": self.settings.get("sync_from", "")})
        rows = body.get("records") or []
        return Page(rows, str(skip + len(rows)), source_total=body.get("total"), has_more=bool(body.get("hasNext")))

    def normalize(self, stream: str, r: dict[str, Any]) -> list[NormalizedRecord]:
        refs = [x for x in [_uref(r.get("byUserName") or r.get("userName"), self.settings.get("user_domain"))] if x]
        if r.get("machineName"):
            refs.append(EntityRef(kind="asset", role="source_host", attributes={"hostname": r["machineName"],
                                                                                 "ip": r.get("ipAddress")}))
        action = str(r.get("action", "")).upper()
        return [NormalizedRecord(
            kind="secret_access", tool=self.tool, source_type="secret_audit",
            source_id=str(r.get("secretAuditId") or f"{r.get('secretId')}:{r.get('dateRecorded')}"),
            observed_at=parse_ts(r.get("dateRecorded")), title=f"{action.title()} secret '{r.get('secretName')}'",
            severity="medium" if action in SENSITIVE_ACTIONS else "informational", dimension="privileged_access",
            refs=refs, attributes={"secret_id": r.get("secretId"), "secret_name": r.get("secretName"), "action": action,
                                   "folder": r.get("folderPath"), "notes": r.get("notes"), "ip": r.get("ipAddress")},
            deep_link=f"{self.settings.get('base_url', '')}/app/#/secrets/{r.get('secretId')}/audit")]

    def lookup(self, entity_type: str, value: str, **context: Any) -> LookupResult:
        def run() -> LookupResult:
            user = value.split("@")[0]
            body = self.get("/api/v1/secret-audits", params={"filter.userName": user, "take": 100})
            rows = body.get("records") or []
            recs = [r for row in rows for r in self.normalize("secret_audits", row)]
            sensitive = [r for r in rows if str(r.get("action", "")).upper() in SENSITIVE_ACTIONS]
            sessions = self.get("/api/v1/launched-sessions", params={"filter.userName": user}).get("records") or []
            standing = self.get("/api/v1/users", params={"filter.searchText": user}).get("records") or []
            admin = any(u.get("isApplicationAccount") is False and u.get("adminRoles") for u in standing)
            return ok_lookup(self, recs, f"{len(rows)} secret audit event(s), {len(sensitive)} credential access(es) "
                                         f"({sorted({r.get('secretName') for r in sensitive})}); "
                                         f"{len(sessions)} privileged session(s); standing admin role: {admin}",
                             sensitive_access=len(sensitive), standing_admin=admin,
                             secrets=sorted({str(r.get("secretId")) for r in sensitive}))

        return self.timed_lookup(run)

    def rotate(self, params: dict, targets: list) -> dict:
        ids = [t["secret_id"] for t in targets if t.get("type") == "secret" and t.get("secret_id")]
        for sid in ids:
            self.post(f"/api/v1/secrets/{sid}/change-password", json={"newPassword": None, "autoChangeNextPassword": True})
        return {"rotated": ids}


class PrivilegeManagerConnector(ToolConnector):
    name = "delinea_privilege_manager"
    tool = "delinea_privilege_manager"
    dimension = "privileged_access"
    streams = ("elevation_events",)
    lookups = ("user", "host")

    def fetch_page(self, stream: str, cursor: str | None) -> Page:
        body = self.get("/Tms/api/v1/events/elevation", params={"after": cursor or "", "take": 500})
        rows = body.get("items") or []
        return Page(rows, str(body.get("lastId") or cursor or ""), has_more=bool(body.get("hasMore")))

    def normalize(self, stream: str, e: dict[str, Any]) -> list[NormalizedRecord]:
        refs = [x for x in [_uref(e.get("userName"), self.settings.get("user_domain"))] if x]
        if e.get("computerName"):
            refs.append(EntityRef(kind="asset", role="host", attributes={"hostname": e["computerName"]}))
        denied = str(e.get("outcome", "")).lower() in {"denied", "blocked"}
        return [NormalizedRecord(
            kind="elevation", tool=self.tool, source_type="elevation_event", source_id=str(e["id"]),
            observed_at=parse_ts(e.get("eventTime")), title=f"Elevation {e.get('outcome')}: {e.get('applicationName')}",
            severity="medium" if denied else "informational", dimension="privileged_access", refs=refs,
            attributes={"application": e.get("applicationName"), "outcome": e.get("outcome"), "policy": e.get("policyName"),
                        "justification": e.get("justification"), "file_hash": e.get("fileHash")})]

    def lookup(self, entity_type: str, value: str, **context: Any) -> LookupResult:
        def run() -> LookupResult:
            key = "userName" if entity_type == "user" else "computerName"
            rows = self.get("/Tms/api/v1/events/elevation", params={key: value.split("@")[0], "take": 100}).get("items") or []
            recs = [r for row in rows for r in self.normalize("elevation_events", row)]
            denied = [r for r in rows if str(r.get("outcome", "")).lower() in {"denied", "blocked"}]
            return ok_lookup(self, recs, f"{len(rows)} elevation event(s), {len(denied)} denied",
                             elevation_denied=len(denied))

        return self.timed_lookup(run)


def _ss_actions(c: SecretServerConnector) -> list:
    return [ConnectorAction("pam.rotate_secret", c, c.rotate, description="Rotate secret credential (Change Password Now)",
                            preconditions=lambda p, t: [] if any(x.get("secret_id") for x in t) else ["no secret ids"])]


def _ss_live(s: dict[str, Any]) -> HttpTransport:
    base = s["base_url"].rstrip("/")
    return HttpTransport(base, OAuth2ClientCredentials(f"{base}/oauth2/token", s["username"], s["password"],
                                                       grant_type="password",
                                                       extra={"username": s["username"], "password": s["password"]}))


def _pm_live(s: dict[str, Any]) -> HttpTransport:
    base = s["base_url"].rstrip("/")
    return HttpTransport(base, OAuth2ClientCredentials(f"{base}/Tms/oauth2/token", s["client_id"], s["client_secret"]))


MANIFESTS = [
    ConnectorManifest(
        name="delinea_secret_server", tool="Delinea Secret Server", vendor="Delinea", category="pam",
        dimension="privileged_access",
        description="Secret access audit, privileged sessions, standing privilege; credential rotation.",
        factory=lambda s, t: SecretServerConnector(s, t, rate_per_sec=2, burst=4), live_transport=_ss_live,
        config=[ConfigField("base_url", "Secret Server URL"), ConfigField("username", "API user", secret=True),
                ConfigField("password", "API user password", secret=True),
                ConfigField("user_domain", "UPN suffix", required=False)],
        actions=_ss_actions, confidence="Medium",
        to_confirm="API access approval - privileged access data needs extra governance",
        fake_settings={"user_domain": "cci-demo.com", "base_url": "https://pam.cci-demo.com/SecretServer"},
        focus_areas=("incident",)),
    ConnectorManifest(
        name="delinea_privilege_manager", tool="Delinea Privilege Manager", vendor="Delinea", category="pam",
        dimension="privileged_access", description="Elevation and application-control events.",
        factory=lambda s, t: PrivilegeManagerConnector(s, t, rate_per_sec=2, burst=4), live_transport=_pm_live,
        config=[ConfigField("base_url", "Privilege Manager URL"), ConfigField("client_id", "API client id", secret=True),
                ConfigField("client_secret", "API client secret", secret=True),
                ConfigField("user_domain", "UPN suffix", required=False)],
        confidence="Medium", to_confirm="API access approval and available event granularity",
        fake_settings={"user_domain": "cci-demo.com", "base_url": "https://pam.cci-demo.com/SecretServer"},
        focus_areas=("incident",)),
]
