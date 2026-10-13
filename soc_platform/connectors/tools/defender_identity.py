"""Microsoft Defender for Identity via Microsoft Graph (on-premises Active Directory identity signals).

Read:
  * ``alerts`` - Defender for Identity alerts (Graph ``security/alerts_v2``, service source
    ``microsoftDefenderForIdentity``), resumed from the newest ``lastUpdateDateTime``.
  * ``logon_events`` - ``IdentityLogonEvents`` through Defender XDR advanced hunting (Graph ``runHuntingQuery``):
    domain-controller authentications (success / failure, protocol, source device), resumed from the newest event time.
Write: none - containment of an identity goes through Entra ID (session revoke, password reset).

People are linked by the on-premises SID (``AccountSid``), which the directory maps to the Entra user
(``onPremisesSecurityIdentifier``): a directory mapping, never name similarity. A logon event is evidence, not an
alert: it raises no risk on its own (a failed logon is not a compromise).
"""

from __future__ import annotations

from typing import Any

from soc_platform.connectors.base import Page
from soc_platform.connectors.registry import ConfigField, ConnectorManifest
from soc_platform.connectors.tools._common import Watermark, need, parse_ts, sev_name, source_verdict
from soc_platform.connectors.tools._microsoft import APP_FIELDS, MicrosoftConnector, graph_transport
from soc_platform.core.identity import is_builtin, user_ref
from soc_platform.core.schema import EntityRef, NormalizedRecord

PORTAL = "https://security.microsoft.com"
LOGON_COLUMNS = ("Timestamp, ReportId, ActionType, Application, LogonType, Protocol, FailureReason, AccountName, "
                 "AccountDomain, AccountUpn, AccountSid, AccountObjectId, AccountDisplayName, DeviceName, IPAddress, "
                 "DestinationDeviceName, DestinationIPAddress")


class DefenderIdentityConnector(MicrosoftConnector):
    name = "defender_identity"
    tool = "defender_identity"
    dimension = "identity"
    streams = ("alerts", "logon_events")
    read_scopes = ("SecurityAlert.Read.All", "ThreatHunting.Read.All")
    write_scopes = ()

    @property
    def page_size(self) -> int:
        return max(1, int(self.settings.get("hunting_page_size") or 1000))

    # ------------------------------------------------------------------ streams

    def fetch_page(self, stream: str, cursor: str | None) -> Page:
        if stream == "alerts":
            return self.odata_page("/v1.0/security/alerts_v2", cursor,
                                   {"$filter": "serviceSource eq 'microsoftDefenderForIdentity'", "$top": 100},
                                   watermark="lastUpdateDateTime")
        if stream == "logon_events":
            return self._logon_page(cursor)
        raise ValueError(stream)

    def _logon_page(self, cursor: str | None) -> Page:
        """Hunting results do not page: each call asks from a time, oldest first, at most ``page_size`` rows. A full
        page continues from its newest row's exact time ("at:", also a valid resume point if the sync stops there) -
        without the between-syncs overlap, which would re-read the same first rows and stall a busy stream. Rows at
        that exact time are read again and ingest ignores them (idempotent by ReportId)."""
        wm = Watermark.of(self, "logon_events")
        if cursor and cursor.startswith("at:"):
            since: str | None = cursor[3:]
            wm.see([{"Timestamp": since}], "Timestamp")
        else:
            since = wm.start(cursor)
        days = int(self.settings.get("lookback_days") or 7)
        when = f"Timestamp >= datetime({since})" if since else f"Timestamp > ago({days}d)"
        rows = self.graph_hunt(f"IdentityLogonEvents | where {when}\n| order by Timestamp asc | take {self.page_size}\n"
                               f"| project {LOGON_COLUMNS}")
        before = parse_ts(since) if since else None
        wm.see(rows, "Timestamp")
        if len(rows) >= self.page_size and wm.best is not None and wm.best != before:
            return Page(rows, "at:" + wm.finish()[6:], has_more=True)
        return Page(rows, wm.finish(), has_more=False, reset=True)

    def normalize(self, stream: str, raw: dict[str, Any]) -> list[NormalizedRecord]:
        if stream == "alerts":
            return [self._alert(raw)]
        return [self._logon(raw)]

    # ------------------------------------------------------------------ normalisers

    def _person(self, *, sid: Any = None, upn: Any = None, object_id: Any = None, name: Any = None,
                domain: Any = None, role: str = "user") -> EntityRef | None:
        if (name and is_builtin(str(name))) or (upn and is_builtin(str(upn))):
            return None                       # built-in and machine accounts are not people
        keys = {k: v for k, v in (("sid", sid), ("upn", upn), ("entra_object_id", object_id)) if v}
        if keys:
            attrs = {"display_name": name, "account_domain": domain} if name else {}
            return EntityRef(kind="identity", role=role, keys=keys, attributes={k: v for k, v in attrs.items() if v})
        return user_ref(f"{domain}\\{name}" if domain and name else name, role=role,
                        default_domain=self.settings.get("user_domain"))

    def _alert(self, a: dict[str, Any]) -> NormalizedRecord:
        refs: list[EntityRef] = []
        for ev in a.get("evidence") or []:
            t = ev.get("@odata.type", "")
            if t.endswith("userEvidence"):
                acc = ev.get("userAccount") or {}
                ref = self._person(sid=acc.get("userSid"), upn=acc.get("userPrincipalName"),
                                   object_id=acc.get("azureAdUserId"), name=acc.get("accountName"),
                                   domain=acc.get("domainName"))
                if ref is not None:
                    refs.append(ref)
            elif t.endswith("deviceEvidence"):
                keys = {k: v for k, v in (("mde_device_id", ev.get("mdeDeviceId")),
                                          ("aad_device_id", ev.get("azureAdDeviceId"))) if v}
                if keys or ev.get("deviceDnsName"):
                    refs.append(EntityRef(kind="asset", role="host", keys=keys,
                                          attributes={"hostname": ev.get("deviceDnsName"),
                                                      "ip": (ev.get("ipInterfaces") or [None])[0]}))
            elif t.endswith("ipEvidence") and ev.get("ipAddress"):
                refs.append(EntityRef(kind="indicator", role="observable", keys={"value": ev["ipAddress"]},
                                      attributes={"type": "ip"}))
        return NormalizedRecord(
            kind="alert", tool=self.tool, source_type="alert_v2", source_id=need(a, "id"), dimension="identity",
            observed_at=parse_ts(a.get("createdDateTime")), title=a.get("title") or "Defender for Identity alert",
            severity=sev_name(a.get("severity")), refs=refs,
            attributes={"category": a.get("category"), "status": a.get("status"),
                        "source_verdict": source_verdict(a.get("classification"), a.get("determination")),
                        "mitre_techniques": a.get("mitreTechniques") or [], "incident_id": a.get("incidentId"),
                        "description": a.get("description"), "detection_source": a.get("detectionSource")},
            deep_link=a.get("alertWebUrl") or f"{PORTAL}/alerts")

    def _logon(self, r: dict[str, Any]) -> NormalizedRecord:
        refs: list[EntityRef] = []
        person = self._person(sid=r.get("AccountSid"), upn=r.get("AccountUpn"), object_id=r.get("AccountObjectId"),
                              name=r.get("AccountName"), domain=r.get("AccountDomain"))
        if person is not None:
            refs.append(person)
        if r.get("DeviceName") or r.get("IPAddress"):
            refs.append(EntityRef(kind="asset", role="source_host",
                                  attributes={"hostname": r.get("DeviceName"), "ip": r.get("IPAddress")}))
        # the domain controller stays an attribute: a host known only by name must not become an asset of its own
        failed = str(r.get("ActionType") or "").lower() == "logonfailed"
        return NormalizedRecord(
            kind="signin", tool=self.tool, source_type="identity_logon", source_id=str(need(r, "ReportId")),
            dimension="identity", observed_at=parse_ts(r.get("Timestamp")),
            title=f"Domain logon {'failure' if failed else 'success'} ({r.get('Protocol') or 'unknown protocol'})",
            severity="informational", refs=refs,
            attributes={"action": r.get("ActionType"), "protocol": r.get("Protocol"), "logon_type": r.get("LogonType"),
                        "failure": r.get("FailureReason"), "application": r.get("Application"),
                        "ip": r.get("IPAddress"), "domain_controller": r.get("DestinationDeviceName")},
            deep_link=f"{PORTAL}/v2/advanced-hunting")


MANIFEST = ConnectorManifest(
    name="defender_identity", tool="Microsoft Defender for Identity", vendor="Microsoft", category="identity",
    dimension="identity",
    description="On-premises Active Directory identity alerts and domain logon events (Defender XDR, through Graph).",
    factory=lambda s, t: DefenderIdentityConnector(s, t, rate_per_sec=2, burst=5),
    live_transport=graph_transport,
    config=APP_FIELDS + [
        ConfigField("user_domain", "UPN suffix for bare account names", required=False),
        ConfigField("lookback_days", "Days of logon events read on the first sync (default 7)", required=False,
                    kind="int"),
        ConfigField("hunting_page_size", "Rows per advanced-hunting call (default 1000)", required=False, kind="int"),
        ConfigField("graph_base", "Microsoft Graph base (national clouds only)", required=False, kind="url")],
    confidence="Medium",
    to_confirm="Defender for Identity licence and sensor coverage of the domain controllers; Graph app permissions "
               "SecurityAlert.Read.All and ThreatHunting.Read.All",
    fake_settings={"tenant_id": "demo-tenant", "user_domain": "acme-demo.com"},
    focus_areas=("incident",),
)
