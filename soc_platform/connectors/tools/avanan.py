"""Avanan / Check Point Harmony Email & Collaboration connector (PH-F01, PH-F04).

The least certain integration (section 10: Low-Medium). Implemented against the
Harmony Email & Collaboration (HEC) Smart API: security events, entity (email)
lookup with Avanan verdicts, and quarantine/restore actions. If the API is not
licensed, set ``fallback: shared_mailbox`` and ingest Avanan-reported items from the
SOC mailbox through the Defender for Office 365 connector instead.
"""

from __future__ import annotations

import time
import uuid
from typing import Any

import httpx

from soc_platform.connectors.base import ConnectorError, LookupResult, Page
from soc_platform.connectors.http import Auth, HttpTransport
from soc_platform.connectors.registry import ConfigField, ConnectorManifest
from soc_platform.connectors.tools._common import ConnectorAction, ToolConnector, ok_lookup, parse_ts, sev_name
from soc_platform.core.schema import EntityRef, NormalizedRecord


class HecAuth(Auth):
    """HEC Smart API: POST /auth/external with clientId/accessKey -> bearer token, plus request id header."""

    def __init__(self, base: str, client_id: str, access_key: str) -> None:
        self.base, self.client_id, self.access_key = base.rstrip("/"), client_id, access_key
        self._tok, self._exp = None, 0.0

    def apply(self, headers, params):
        if not self._tok or time.time() > self._exp:
            r = httpx.post(f"{self.base}/auth/external", json={"clientId": self.client_id, "accessKey": self.access_key},
                           timeout=30)
            if r.status_code >= 400:
                raise ConnectorError(f"Avanan auth failed {r.status_code}")
            self._tok, self._exp = r.json()["data"]["token"], time.time() + 3000
        headers["Authorization"] = f"Bearer {self._tok}"
        headers["x-av-req-id"] = str(uuid.uuid4())


class AvananConnector(ToolConnector):
    name = "avanan"
    tool = "avanan"
    dimension = "email"
    streams = ("security_events",)
    lookups = ("email_message", "domain")
    write_scopes = ("quarantine / restore",)

    def fetch_page(self, stream: str, cursor: str | None) -> Page:
        body = self.post("/app/hec-api/v1.0/event/query", json={"requestData": {
            "startDate": cursor or self.settings.get("sync_from", "2026-01-01T00:00:00Z"),
            "eventTypes": ["phishing", "malware", "suspicious_phishing", "suspicious_malware", "spam", "dlp"]}})
        events = (body.get("responseData") or [])
        last = max((e.get("eventCreated") or "" for e in events), default=cursor)
        return Page(events, last, has_more=False)

    def normalize(self, stream: str, e: dict[str, Any]) -> list[NormalizedRecord]:
        refs = []
        if e.get("senderAddress"):
            refs.append(EntityRef(kind="indicator", role="sender", keys={"value": e["senderAddress"]}, attributes={"type": "email"}))
        for r in e.get("recipients") or []:
            refs.append(EntityRef(kind="identity", role="recipient", keys={"upn": r}))
        return [NormalizedRecord(
            kind="mail_event", tool=self.tool, source_type="security_event", source_id=e["eventId"],
            observed_at=parse_ts(e.get("eventCreated")), title=e.get("description") or f"Avanan {e.get('type')}",
            severity=sev_name(e.get("severity")), dimension="email", refs=refs,
            attributes={"verdict": e.get("type"), "state": e.get("state"), "action_taken": e.get("actions"),
                        "entity_id": e.get("entityId"), "subject": e.get("subject"),
                        "internet_message_id": e.get("internetMessageId")},
            deep_link=e.get("entityLink"))]

    def verdict_for(self, internet_message_id: str) -> dict[str, Any] | None:
        """Avanan verdict + applied actions for one message (PH-F04 reconciliation)."""
        body = self.post("/app/hec-api/v1.0/search/query", json={"requestData": {"entityFilter": {
            "saas": "office365_emails", "extendedFilter": [{"saasAttrName": "entityPayload.internetMessageId",
                                                            "saasAttrOp": "is", "saasAttrValue": internet_message_id}]}}})
        items = body.get("responseData") or []
        if not items:
            return None
        it = items[0]
        info = it.get("entityInfo") or {}
        sec = it.get("entitySecurityResult") or {}
        return {"entity_id": info.get("entityId"), "verdict": (sec.get("combinedVerdict") or "").lower() or None,
                "engines": {k: (v or {}).get("verdict") for k, v in sec.items() if isinstance(v, dict)},
                "actions": [a.get("actionType") for a in it.get("entityActions") or []],
                "quarantined": any(a.get("actionType") == "quarantine" for a in it.get("entityActions") or [])}

    def lookup(self, entity_type: str, value: str, **context: Any) -> LookupResult:
        def run() -> LookupResult:
            if entity_type == "email_message":
                v = self.verdict_for(value)
                return ok_lookup(self, [], f"Avanan verdict={v['verdict']}, actions={v['actions']}" if v
                                 else "message not found in Avanan")
            body = self.post("/app/hec-api/v1.0/event/query", json={"requestData": {"senderDomain": value}})
            ev = body.get("responseData") or []
            return ok_lookup(self, [], f"{len(ev)} Avanan event(s) for sender domain {value}")

        return self.timed_lookup(run)

    def _action(self, action: str, targets: list) -> dict:
        ids = [t["avanan_entity_id"] for t in targets if t.get("avanan_entity_id")]
        body = self.post("/app/hec-api/v1.0/action/entity", json={"requestData": {
            "entityIds": ids, "entityActionName": action, "entityActionParam": ""}})
        return {"action": action, "entities": ids, "response": body}

    def quarantine(self, params: dict, targets: list) -> dict:
        return self._action("quarantine", targets)

    def restore(self, params: dict, targets: list) -> dict:
        return self._action("restore", targets)


def _has_entity(params: dict, targets: list) -> list[str]:
    return [] if any(t.get("avanan_entity_id") for t in targets) else ["no Avanan entity ids in targets"]


def _actions(c: AvananConnector) -> list:
    return [ConnectorAction("email.gateway_quarantine", c, c.quarantine, preconditions=_has_entity,
                            reverse_type="email.gateway_restore", description="Quarantine in Avanan"),
            ConnectorAction("email.gateway_restore", c, c.restore, preconditions=_has_entity,
                            description="Restore from Avanan quarantine")]


def _live(s: dict[str, Any]) -> HttpTransport:
    base = s.get("api_url") or "https://cloudinfra-gw.portal.checkpoint.com"
    return HttpTransport(base, HecAuth(base, s["client_id"], s["access_key"]))


MANIFEST = ConnectorManifest(
    name="avanan", tool="Avanan (Check Point Harmony Email)", vendor="Check Point", category="email", dimension="email",
    description="Security events, per-message verdicts and actions for reconciliation; quarantine/restore.",
    factory=lambda s, t: AvananConnector(s, t, rate_per_sec=2, burst=4), live_transport=_live,
    config=[ConfigField("api_url", "Smart API gateway URL (region specific)", required=False),
            ConfigField("client_id", "Infinity Portal API client id", secret=True),
            ConfigField("access_key", "API access key", secret=True),
            ConfigField("fallback", "shared_mailbox | export if the API is not licensed", required=False)],
    actions=_actions, confidence="Low-Medium",
    to_confirm="API availability and scope under current licence (fallbacks: journaling, shared mailbox, export)",
    focus_areas=("phishing",),
)
