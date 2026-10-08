"""Avanan / Check Point Harmony Email & Collaboration connector (PH-F01, PH-F04).

The least certain integration (section 10: Low-Medium). Implemented against the
Harmony Email & Collaboration (HEC) Smart API: security events, entity (email)
lookup with Avanan verdicts, and quarantine/restore actions. If the API is not
licensed, set ``fallback: shared_mailbox`` and ingest Avanan-reported items from the
SOC mailbox through the Defender for Office 365 connector instead.
"""

from __future__ import annotations

import logging
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from typing import Any

import httpx

from soc_platform.connectors.base import ConnectorError, LookupResult, Page
from soc_platform.connectors.http import Auth, HttpTransport
from soc_platform.connectors.registry import ConfigField, ConnectorManifest
from soc_platform.connectors.tools._common import ConnectorAction, ToolConnector, need, ok_lookup, parse_ts, sev_name
from soc_platform.core.models import utcnow
from soc_platform.core.schema import EntityRef, NormalizedRecord

log = logging.getLogger(__name__)

API = "/app/hec-api/v1.0"
SAAS = "office365_emails"
# HEC severities are strings "1".."5"
HEC_SEVERITY = {"1": "informational", "2": "low", "3": "medium", "4": "high", "5": "critical"}
# worst first: the overall verdict of a message is the worst verdict any engine gave it
VERDICT_ORDER = ("malicious", "phishing", "suspicious", "spam", "clean")


def overall_verdict(combined: dict[str, Any]) -> str | None:
    """``entitySecurityResult.combinedVerdict`` is one verdict per engine (ap, av, dlp, clicktimeProtection...)."""
    seen = {str(v).lower() for v in (combined or {}).values() if v}
    return next((v for v in VERDICT_ORDER if v in seen), min(seen, default=None))


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
    read_scopes = ("Infinity Portal API key for the Email & Collaboration service (read events and entities)",)
    write_scopes = ("same API key with a read-write role: quarantine / restore",)

    def fetch_page(self, stream: str, cursor: str | None) -> Page:
        req: dict[str, Any] = {"startDate": cursor or self.settings.get("sync_from", "2026-01-01T00:00:00Z"),
                               "saas": [SAAS]}
        events: list[dict[str, Any]] = []
        for _ in range(50):                     # HEC pages with a scroll id until recordsNumber is reached
            body = self.post(f"{API}/event/query", json={"requestData": req})
            page = body.get("responseData") or []
            events.extend(page)
            env = body.get("responseEnvelope") or {}
            if not page or not env.get("scrollId") or len(events) >= int(env.get("recordsNumber") or 0):
                break
            req = {"scrollId": env["scrollId"]}
        # an event names its e-mail only by entityId; sender, recipients, subject and Message-ID live on the entity
        ids = sorted({e["entityId"] for e in events if e.get("entityId")})
        with ThreadPoolExecutor(max_workers=4) as pool:
            entities = dict(zip(ids, pool.map(self._entity, ids), strict=True))
        for e in events:
            e["_entity"] = entities.get(e.get("entityId")) or {}
        last = max((e.get("eventCreated") or "" for e in events), default=cursor)
        return Page(events, last, has_more=False)

    def _entity(self, entity_id: str) -> dict[str, Any]:
        try:
            items = self.get(f"{API}/search/entity/{entity_id}").get("responseData") or []
        except ConnectorError as exc:           # the event is still worth ingesting without its message details
            log.warning("avanan: entity %s not readable: %s", entity_id, exc)
            return {}
        return items[0] if items else {}

    def normalize(self, stream: str, e: dict[str, Any]) -> list[NormalizedRecord]:
        ent = e.get("_entity") or {}
        p = ent.get("entityPayload") or {}
        refs = []
        if p.get("fromEmail"):
            refs.append(EntityRef(kind="indicator", role="sender", keys={"value": p["fromEmail"].lower()},
                                  attributes={"type": "email"}))
        for r in p.get("recipients") or []:
            refs.append(EntityRef(kind="identity", role="recipient", keys={"upn": r.lower()}))
        return [NormalizedRecord(
            kind="mail_event", tool=self.tool, source_type="security_event", source_id=need(e, "eventId"),
            observed_at=parse_ts(e.get("eventCreated")), title=e.get("description") or f"Avanan {e.get('type')}",
            severity=HEC_SEVERITY.get(str(e.get("severity")), sev_name(e.get("severity"))), dimension="email",
            refs=refs,
            attributes={"verdict": e.get("type"), "state": e.get("state"),
                        "action_taken": [a.get("actionType") for a in e.get("actions") or []],
                        "entity_id": e.get("entityId"), "subject": p.get("subject"),
                        "internet_message_id": p.get("internetMessageId"),
                        "engine_verdicts": (ent.get("entitySecurityResult") or {}).get("combinedVerdict") or {}})]

    def _search(self, attr: str, op: str, value: str, days: int = 30) -> list[dict[str, Any]]:
        body = self.post(f"{API}/search/query", json={"requestData": {
            "entityFilter": {"saas": SAAS, "startDate": (utcnow() - timedelta(days=days)).isoformat()},
            "entityExtendedFilter": [{"saasAttrName": f"entityPayload.{attr}", "saasAttrOp": op,
                                      "saasAttrValue": value}]}})
        return body.get("responseData") or []

    def verdict_for(self, internet_message_id: str) -> dict[str, Any] | None:
        """Avanan verdict + applied actions for one message (PH-F04 reconciliation)."""
        items = self._search("internetMessageId", "is", internet_message_id)
        if not items:
            return None
        it = items[0]
        combined = (it.get("entitySecurityResult") or {}).get("combinedVerdict") or {}
        actions = [a.get("actionType") or a.get("entityActionName") for a in it.get("entityActions") or []]
        return {"entity_id": (it.get("entityInfo") or {}).get("entityId"), "verdict": overall_verdict(combined),
                "engines": {k: v for k, v in sorted(combined.items()) if v},
                "actions": [a for a in actions if a],
                "quarantined": bool((it.get("entityPayload") or {}).get("isQuarantined"))}

    def lookup(self, entity_type: str, value: str, **context: Any) -> LookupResult:
        def run() -> LookupResult:
            if entity_type == "email_message":
                v = self.verdict_for(value)
                return ok_lookup(self, [], f"Avanan verdict={v['verdict']}, actions={v['actions']}" if v
                                 else "message not found in Avanan")
            found = self._search("fromDomain", "is", value)
            return ok_lookup(self, [], f"{len(found)} Avanan-scanned message(s) from sender domain {value} (30 days)")

        return self.timed_lookup(run)

    def _action(self, action: str, targets: list) -> dict:
        ids = [t["avanan_entity_id"] for t in targets if t.get("avanan_entity_id")]
        body = self.post(f"{API}/action/entity", json={"requestData": {
            "entityIds": ids, "entityType": f"{SAAS}_email", "entityActionName": action}})
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
    config=[ConfigField("api_url", "Smart API gateway URL (region specific)", required=False, kind="url"),
            ConfigField("client_id", "Infinity Portal API client id", secret=True),
            ConfigField("access_key", "API access key", secret=True),
            ConfigField("fallback", "shared_mailbox | export if the API is not licensed", required=False,
                        kind="choice", choices=("shared_mailbox", "export")),
            ConfigField("sync_from", "First sync starts here (ISO time; default 2026-01-01T00:00:00Z)",
                        required=False)],
    actions=_actions, confidence="Low-Medium",
    to_confirm="API availability and scope under current licence (fallbacks: journaling, shared mailbox, export)",
    focus_areas=("phishing",),
)
