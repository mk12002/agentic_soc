"""Microsoft Defender for Office 365 + Exchange Online via Graph (PH-T01, PH-F01, PH-F05, PH-F06, PH-F11).

Read:
  * ``reported_messages`` - the SOC reporting mailbox that Defender's user-reported
    settings deliver to (report button / Report Message add-in); original MIME is
    fetched intact from the attached item so headers are preserved (PH-F01).
  * ``email_alerts`` - Defender for Office 365 alerts (alerts_v2).
  * advanced hunting over EmailEvents / EmailUrlInfo / EmailAttachmentInfo /
    UrlClickEvents for campaign scope and user interaction (PH-F05, PH-F06).
Write (policy-gated): tenant-wide remediation of delivered copies (soft delete /
move to junk, reversible with move-to-inbox), per-message tagging, reporter
feedback mail from the SOC mailbox, tenant allow/block list sender block.
"""

from __future__ import annotations

import base64
from typing import Any

from soc_platform.connectors.base import LookupResult, Page
from soc_platform.connectors.registry import ConfigField, ConnectorManifest
from soc_platform.connectors.tools._common import ConnectorAction, ok_lookup, parse_ts, sev_name
from soc_platform.connectors.tools._microsoft import APP_FIELDS, MicrosoftConnector, graph_transport, kql_list, kql_str
from soc_platform.core.schema import EntityRef, NormalizedRecord

PORTAL = "https://security.microsoft.com"


class DefenderOffice365Connector(MicrosoftConnector):
    name = "defender_office365"
    tool = "defender_office365"
    dimension = "email"
    streams = ("reported_messages", "email_alerts")
    lookups = ("email_message", "user", "domain", "url", "hash")
    read_scopes = ("Mail.Read (reporting mailbox, app-access-policy scoped)", "SecurityAlert.Read.All",
                   "ThreatHunting.Read.All")
    write_scopes = ("SecurityAnalyzedMessage.ReadWrite.All", "Mail.ReadWrite (scoped)", "Mail.Send (SOC mailbox)",
                    "Exchange.ManageAsApp (tenant allow/block list)")

    @property
    def mailbox(self) -> str:
        return self.settings.get("reporting_mailbox") or "soc-reports@example.com"

    # ------------------------------------------------------------------ streams

    def fetch_page(self, stream: str, cursor: str | None) -> Page:
        if stream == "reported_messages":
            return self.odata_page(f"/v1.0/users/{self.mailbox}/mailFolders/inbox/messages", cursor,
                                   {"$top": 50, "$orderby": "receivedDateTime asc",
                                    "$select": "id,subject,from,receivedDateTime,hasAttachments,internetMessageId"})
        if stream == "email_alerts":
            return self.odata_page("/v1.0/security/alerts_v2", cursor,
                                   {"$filter": "serviceSource eq 'microsoftDefenderForOffice365'", "$top": 100})
        raise ValueError(stream)

    def normalize(self, stream: str, raw: dict[str, Any]) -> list[NormalizedRecord]:
        if stream == "reported_messages":
            return [self._reported(raw)]
        return [self._alert(raw)]

    def original_mime(self, report_message_id: str) -> tuple[bytes | None, dict[str, Any]]:
        """Return the reported (attached) message's raw MIME, preserving original headers."""
        atts = self.get(f"/v1.0/users/{self.mailbox}/messages/{report_message_id}/attachments").get("value", [])
        for a in atts:
            odt = a.get("@odata.type", "")
            if odt.endswith("itemAttachment") or a.get("contentType") == "message/rfc822" or \
                    str(a.get("name", "")).lower().endswith(".eml"):
                if a.get("contentBytes"):
                    return base64.b64decode(a["contentBytes"]), a
                raw = self.req("GET", f"/v1.0/users/{self.mailbox}/messages/{report_message_id}/attachments/{a['id']}/$value").body
                return (raw.encode() if isinstance(raw, str) else raw), a
        # Report button configured to forward inline: fall back to the report message itself.
        raw = self.req("GET", f"/v1.0/users/{self.mailbox}/messages/{report_message_id}/$value").body
        return (raw.encode() if isinstance(raw, str) else raw), {}

    def _reported(self, m: dict[str, Any]) -> NormalizedRecord:
        reporter = ((m.get("from") or {}).get("emailAddress") or {}).get("address")
        return NormalizedRecord(
            kind="email", tool=self.tool, source_type="user_reported", source_id=m["id"],
            observed_at=parse_ts(m.get("receivedDateTime")), title=m.get("subject") or "(reported message)",
            dimension="email",
            refs=[EntityRef(kind="identity", role="reporter", keys={"upn": reporter})] if reporter else [],
            attributes={"reporter": reporter, "report_message_id": m["id"], "mailbox": self.mailbox,
                        "has_attachments": m.get("hasAttachments"), "internet_message_id": m.get("internetMessageId")},
            deep_link=f"{PORTAL}/reportsubmission")

    def _alert(self, a: dict[str, Any]) -> NormalizedRecord:
        refs = []
        for ev in a.get("evidence") or []:
            t = ev.get("@odata.type", "")
            if t.endswith("userEvidence"):
                upn = (ev.get("userAccount") or {}).get("userPrincipalName")
                if upn:
                    refs.append(EntityRef(kind="identity", role="recipient", keys={"upn": upn}))
            elif t.endswith("urlEvidence") and ev.get("url"):
                refs.append(EntityRef(kind="indicator", role="observable", keys={"value": ev["url"]},
                                      attributes={"type": "url"}))
            elif t.endswith("analyzedMessageEvidence"):
                sender = ev.get("senderIp")
                if sender:
                    refs.append(EntityRef(kind="indicator", role="sender_ip", keys={"value": sender},
                                          attributes={"type": "ip"}))
        return NormalizedRecord(
            kind="alert", tool=self.tool, source_type="alert_v2", source_id=a["id"],
            observed_at=parse_ts(a.get("createdDateTime")), title=a.get("title", "Defender for Office 365 alert"),
            severity=sev_name(a.get("severity")), refs=refs, dimension="email",
            attributes={"category": a.get("category"), "status": a.get("status"),
                        "mitre_techniques": a.get("mitreTechniques") or [], "incident_id": a.get("incidentId"),
                        "description": a.get("description")},
            deep_link=a.get("alertWebUrl"))

    # ------------------------------------------------------------------ investigation helpers (used by phishing agents)

    def message_events(self, *, network_message_id: str | None = None, internet_message_id: str | None = None,
                       lookback_days: int = 7) -> list[dict[str, Any]]:
        cond = (f"NetworkMessageId == {kql_str(network_message_id)}" if network_message_id
                else f"InternetMessageId == {kql_str(internet_message_id or '')}")
        return self.graph_hunt(
            f"EmailEvents | where Timestamp > ago({lookback_days}d) | where {cond}\n"
            "| project Timestamp, NetworkMessageId, InternetMessageId, SenderFromAddress, SenderMailFromAddress, "
            "SenderDisplayName, SenderIPv4, RecipientEmailAddress, Subject, DeliveryAction, DeliveryLocation, "
            "ThreatTypes, DetectionMethods, AuthenticationDetails, UrlCount, AttachmentCount, LatestDeliveryAction")

    def similar_messages(self, *, sender_domains: list[str], subject_terms: list[str], url_domains: list[str],
                         sha256s: list[str], lookback_days: int = 14) -> list[dict[str, Any]]:
        """Candidate campaign members across the tenant (PH-F05); clustering happens in the Campaign Agent."""
        q = (f"let senders = {kql_list(sender_domains)}; let urls = {kql_list(url_domains)};\n"
             f"let hashes = {kql_list(sha256s)}; let subj = {kql_list(subject_terms)};\n"
             f"let byUrl = EmailUrlInfo | where Timestamp > ago({lookback_days}d) | where UrlDomain in~ (urls) "
             "| project NetworkMessageId, Url, UrlDomain;\n"
             f"let byAtt = EmailAttachmentInfo | where Timestamp > ago({lookback_days}d) | where SHA256 in~ (hashes) "
             "| project NetworkMessageId, SHA256, FileName;\n"
             f"EmailEvents | where Timestamp > ago({lookback_days}d)\n"
             "| where SenderFromDomain in~ (senders) or Subject has_any (subj)"
             " or NetworkMessageId in ((byUrl | project NetworkMessageId))"
             " or NetworkMessageId in ((byAtt | project NetworkMessageId))\n"
             "| join kind=leftouter byUrl on NetworkMessageId | join kind=leftouter byAtt on NetworkMessageId\n"
             "| project Timestamp, NetworkMessageId, InternetMessageId, SenderFromAddress, SenderDisplayName, "
             "SenderIPv4, RecipientEmailAddress, Subject, DeliveryAction, DeliveryLocation, LatestDeliveryAction, "
             "ThreatTypes, Url, UrlDomain, SHA256, FileName")
        return self.graph_hunt(q)

    def url_clicks(self, urls: list[str], url_domains: list[str], lookback_days: int = 14) -> list[dict[str, Any]]:
        """Safe Links click telemetry: who clicked, when, allowed or blocked (PH-F06)."""
        return self.graph_hunt(
            f"UrlClickEvents | where Timestamp > ago({lookback_days}d)\n"
            f"| where Url in~ ({kql_list(urls)}) or parse_url(Url).Host in~ ({kql_list(url_domains)})\n"
            "| project Timestamp, AccountUpn, Url, ActionType, IsClickedThrough, NetworkMessageId, IPAddress, Workload")

    def post_delivery_events(self, network_message_ids: list[str]) -> list[dict[str, Any]]:
        return self.graph_hunt(
            f"EmailPostDeliveryEvents | where NetworkMessageId in ({kql_list(network_message_ids)})\n"
            "| project Timestamp, NetworkMessageId, RecipientEmailAddress, Action, ActionType, ActionResult, "
            "DeliveryLocation")

    def lookup(self, entity_type: str, value: str, **context: Any) -> LookupResult:
        def run() -> LookupResult:
            if entity_type == "email_message":
                rows = self.message_events(network_message_id=value) or self.message_events(internet_message_id=value)
                return ok_lookup(self, [], f"{len(rows)} delivery record(s); actions="
                                           f"{sorted({r.get('DeliveryAction') for r in rows})}")
            if entity_type == "user":
                rows = self.graph_hunt(
                    f"EmailEvents | where Timestamp > ago(7d) | where RecipientEmailAddress =~ {kql_str(value)}"
                    " | where ThreatTypes != '' | project Timestamp, SenderFromAddress, Subject, ThreatTypes, "
                    "DeliveryAction | take 50")
                clicks = self.graph_hunt(
                    f"UrlClickEvents | where Timestamp > ago(7d) | where AccountUpn =~ {kql_str(value)}"
                    " | project Timestamp, Url, ActionType, IsClickedThrough | take 50")
                return ok_lookup(self, [], f"{len(rows)} threat mail(s) received, {len(clicks)} Safe Links click(s) in 7d",
                                 threat_mails=len(rows), clicks=len(clicks))
            if entity_type in {"domain", "url"}:
                col = "UrlDomain" if entity_type == "domain" else "Url"
                rows = self.graph_hunt(
                    f"EmailUrlInfo | where Timestamp > ago(14d) | where {col} =~ {kql_str(value)}"
                    " | summarize Messages=dcount(NetworkMessageId)")
                n = rows[0].get("Messages", 0) if rows else 0
                return ok_lookup(self, [], f"{entity_type} appeared in {n} message(s) in 14d mail flow")
            if entity_type == "hash":
                rows = self.graph_hunt(
                    f"EmailAttachmentInfo | where Timestamp > ago(14d) | where SHA256 =~ {kql_str(value)}"
                    " | summarize Messages=dcount(NetworkMessageId), Recipients=dcount(RecipientEmailAddress)")
                r = rows[0] if rows else {}
                return ok_lookup(self, [], f"attachment seen in {r.get('Messages', 0)} message(s) to "
                                           f"{r.get('Recipients', 0)} recipient(s)")
            raise ValueError(entity_type)

        return self.timed_lookup(run)

    # ------------------------------------------------------------------ actions

    def _remediate(self, action: str, params: dict, targets: list) -> dict:
        emails = [{"networkMessageId": t["network_message_id"], "recipientEmailAddress": t["recipient"]}
                  for t in targets if t.get("type") == "email" and t.get("network_message_id") and t.get("recipient")]
        if not emails:
            raise ValueError("no (network_message_id, recipient) targets")
        body = self.post("/beta/security/collaboration/analyzedEmails/remediate", json={
            "displayName": params.get("name", f"SOC platform {action}"), "description": params.get("reason", ""),
            "severity": params.get("severity", "high"), "action": action, "remediateSendersCopy": False,
            "analyzedEmails": emails})
        return {"action": action, "messages": len(emails), "response": body}

    def purge(self, params: dict, targets: list) -> dict:
        return self._remediate(params.get("mode", "softDelete"), params, targets)

    def restore(self, params: dict, targets: list) -> dict:
        return self._remediate("moveToInbox", params, targets)

    def tag(self, params: dict, targets: list) -> dict:
        done = []
        for t in targets:
            if t.get("type") == "email" and t.get("graph_message_id") and t.get("recipient"):
                self.req("PATCH", f"/v1.0/users/{t['recipient']}/messages/{t['graph_message_id']}",
                         json={"categories": params.get("categories", ["Phishing - SOC confirmed"])})
                done.append(t["graph_message_id"])
        return {"tagged": done}

    def send_feedback(self, params: dict, targets: list) -> dict:
        sent = []
        for t in targets:
            if t.get("type") != "identity" or not t.get("upn"):
                continue
            self.post(f"/v1.0/users/{self.mailbox}/sendMail", json={"message": {
                "subject": params.get("subject", "Update on the email you reported"),
                "body": {"contentType": "HTML", "content": params["body_html"]},
                "toRecipients": [{"emailAddress": {"address": t["upn"]}}]}, "saveToSentItems": True})
            sent.append(t["upn"])
        return {"sent": sent}

    def notify(self, params: dict, targets: list) -> dict:
        """Send a notification (e.g. VM remediation notice) from the SOC mailbox (VM-T09)."""
        to = [t.get("email") or t.get("id") for t in targets if t.get("type") in {"recipient", "team", "identity"}]
        to = [x for x in to if x and "@" in x]
        if not to:
            raise ValueError("no recipient email addresses")
        self.post(f"/v1.0/users/{self.mailbox}/sendMail", json={"message": {
            "subject": params["subject"], "body": {"contentType": "Text", "content": params["body"]},
            "toRecipients": [{"emailAddress": {"address": x}} for x in to]}, "saveToSentItems": True})
        return {"sent_to": to, "subject": params["subject"]}

    def block_sender(self, params: dict, targets: list) -> dict:
        """Tenant Allow/Block List entry through the Exchange Online admin API (verify in tenant)."""
        senders = [t["value"] for t in targets if t.get("type") == "indicator" and t.get("indicator_type") in {"email", "domain"}]
        tenant = self.settings.get("tenant_id", "")
        body = self.post(f"https://outlook.office365.com/adminapi/beta/{tenant}/InvokeCommand", json={
            "CmdletInput": {"CmdletName": "New-TenantAllowBlockListItems", "Parameters": {
                "ListType": "Sender", "Block": True, "Entries": senders,
                "ExpirationDate": params.get("expires"), "Notes": params.get("reason", "SOC platform")}}})
        return {"blocked": senders, "response": body}

    def unblock_sender(self, params: dict, targets: list) -> dict:
        senders = [t["value"] for t in targets if t.get("type") == "indicator"]
        tenant = self.settings.get("tenant_id", "")
        self.post(f"https://outlook.office365.com/adminapi/beta/{tenant}/InvokeCommand", json={
            "CmdletInput": {"CmdletName": "Remove-TenantAllowBlockListItems",
                            "Parameters": {"ListType": "Sender", "Entries": senders}}})
        return {"unblocked": senders}


def _email_targets(params: dict, targets: list) -> list[str]:
    ok = any(t.get("type") == "email" and t.get("network_message_id") and t.get("recipient") for t in targets)
    return [] if ok else ["targets need network_message_id and recipient"]


def _actions(c: DefenderOffice365Connector) -> list:
    return [
        ConnectorAction("email.campaign_purge", c, c.purge, preconditions=_email_targets,
                        description="Tenant-wide soft delete of delivered copies (reversible)",
                        reverse_type="email.restore"),
        ConnectorAction("email.restore", c, c.restore, preconditions=_email_targets,
                        description="Move remediated copies back to the inbox"),
        ConnectorAction("email.tag", c, c.tag, description="Categorise message in the recipient mailbox"),
        ConnectorAction("email.reporter_feedback", c, c.send_feedback,
                        description="Send outcome to the reporting user from the SOC mailbox"),
        ConnectorAction("notify.email", c, c.notify, description="Send a notification email from the SOC mailbox",
                        preconditions=lambda p, t: [] if p.get("subject") and p.get("body") else ["subject/body required"]),
        ConnectorAction("email.block_sender", c, c.block_sender, reverse_type="email.unblock_sender",
                        description="Tenant Allow/Block List sender block"),
        ConnectorAction("email.unblock_sender", c, c.unblock_sender, description="Remove sender block"),
    ]


MANIFEST = ConnectorManifest(
    name="defender_office365", tool="Microsoft Defender for Office 365", vendor="Microsoft", category="email",
    dimension="email",
    description="User-reported mail, email alerts, message trace & campaign hunting, click telemetry, remediation.",
    factory=lambda s, t: DefenderOffice365Connector(s, t, rate_per_sec=2, burst=5),
    live_transport=graph_transport,
    config=APP_FIELDS + [ConfigField("reporting_mailbox", "Mailbox receiving user-reported messages / SOC mailbox")],
    actions=_actions, confidence="High",
    to_confirm="Licence tier for advanced hunting and Safe Links click telemetry; Graph app permissions; "
               "Exchange app-access policy scoping the SOC mailbox",
    fake_settings={"reporting_mailbox": "soc-reports@cci-demo.com", "tenant_id": "demo-tenant"},
    focus_areas=("phishing", "incident"),
)
