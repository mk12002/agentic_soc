"""Microsoft Entra ID / Identity Protection connector (IM-T01, PH-F08, IM-F09, U07).

Read: users, sign-ins, risky users, risk detections, directory audits; per-user identity
context (roles, groups, MFA methods, recent sign-ins, inbox rules, registered devices).
Write (policy-gated): revoke sessions, disable/enable account, confirm compromised,
force password change at next sign-in.
"""

from __future__ import annotations

from typing import Any

from soc_platform.connectors.base import LookupResult, Page
from soc_platform.connectors.registry import ConnectorManifest
from soc_platform.connectors.tools._common import ConnectorAction, ok_lookup, parse_ts, targets_of
from soc_platform.connectors.tools._microsoft import APP_FIELDS, MicrosoftConnector, graph_transport
from soc_platform.core.schema import EntityRef, NormalizedRecord

PORTAL = "https://entra.microsoft.com"
PRIVILEGED_ROLES = {"Global Administrator", "Privileged Role Administrator", "Security Administrator",
                    "Exchange Administrator", "SharePoint Administrator", "User Administrator",
                    "Application Administrator", "Cloud Application Administrator", "Privileged Authentication Administrator"}
_RISK = {"none": "informational", "low": "low", "medium": "medium", "high": "high", "hidden": "medium"}


class EntraConnector(MicrosoftConnector):
    name = "entra"
    tool = "entra"
    dimension = "identity"
    streams = ("users", "signins", "risky_users", "risk_detections", "directory_audits")
    lookups = ("user", "ip")
    read_scopes = ("User.Read.All", "AuditLog.Read.All", "IdentityRiskyUser.Read.All", "IdentityRiskEvent.Read.All",
                   "RoleManagement.Read.Directory", "UserAuthenticationMethod.Read.All", "MailboxSettings.Read")
    write_scopes = ("User.RevokeSessions.All", "User.EnableDisableAccount.All", "IdentityRiskyUser.ReadWrite.All",
                    "User-PasswordProfile.ReadWrite.All")

    def fetch_page(self, stream: str, cursor: str | None) -> Page:
        path, params = {
            "users": ("/v1.0/users", {"$select": "id,userPrincipalName,mail,displayName,department,jobTitle,"
                                                  "accountEnabled,onPremisesSamAccountName,onPremisesSecurityIdentifier",
                                      "$top": 999}),
            "signins": ("/v1.0/auditLogs/signIns", {"$top": 500}),
            "risky_users": ("/v1.0/identityProtection/riskyUsers", {"$top": 500}),
            "risk_detections": ("/v1.0/identityProtection/riskDetections", {"$top": 500}),
            "directory_audits": ("/v1.0/auditLogs/directoryAudits", {"$top": 500}),
        }[stream]
        return self.odata_page(path, cursor, params)

    def normalize(self, stream: str, raw: dict[str, Any]) -> list[NormalizedRecord]:
        if stream == "users":
            return [self._user(raw)]
        if stream == "signins":
            return [self._signin(raw)]
        if stream == "risky_users":
            return [self._risky_user(raw)]
        if stream == "risk_detections":
            return [self._risk_detection(raw)]
        return [self._audit(raw)]

    def _user(self, u: dict[str, Any]) -> NormalizedRecord:
        return NormalizedRecord(
            kind="identity", tool=self.tool, source_type="user", source_id=u["id"], dimension="identity",
            keys={"entra_object_id": u["id"], "upn": u.get("userPrincipalName"), "email": u.get("mail"),
                  "sid": u.get("onPremisesSecurityIdentifier")},
            attributes={"display_name": u.get("displayName"), "department": u.get("department"),
                        "job_title": u.get("jobTitle"), "account_enabled": u.get("accountEnabled"),
                        "sam_account_name": u.get("onPremisesSamAccountName")},
            deep_link=f"{PORTAL}/#view/Microsoft_AAD_UsersAndTenants/UserProfileMenuBlade/~/overview/userId/{u['id']}")

    def _uref(self, upn: str | None, oid: str | None) -> EntityRef:
        return EntityRef(kind="identity", role="user", keys={k: v for k, v in {"upn": upn, "entra_object_id": oid}.items() if v})

    def _signin(self, s: dict[str, Any]) -> NormalizedRecord:
        st = s.get("status") or {}
        loc = s.get("location") or {}
        dev = s.get("deviceDetail") or {}
        refs = [self._uref(s.get("userPrincipalName"), s.get("userId"))]
        if s.get("ipAddress"):
            refs.append(EntityRef(kind="indicator", role="source_ip", keys={"value": s["ipAddress"]}, attributes={"type": "ip"}))
        if dev.get("deviceId"):
            refs.append(EntityRef(kind="asset", role="device", keys={"aad_device_id": dev["deviceId"]},
                                  attributes={"hostname": dev.get("displayName")}))
        risky = s.get("riskLevelDuringSignIn") not in (None, "none", "hidden")
        return NormalizedRecord(
            kind="signin", tool=self.tool, source_type="signin", source_id=s["id"], dimension="identity",
            observed_at=parse_ts(s.get("createdDateTime")),
            title=f"Sign-in {'failure' if st.get('errorCode') else 'success'} to {s.get('appDisplayName')}",
            severity=_RISK.get(s.get("riskLevelDuringSignIn") or "none") if risky else "informational", refs=refs,
            attributes={"app": s.get("appDisplayName"), "ip": s.get("ipAddress"), "country": loc.get("countryOrRegion"),
                        "city": loc.get("city"), "error_code": st.get("errorCode"), "failure": st.get("failureReason"),
                        "risk_level": s.get("riskLevelDuringSignIn"), "risk_state": s.get("riskState"),
                        "mfa_detail": s.get("mfaDetail"), "conditional_access": s.get("conditionalAccessStatus"),
                        "client_app": s.get("clientAppUsed"), "device_compliant": dev.get("isCompliant"),
                        "authentication_requirement": s.get("authenticationRequirement")},
            deep_link=f"{PORTAL}/#view/Microsoft_AAD_IAM/SignInLogsList.ReactView")

    def _risky_user(self, r: dict[str, Any]) -> NormalizedRecord:
        return NormalizedRecord(
            kind="alert", tool=self.tool, source_type="risky_user", source_id=r["id"], dimension="identity",
            observed_at=parse_ts(r.get("riskLastUpdatedDateTime")), title=f"Risky user: {r.get('userPrincipalName')}",
            severity=_RISK.get(r.get("riskLevel") or "none"), refs=[self._uref(r.get("userPrincipalName"), r.get("id"))],
            attributes={"risk_level": r.get("riskLevel"), "risk_state": r.get("riskState"), "risk_detail": r.get("riskDetail")},
            deep_link=f"{PORTAL}/#view/Microsoft_AAD_IAM/RiskyUsersBlade")

    def _risk_detection(self, r: dict[str, Any]) -> NormalizedRecord:
        refs = [self._uref(r.get("userPrincipalName"), r.get("userId"))]
        if r.get("ipAddress"):
            refs.append(EntityRef(kind="indicator", role="source_ip", keys={"value": r["ipAddress"]}, attributes={"type": "ip"}))
        return NormalizedRecord(
            kind="alert", tool=self.tool, source_type="risk_detection", source_id=r["id"], dimension="identity",
            observed_at=parse_ts(r.get("detectedDateTime")), title=f"Identity risk: {r.get('riskEventType')}",
            severity=_RISK.get(r.get("riskLevel") or "none"), refs=refs,
            attributes={"risk_event_type": r.get("riskEventType"), "ip": r.get("ipAddress"),
                        "location": r.get("location"), "detection_timing": r.get("detectionTimingType"),
                        "additional_info": r.get("additionalInfo")},
            deep_link=f"{PORTAL}/#view/Microsoft_AAD_IAM/RiskDetectionsBlade")

    def _audit(self, a: dict[str, Any]) -> NormalizedRecord:
        by = ((a.get("initiatedBy") or {}).get("user") or {})
        refs = [self._uref(by.get("userPrincipalName"), by.get("id"))] if by.get("userPrincipalName") else []
        for t in a.get("targetResources") or []:
            if t.get("type") == "User" and t.get("userPrincipalName"):
                refs.append(EntityRef(kind="identity", role="target", keys={"upn": t["userPrincipalName"]}))
        return NormalizedRecord(
            kind="alert" if a.get("category") in {"RoleManagement"} else "signin", tool=self.tool,
            source_type="directory_audit", source_id=a["id"], dimension="identity",
            observed_at=parse_ts(a.get("activityDateTime")), title=a.get("activityDisplayName", "Directory change"),
            severity="informational", refs=refs,
            attributes={"category": a.get("category"), "result": a.get("result")})

    # ------------------------------------------------------------------ identity context (PH-F08, IM-F04)

    def identity_context(self, upn: str, since_iso: str | None = None) -> dict[str, Any]:
        u = self.get(f"/v1.0/users/{upn}", params={"$select": "id,userPrincipalName,displayName,department,jobTitle,"
                                                               "accountEnabled,createdDateTime"})
        roles = [r.get("displayName") for r in self.get(f"/v1.0/users/{upn}/transitiveMemberOf").get("value", [])
                 if r.get("@odata.type", "").endswith("directoryRole")]
        groups = [g.get("displayName") for g in self.get(f"/v1.0/users/{upn}/transitiveMemberOf").get("value", [])
                  if g.get("@odata.type", "").endswith("group")]
        methods = [m.get("@odata.type", "").split(".")[-1] for m in
                   self.get(f"/v1.0/users/{upn}/authentication/methods").get("value", [])]
        flt = f"userPrincipalName eq '{upn}'" + (f" and createdDateTime ge {since_iso}" if since_iso else "")
        signins = self.get("/v1.0/auditLogs/signIns", params={"$filter": flt, "$top": 50}).get("value", [])
        risky = self.get("/v1.0/identityProtection/riskyUsers", params={"$filter": f"userPrincipalName eq '{upn}'"}).get("value", [])
        rules = self.get(f"/v1.0/users/{upn}/mailFolders/inbox/messageRules").get("value", [])
        devices = self.get(f"/v1.0/users/{upn}/registeredDevices").get("value", [])
        suspicious_rules = [r for r in rules if (r.get("actions") or {}).get("forwardTo") or
                            (r.get("actions") or {}).get("redirectTo") or (r.get("actions") or {}).get("delete")
                            or (r.get("actions") or {}).get("moveToFolder") in {"RSS Feeds", "Archive", "Conversation History"}]
        new_devices = [d for d in devices if since_iso and str(d.get("registrationDateTime", "")) >= since_iso]
        return {"user": u, "roles": roles, "privileged_roles": sorted(set(roles) & PRIVILEGED_ROLES), "groups": groups,
                "mfa_methods": methods, "signins": signins, "risky": risky[0] if risky else None,
                "inbox_rules": rules, "suspicious_inbox_rules": suspicious_rules, "devices": devices,
                "new_devices": new_devices}

    def lookup(self, entity_type: str, value: str, **context: Any) -> LookupResult:
        def run() -> LookupResult:
            if entity_type == "user":
                ctx = self.identity_context(value, context.get("since"))
                recs = [self._user(ctx["user"])] + [self._signin(s) for s in ctx["signins"]]
                risky_signins = [s for s in ctx["signins"] if s.get("riskLevelDuringSignIn") not in (None, "none", "hidden")]
                summary = (f"{ctx['user'].get('displayName')} ({ctx['user'].get('jobTitle')}); "
                           f"privileged roles: {ctx['privileged_roles'] or 'none'}; MFA: {ctx['mfa_methods']}; "
                           f"user risk: {(ctx['risky'] or {}).get('riskLevel', 'none')}; "
                           f"{len(ctx['signins'])} sign-in(s), {len(risky_signins)} risky; "
                           f"{len(ctx['suspicious_inbox_rules'])} suspicious inbox rule(s); "
                           f"{len(ctx['new_devices'])} newly registered device(s)")
                return ok_lookup(self, recs, summary, recs[0].deep_link, risky_signins=len(risky_signins),
                                 user_risk=(ctx["risky"] or {}).get("riskLevel", "none"),
                                 suspicious_inbox_rules=len(ctx["suspicious_inbox_rules"]),
                                 new_devices=len(ctx["new_devices"]), privileged_roles=ctx["privileged_roles"],
                                 risky_ips=sorted({s.get("ipAddress") for s in risky_signins if s.get("ipAddress")}))
            if entity_type == "ip":
                s = self.get("/v1.0/auditLogs/signIns", params={"$filter": f"ipAddress eq '{value}'", "$top": 50}).get("value", [])
                users = sorted({x.get("userPrincipalName") for x in s})
                return ok_lookup(self, [self._signin(x) for x in s], f"{len(s)} sign-in(s) from {value} by {users}",
                                 signins_from_ip=len(s), users=users)
            raise ValueError(entity_type)

        return self.timed_lookup(run)

    # ------------------------------------------------------------------ actions

    def _upns(self, targets: list) -> list[str]:
        return targets_of(targets, "identity", "upn")

    def revoke(self, params: dict, targets: list) -> dict:
        return {"revoked": [u for u in self._upns(targets) if self.post(f"/v1.0/users/{u}/revokeSignInSessions") is not None]}

    def disable(self, params: dict, targets: list) -> dict:
        for u in self._upns(targets):
            self.req("PATCH", f"/v1.0/users/{u}", json={"accountEnabled": False})
        return {"disabled": self._upns(targets)}

    def enable(self, params: dict, targets: list) -> dict:
        for u in self._upns(targets):
            self.req("PATCH", f"/v1.0/users/{u}", json={"accountEnabled": True})
        return {"enabled": self._upns(targets)}

    def confirm_compromised(self, params: dict, targets: list) -> dict:
        ids = targets_of(targets, "identity", "entra_object_id")
        self.post("/v1.0/identityProtection/riskyUsers/confirmCompromised", json={"userIds": ids})
        return {"confirmed": ids}

    def force_password_change(self, params: dict, targets: list) -> dict:
        for u in self._upns(targets):
            self.req("PATCH", f"/v1.0/users/{u}", json={"passwordProfile": {"forceChangePasswordNextSignIn": True}})
        return {"forced": self._upns(targets)}


def _has_upn(params: dict, targets: list) -> list[str]:
    return [] if targets_of(targets, "identity", "upn") else ["no identity targets with a UPN"]


def _actions(c: EntraConnector) -> list:
    return [
        ConnectorAction("identity.revoke_sessions", c, c.revoke, preconditions=_has_upn,
                        description="Revoke refresh tokens / sign-in sessions"),
        ConnectorAction("identity.disable_account", c, c.disable, preconditions=_has_upn,
                        reverse_type="identity.enable_account", description="Disable the account"),
        ConnectorAction("identity.enable_account", c, c.enable, preconditions=_has_upn, description="Re-enable the account"),
        ConnectorAction("identity.confirm_compromised", c, c.confirm_compromised,
                        description="Mark user compromised in Identity Protection (raises risk; drives CA policy)"),
        ConnectorAction("identity.reset_password", c, c.force_password_change, preconditions=_has_upn,
                        description="Force password change at next sign-in"),
    ]


MANIFEST = ConnectorManifest(
    name="entra", tool="Microsoft Entra ID", vendor="Microsoft", category="identity", dimension="identity",
    description="Users, sign-ins, risky users and detections, roles, MFA, inbox rules; session revoke and account control.",
    factory=lambda s, t: EntraConnector(s, t, rate_per_sec=5, burst=10),
    live_transport=graph_transport, config=list(APP_FIELDS), actions=_actions, confidence="High",
    to_confirm="Entra ID P2 for Identity Protection risk data; write permissions for response actions",
    focus_areas=("incident", "phishing"),
)
