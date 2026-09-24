"""The three new phishing agents (PH-T02): Control-Reconciliation, Campaign, User-Impact.

All three work through the connector registry, so they run identically on fixtures or
live tenants, and each returns structured findings plus evidence sentences with the
source tool and deep link needed for the consolidated investigation view.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from rapidfuzz import fuzz

from soc_platform.connectors.registry import ConnectorRegistry
from soc_platform.domains.phishing.agents.decompose import DecomposedEmail


@dataclass
class EvidenceItem:
    summary: str
    source: str
    dimension: str
    data: dict[str, Any] = field(default_factory=dict)
    deep_link: str | None = None
    is_inference: bool = False


def _get(reg: ConnectorRegistry, name: str):
    return reg.get(name) if name in reg.enabled_names() else None


# ============================================================================ PH-F04 reconciliation


def reconcile(reg: ConnectorRegistry, em: DecomposedEmail, our_verdict: str) -> dict[str, Any]:
    """Compare our verdict with what Defender for Office 365 and Avanan did with the same message."""
    controls: dict[str, Any] = {}
    evidence: list[EvidenceItem] = []
    unavailable: list[str] = []
    mdo = _get(reg, "defender_office365")
    if mdo:
        try:
            rows = mdo.message_events(internet_message_id=em.message_id)
            if rows:
                actions = sorted({r.get("DeliveryAction") for r in rows if r.get("DeliveryAction")})
                threats = sorted({t for r in rows for t in str(r.get("ThreatTypes") or "").split(",") if t})
                det = sorted({t for r in rows for t in str(r.get("DetectionMethods") or "").split(",") if t})
                verdict = "malicious" if threats else "clean"
                controls["defender_office365"] = {"verdict": verdict, "delivery_actions": actions, "threat_types": threats,
                                                  "detection_methods": det, "recipients": len(rows),
                                                  "network_message_id": rows[0].get("NetworkMessageId")}
                evidence.append(EvidenceItem(f"Defender for Office 365: {verdict} (delivery {actions}, threats "
                                             f"{threats or 'none'}) to {len(rows)} recipient(s)", "defender_office365",
                                             "email", controls["defender_office365"]))
            else:
                controls["defender_office365"] = {"verdict": "not_found"}
        except Exception as exc:
            unavailable.append(f"defender_office365: {exc}")
    av = _get(reg, "avanan")
    if av:
        try:
            v = av.verdict_for(em.message_id)
            controls["avanan"] = v or {"verdict": "not_found"}
            if v:
                evidence.append(EvidenceItem(f"Avanan: {v['verdict']} (actions {v['actions'] or 'none'})", "avanan",
                                             "email", v))
        except Exception as exc:
            unavailable.append(f"avanan: {exc}")
    passed = [n for n, c in controls.items() if c.get("verdict") in {"clean", "not_found"}]
    ours_bad = our_verdict in {"malicious", "suspicious"}
    disagreements = []
    if ours_bad and passed:
        disagreements.append({"type": "missed_by_controls", "controls": passed,
                              "note": "Platform flags the message but these controls passed it - high-value finding"})
    if not ours_bad and any(c.get("verdict") == "malicious" for c in controls.values()):
        disagreements.append({"type": "platform_less_severe",
                              "controls": [n for n, c in controls.items() if c.get("verdict") == "malicious"]})
    for d in disagreements:
        evidence.append(EvidenceItem(f"Control disagreement: {d['type']} ({', '.join(d['controls'])})", "platform",
                                     "email", d, is_inference=True))
    return {"controls": controls, "disagreements": disagreements, "evidence": evidence, "unavailable": unavailable}


# ============================================================================ PH-F05 / PH-T03 campaign clustering


def _subject_template(s: str) -> str:
    s = re.sub(r"^\s*((re|fw|fwd|aw|tr)\s*:\s*)+", "", s or "", flags=re.I).lower()
    s = re.sub(r"\d+", "#", s)
    return re.sub(r"\s+", " ", s).strip()


def _url_skeleton(u: str) -> str:
    u = re.sub(r"^https?://", "", u or "", flags=re.I)
    host, _, path = u.partition("/")
    path = re.sub(r"[?#].*$", "", path)
    path = re.sub(r"[0-9a-f]{8,}|\d+", "#", path, flags=re.I)
    return f"{host.lower()}/{path}"


def similarity(seed: dict[str, Any], cand: dict[str, Any]) -> tuple[float, list[str]]:
    """Weighted similarity with an analyst-visible rationale (configurable threshold applied by caller)."""
    score, why = 0.0, []
    if seed.get("sender_domain") and seed["sender_domain"] == (cand.get("SenderFromDomain") or "").lower():
        score += 0.30
        why.append("same sender domain")
    dn = fuzz.token_set_ratio(seed.get("display_name", ""), cand.get("SenderDisplayName", "")) / 100
    if dn >= 0.85 and seed.get("display_name"):
        score += 0.10
        why.append(f"display name {dn:.2f}")
    st = fuzz.token_set_ratio(_subject_template(seed.get("subject", "")), _subject_template(cand.get("Subject", ""))) / 100
    if st >= 0.8:
        score += 0.25 * st
        why.append(f"subject template {st:.2f}")
    cu = cand.get("Url") or ""
    if cu and seed.get("url_skeletons"):
        best = max(fuzz.ratio(_url_skeleton(cu), s) / 100 for s in seed["url_skeletons"])
        if best >= 0.8:
            score += 0.25 * best
            why.append(f"URL structure {best:.2f}")
    if cand.get("SHA256") and cand["SHA256"].lower() in seed.get("hashes", set()):
        score += 0.10
        why.append("same attachment hash")
    if cand.get("SenderIPv4") and cand["SenderIPv4"] == seed.get("origin_ip"):
        score += 0.05
        why.append("same sending IP")
    return round(min(1.0, score), 3), why


def campaign_scope(reg: ConnectorRegistry, em: DecomposedEmail, *, threshold: float = 0.5,
                   lookback_days: int = 14) -> dict[str, Any]:
    mdo = _get(reg, "defender_office365")
    if mdo is None:
        return {"members": [], "recipients": [], "evidence": [], "unavailable": ["defender_office365 not enabled"]}
    seed = {"sender_domain": em.sender_domain, "display_name": em.display_name, "subject": em.subject,
            "url_skeletons": [_url_skeleton(u) for u in em.urls], "hashes": {a.sha256 for a in em.attachments},
            "origin_ip": em.origin_ip}
    terms = [w for w in re.findall(r"[a-z]{5,}", _subject_template(em.subject))][:5]
    try:
        cands = mdo.similar_messages(sender_domains=[em.sender_domain] if em.sender_domain else [],
                                     subject_terms=terms, url_domains=em.url_domains,
                                     sha256s=[a.sha256 for a in em.attachments], lookback_days=lookback_days)
    except Exception as exc:
        return {"members": [], "recipients": [], "evidence": [], "unavailable": [f"defender_office365: {exc}"]}
    members, rejected = {}, 0
    for c in cands:
        sc, why = similarity(seed, c)
        key = (c.get("NetworkMessageId"), (c.get("RecipientEmailAddress") or "").lower())
        if sc >= threshold:
            if key not in members or members[key]["similarity"] < sc:
                members[key] = {"network_message_id": key[0], "recipient": key[1], "subject": c.get("Subject"),
                                "sender": c.get("SenderFromAddress"), "delivery_action": c.get("DeliveryAction"),
                                "delivery_location": c.get("DeliveryLocation"), "timestamp": c.get("Timestamp"),
                                "internet_message_id": c.get("InternetMessageId"), "similarity": sc, "rationale": why}
        else:
            rejected += 1
    ms = sorted(members.values(), key=lambda m: (-m["similarity"], m["recipient"]))
    variants = sorted({m["network_message_id"] for m in ms})
    recipients = sorted({m["recipient"] for m in ms})
    delivered = [m for m in ms if (m.get("delivery_action") or "").lower() == "delivered"]
    ev = [EvidenceItem(f"Campaign scope: {len(recipients)} recipient(s) across {len(variants)} message variant(s); "
                       f"{len(delivered)} delivered to inbox; {rejected} similar-looking message(s) rejected below "
                       f"threshold {threshold}", "defender_office365", "email",
                       {"recipients": recipients, "variants": variants, "threshold": threshold})]
    try:
        zap = mdo.post_delivery_events(variants) if variants else []
    except Exception:
        zap = []
    if zap:
        ev.append(EvidenceItem(f"Post-delivery: {len(zap)} copy/copies already moved by ZAP/admin "
                               f"({sorted({z.get('RecipientEmailAddress') for z in zap})})", "defender_office365", "email",
                               {"events": zap}))
    return {"members": ms, "recipients": recipients, "variants": variants, "delivered": len(delivered),
            "rejected_candidates": rejected, "post_delivery": zap, "evidence": ev, "unavailable": []}


# ============================================================================ PH-F06/F07/F08 user impact


def user_impact(reg: ConnectorRegistry, em: DecomposedEmail, recipients: list[str]) -> dict[str, Any]:
    ev: list[EvidenceItem] = []
    unavailable: list[str] = []
    per_user: dict[str, dict[str, Any]] = {r: {"clicked": False, "click_blocked": False, "reached_site": False,
                                               "endpoint": {}, "identity": {}} for r in recipients}
    mdo, umb = _get(reg, "defender_office365"), _get(reg, "umbrella")
    if mdo and em.urls:
        try:
            for c in mdo.url_clicks(em.urls, em.url_domains):
                u = (c.get("AccountUpn") or "").lower()
                row = per_user.setdefault(u, {"clicked": False, "click_blocked": False, "reached_site": False,
                                              "endpoint": {}, "identity": {}})
                if c.get("ActionType") == "ClickAllowed" or c.get("IsClickedThrough"):
                    row["clicked"], row["click_time"] = True, c.get("Timestamp")
                else:
                    row["click_blocked"] = True
            clicked = [u for u, r in per_user.items() if r["clicked"]]
            blocked = [u for u, r in per_user.items() if r["click_blocked"] and not r["clicked"]]
            ev.append(EvidenceItem(f"Safe Links: {len(clicked)} user(s) clicked through {clicked}; {len(blocked)} click(s) "
                                   f"blocked {blocked}", "defender_office365", "email",
                                   {"clicked": clicked, "blocked": blocked}))
        except Exception as exc:
            unavailable.append(f"defender_office365 clicks: {exc}")
    if umb:
        for d in em.url_domains:
            try:
                rows = umb.activity(domain=d)
            except Exception as exc:
                unavailable.append(f"umbrella: {exc}")
                continue
            for r in rows:
                if r.get("verdict") != "allowed":
                    continue
                for ident in r.get("identities") or []:
                    lab = str(ident.get("label", "")).lower()
                    if lab in per_user:
                        per_user[lab]["reached_site"] = True
            reached = sorted(u for u, x in per_user.items() if x["reached_site"])
            ev.append(EvidenceItem(f"Umbrella: {d} resolved {len(rows)} time(s); users whose devices reached it: "
                                   f"{reached or 'none'}", "umbrella", "dns", {"domain": d, "reached": reached}))
    affected = sorted(u for u, x in per_user.items() if x["clicked"] or x["reached_site"])
    mde, cs, entra = _get(reg, "defender_endpoint"), _get(reg, "crowdstrike"), _get(reg, "entra")
    iocs = em.urls + em.url_domains + [a.sha256 for a in em.attachments]
    for u in affected:
        row = per_user[u]
        since = str(row.get("click_time") or em.date or "")[:19] or None
        if mde:
            try:
                devices = mde.lookup("user", u).records
                hits = []
                for d in devices:
                    fqdn = d.attributes.get("fqdn") or d.attributes.get("hostname")
                    hits += mde.process_activity(fqdn, (since or "2000-01-01T00:00:00") + "Z", iocs)
                row["endpoint"]["devices"] = [d.attributes.get("hostname") for d in devices]
                row["endpoint"]["device_keys"] = [{"hostname": d.attributes.get("hostname"),
                                                   "mde_device_id": d.keys.get("mde_device_id")} for d in devices]
                row["endpoint"]["ioc_activity"] = hits
                if hits:
                    ev.append(EvidenceItem(f"Endpoint: {len(hits)} process/network event(s) touching campaign indicators "
                                           f"on {row['endpoint']['devices']} for {u}", "defender_endpoint", "endpoint",
                                           {"user": u, "events": hits[:10]}))
            except Exception as exc:
                unavailable.append(f"defender_endpoint ({u}): {exc}")
        if cs:
            try:
                r = cs.lookup("user", u)
                row["endpoint"]["crowdstrike_alerts"] = r.signals.get("endpoint_alerts", 0)
                if r.signals.get("endpoint_alerts"):
                    ev.append(EvidenceItem(f"Endpoint: {r.summary}", "crowdstrike", "endpoint", {"user": u}))
            except Exception as exc:
                unavailable.append(f"crowdstrike ({u}): {exc}")
        if entra:
            try:
                ctx = entra.identity_context(u, since)
                risky = [s for s in ctx["signins"] if s.get("riskLevelDuringSignIn") not in (None, "none", "hidden")]
                row["identity"] = {"risky_signins": len(risky), "risky_ips": sorted({s.get("ipAddress") for s in risky}),
                                   "suspicious_inbox_rules": len(ctx["suspicious_inbox_rules"]),
                                   "new_devices": len(ctx["new_devices"]), "user_risk": (ctx["risky"] or {}).get("riskLevel"),
                                   "privileged_roles": ctx["privileged_roles"], "entra_object_id": ctx["user"].get("id")}
                if risky or ctx["suspicious_inbox_rules"] or ctx["new_devices"]:
                    ev.append(EvidenceItem(
                        f"Identity: {u} - {len(risky)} risky sign-in(s) from {row['identity']['risky_ips']}, "
                        f"{len(ctx['suspicious_inbox_rules'])} forwarding/hiding inbox rule(s), "
                        f"{len(ctx['new_devices'])} new device registration(s) after the click", "entra", "identity",
                        {"user": u, **row["identity"]}))
            except Exception as exc:
                unavailable.append(f"entra ({u}): {exc}")
    compromised = sorted(u for u, x in per_user.items()
                         if x["identity"].get("risky_signins") or x["identity"].get("suspicious_inbox_rules"))
    endpoint_hit = sorted(u for u, x in per_user.items() if x["endpoint"].get("ioc_activity")
                          or x["endpoint"].get("crowdstrike_alerts"))
    return {"per_user": per_user, "clicked": sorted(u for u, x in per_user.items() if x["clicked"]),
            "reached_site": sorted(u for u, x in per_user.items() if x["reached_site"]),
            "identity_compromise": compromised, "endpoint_impact": endpoint_hit, "evidence": ev,
            "unavailable": unavailable}
