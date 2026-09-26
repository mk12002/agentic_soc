"""Entity resolution engine (section 6.2, VM-F02, VM-T04, IM-T03, R01).

Order of precedence for every observed record:
  1. Analyst override for (tool, source_type, source_id) - durable, audited.
  2. Deterministic match on strong keys (agent IDs, device IDs, cloud resource ID,
     serial, MAC, Entra object ID, UPN...). Keys pointing at two different
     entities are a conflict and go to the unresolved queue.
  3. Scored probabilistic match on weak hints (normalised hostname/FQDN, IP within
     a time window, OS family). Auto-match only above ``auto_threshold`` with a
     clear margin; the grey zone goes to the unresolved queue - never silently merged.
  4. Otherwise a new canonical entity is created.
Identities are never fuzzy-merged automatically (wrong identity merges are worse
than duplicates); likely matches are queued for an analyst.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from rapidfuzz import fuzz
from sqlalchemy import and_, func, or_, select
from sqlalchemy.orm import Session

from soc_platform.core.audit import AuditLog
from soc_platform.core.auth import Perm, Principal
from soc_platform.core.models import (
    Entity,
    EntityHint,
    EntityKey,
    ResolutionOverride,
    SourceRecord,
    UnresolvedItem,
    utcnow,
)

STRONG_KEYS: dict[str, list[str]] = {
    "asset": ["crowdstrike_aid", "mde_device_id", "aad_device_id", "cloud_resource_id", "serial_number",
              "mac", "rapid7_asset_id", "wiz_id", "canary_device_id"],
    "identity": ["entra_object_id", "upn", "email", "sam", "sid", "delinea_user_id"],
    "indicator": ["value"],
}
# A differing value on one of these proves two records are NOT the same entity: one host has exactly
# one agent/device/asset id per tool, one cloud resource id and one serial.
CONFLICT_KEYS = {"serial_number", "cloud_resource_id", "entra_object_id", "crowdstrike_aid", "mde_device_id",
                 "rapid7_asset_id", "wiz_id", "canary_device_id"}
# Hardware-derived keys are shared by cloned VMs / docking stations / virtual NICs: a match on them alone is
# only trusted when the names do not contradict it (see EntityResolver._corroborated).
SHARED_PRONE_KEYS = {"serial_number", "mac"}
# Keys that can link records from *different* tools (tool-local ids such as a Rapid7 asset id cannot).
CROSS_TOOL_KEYS = {"serial_number", "mac", "cloud_resource_id", "aad_device_id", "entra_object_id", "upn", "email",
                   "sid", "value"}

_JUNK_MACS = {"000000000000", "ffffffffffff"}


# ----------------------------------------------------------------------------- normalisers


def norm_hostname(h: str | None) -> str:
    h = (h or "").strip().lower().rstrip(".")
    return h.split(".")[0] if h and not _is_ip(h) else h


def norm_fqdn(h: str | None) -> str:
    return (h or "").strip().lower().rstrip(".")


def norm_mac(m: str | None) -> str:
    v = re.sub(r"[^0-9a-f]", "", (m or "").lower())
    return "" if len(v) != 12 or v in _JUNK_MACS else v


def _is_ip(v: str) -> bool:
    try:
        ipaddress.ip_address(v)
        return True
    except ValueError:
        return False


def norm_indicator(ind_type: str, value: str) -> str:
    v = (value or "").strip()
    t = (ind_type or "").lower()
    if t in {"domain", "hostname", "email", "sha256", "sha1", "md5", "hash"}:
        v = v.lower().rstrip(".")
    elif t == "url":
        v = re.sub(r"^(https?://)([^/]+)", lambda m: m.group(1).lower() + m.group(2).lower(), v)
    elif t == "ip":
        try:
            v = str(ipaddress.ip_address(v))
        except ValueError:
            pass
    return f"{t}:{v}"


def normalize_keys(kind: str, keys: dict[str, Any]) -> dict[str, str]:
    out: dict[str, str] = {}
    for name, value in (keys or {}).items():
        if value in (None, ""):
            continue
        v = str(value).strip()
        if name == "mac":
            v = norm_mac(v)
        elif name in {"upn", "email", "sid", "sam"}:
            v = v.lower()
        elif name in {"serial_number"}:
            v = v.upper()
            if v in {"", "0", "NONE", "TO BE FILLED BY O.E.M.", "DEFAULT STRING"}:
                v = ""
        else:
            v = v.lower() if name != "value" else v
        if v and name in STRONG_KEYS.get(kind, []):
            out[name] = v
    return out


def hints_for(kind: str, attrs: dict[str, Any]) -> dict[str, list[str]]:
    h: dict[str, list[str]] = {}
    if kind == "asset":
        if attrs.get("hostname"):
            h["hostname"] = [norm_hostname(attrs["hostname"])]
            if "." in str(attrs["hostname"]) and not _is_ip(str(attrs["hostname"]).strip()):
                h.setdefault("fqdn", []).append(norm_fqdn(attrs["hostname"]))
        if attrs.get("fqdn"):
            h["fqdn"] = [norm_fqdn(attrs["fqdn"])]
            h.setdefault("hostname", []).append(norm_hostname(attrs["fqdn"]))
        ips = attrs.get("ips") or ([attrs["ip"]] if attrs.get("ip") else [])
        h["ip"] = [str(i) for i in ips if i and _is_ip(str(i))]
    elif kind == "identity":
        if attrs.get("display_name"):
            h["display_name"] = [str(attrs["display_name"]).strip().lower()]
        if attrs.get("derived_upn"):
            h["derived_upn"] = [str(attrs["derived_upn"]).strip().lower()]
    return {k: sorted(set(v)) for k, v in h.items() if v}


# ----------------------------------------------------------------------------- scoring


@dataclass
class Candidate:
    entity_id: str
    score: float
    reasons: list[str] = field(default_factory=list)
    exact: bool = False  # exact hostname/FQDN (asset) or display name (identity) match
    provisional: bool = False  # candidate is a nameless (IP-only) entity


def score_asset(obs_hints: dict[str, list[str]], obs_attrs: dict[str, Any], obs_time: datetime,
                cand: Entity, cand_hints: dict[str, set[str]], ip_window: timedelta) -> Candidate:
    score = 0.0
    reasons: list[str] = []
    exact = False
    obs_fqdn = set(obs_hints.get("fqdn", []))
    last_seen = _aware(cand.last_seen)
    recent = abs(_aware(obs_time) - last_seen) <= timedelta(days=30)
    if obs_fqdn & cand_hints.get("fqdn", set()):
        score += 0.75 if recent else 0.6
        exact = True
        reasons.append("fqdn exact" + (" (recently seen)" if recent else " (stale)"))
    else:
        best = 0.0
        for a in obs_hints.get("hostname", []):
            for b in cand_hints.get("hostname", set()):
                best = max(best, fuzz.ratio(a, b) / 100.0)
        if best >= 0.9:
            score += 0.5 * best if best == 1.0 else 0.4 * best
            exact = best == 1.0
            reasons.append(f"hostname similarity {best:.2f}")
    if set(obs_hints.get("ip", [])) & cand_hints.get("ip", set()):
        if abs(_aware(obs_time) - last_seen) <= ip_window:
            score += 0.2
            reasons.append("ip match within window")
        else:
            reasons.append("ip match outside window (ignored)")
    obs_os = _os_family(obs_attrs.get("os"))
    cand_os = _os_family((cand.attributes or {}).get("os"))
    if obs_os and cand_os:
        if obs_os == cand_os:
            score += 0.1
            reasons.append(f"os family {obs_os}")
        else:
            score -= 0.4
            reasons.append(f"os family mismatch {obs_os}/{cand_os}")
    if score < 0.3:
        exact = False  # e.g. hostname match cancelled out by an OS mismatch
    return Candidate(cand.id, round(max(score, 0.0), 3), reasons, exact)


def _os_family(os_name: Any) -> str:
    s = str(os_name or "").lower()
    if any(d in s for d in ("ubuntu", "debian", "red hat", "rhel", "centos", "suse", "amazon linux", "oracle linux",
                            "rocky", "alma", "fedora")):
        return "linux"
    for fam in ("windows", "macos", "linux", "ios", "android"):
        if fam in s or (fam == "macos" and ("mac os" in s or "darwin" in s)):
            return fam
    return ""


def _aware(dt: datetime | None) -> datetime:
    dt = dt or utcnow()
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


# ----------------------------------------------------------------------------- resolver


@dataclass
class ResolutionResult:
    status: str  # matched | created | unresolved
    entity_id: str | None
    method: str  # override | deterministic | probabilistic | new | conflict | ambiguous
    confidence: float
    candidates: list[Candidate] = field(default_factory=list)
    merge_ids: list[str] = field(default_factory=list)  # other entities proven identical by an authoritative record


# Keys whose owner is authoritative for identity (directory object id, hardware / cloud / agent ids).
AUTHORITATIVE_KEYS = {"entra_object_id", "serial_number", "cloud_resource_id", "crowdstrike_aid", "mde_device_id"}


class EntityResolver:
    def __init__(self, session: Session, *, auto_threshold: float = 0.85, review_threshold: float = 0.55,
                 margin: float = 0.1, ip_window: timedelta = timedelta(days=3)) -> None:
        self.s = session
        self.auto_threshold = auto_threshold
        self.review_threshold = review_threshold
        self.margin = margin
        self.ip_window = ip_window

    def resolve(self, kind: str, *, keys: dict[str, Any], attributes: dict[str, Any], tool: str,
                source_type: str, source_id: str, observed_at: datetime | None = None,
                reference: bool = False) -> ResolutionResult:
        """Resolve one observation. ``reference=True`` is for entities merely *referenced* by an
        event (an alert naming a host): a single exact hostname/FQDN candidate is linked with its
        confidence recorded, instead of creating a duplicate entity per event."""
        observed_at = observed_at or utcnow()
        override = self.s.execute(
            select(ResolutionOverride).where(ResolutionOverride.tool == tool,
                                             ResolutionOverride.source_type == source_type,
                                             ResolutionOverride.source_id == source_id)
        ).scalars().first()
        if override:
            return ResolutionResult("matched", override.entity_id, "override", 1.0)

        nkeys = normalize_keys(kind, keys)
        if nkeys:
            pairs = set(nkeys.items())
            if kind == "identity":  # a UPN and a primary/alias email are the same namespace
                for v in [nkeys[k] for k in ("upn", "email") if k in nkeys]:
                    pairs |= {("upn", v), ("email", v)}
            hits = self.s.execute(
                select(EntityKey.entity_id, EntityKey.key_name).where(
                    EntityKey.kind == kind,
                    or_(*[and_(EntityKey.key_name == k, EntityKey.key_value == v) for k, v in pairs]),
                )
            ).all()
            strong_hits = {h.entity_id for h in hits if h.key_name not in SHARED_PRONE_KEYS}
            weak_hits = {h.entity_id for h in hits if h.key_name in SHARED_PRONE_KEYS}
            ids = strong_hits or {e for e in weak_hits if self._corroborated(e, attributes)}
            if not strong_hits and weak_hits and not ids:
                ids = set()  # shared serial/MAC contradicted by names -> fall through to fuzzy / new entity
                nkeys = {k: v for k, v in nkeys.items() if k not in SHARED_PRONE_KEYS}
            if len(ids) == 1:
                eid = next(iter(ids))
                if not self._conflicts(eid, nkeys):
                    return ResolutionResult("matched", eid, "deterministic", 1.0)
                return ResolutionResult("unresolved", None, "conflict", 0.0,
                                        [Candidate(eid, 1.0, ["strong key match but conflicting serial/cloud id"])])
            if len(ids) > 1:
                # An authoritative record (e.g. the directory entry) that matches several partial entities by
                # *different* keys proves they are one entity - provided none of them contradicts it.
                if set(nkeys) & AUTHORITATIVE_KEYS and not any(self._conflicts(i, nkeys) for i in ids)                         and not self._mutually_conflicting(sorted(ids)):
                    primary = max(ids, key=lambda i: (self._has_authoritative(i), -len(self._keys(i))))
                    return ResolutionResult("matched", primary, "deterministic_merge", 1.0,
                                            merge_ids=sorted(i for i in ids if i != primary))
                return ResolutionResult("unresolved", None, "conflict", 0.0,
                                        [Candidate(i, 1.0, ["shares a strong key"]) for i in sorted(ids)])

        if kind == "identity" and attributes.get("derived_upn"):
            d = str(attributes["derived_upn"]).lower()
            ids = set(self.s.execute(select(EntityKey.entity_id).where(
                EntityKey.kind == "identity", EntityKey.key_name.in_(("upn", "email")), EntityKey.key_value == d)).scalars())
            if len(ids) == 1:
                return ResolutionResult("matched", next(iter(ids)), "derived_upn", 0.9)
        if kind == "indicator":
            return ResolutionResult("created", None, "new", 1.0)

        obs_hints = hints_for(kind, attributes)
        cands = self._fuzzy_candidates(kind, obs_hints, attributes, observed_at, nkeys)
        ip_only = (kind == "asset" and not (set(nkeys) & CROSS_TOOL_KEYS) and not obs_hints.get("hostname")
                   and not obs_hints.get("fqdn"))
        if ip_only and cands and not reference:
            return ResolutionResult("unresolved", None, "ip_only", cands[0].score,
                                    [*cands[:5]] or [])
        if cands:
            best = cands[0]
            second = cands[1].score if len(cands) > 1 else 0.0
            if kind == "asset" and best.score >= self.auto_threshold and best.score - second >= self.margin:
                return ResolutionResult("matched", best.entity_id, "probabilistic", best.score, cands[:5])
            exact = [c for c in cands if c.exact]
            if reference and len(exact) == 1 and exact[0].score >= 0.45 and                     (len(cands) == 1 or exact[0].score - cands[1].score >= self.margin or cands[0] is exact[0]):
                return ResolutionResult("matched", exact[0].entity_id, "reference_link", exact[0].score, cands[:5])
            if best.score >= self.review_threshold:
                return ResolutionResult("unresolved", None, "ambiguous", best.score, cands[:5])
        return ResolutionResult("created", None, "new", 1.0 if nkeys else 0.7)

    # ------------------------------------------------------------------ helpers

    def _corroborated(self, entity_id: str, attrs: dict[str, Any]) -> bool:
        """A serial/MAC match counts only if the entity's known names do not contradict the observation."""
        obs = set(hints_for("asset", attrs).get("hostname", []))
        if not obs:
            return True
        known = {v for (v,) in self.s.execute(select(EntityHint.hint_value).where(
            EntityHint.entity_id == entity_id, EntityHint.hint_name == "hostname")).all()}
        if not known:
            return True
        return any(fuzz.ratio(a, b) >= 90 for a in obs for b in known)

    def _has_authoritative(self, entity_id: str) -> bool:
        return self.s.execute(select(EntityKey.id).where(EntityKey.entity_id == entity_id,
                                                         EntityKey.key_name.in_(AUTHORITATIVE_KEYS))).first() is not None

    def _mutually_conflicting(self, ids: list[str]) -> bool:
        seen: dict[str, str] = {}
        for i in ids:
            for k, v in self.s.execute(select(EntityKey.key_name, EntityKey.key_value).where(
                    EntityKey.entity_id == i, EntityKey.key_name.in_(AUTHORITATIVE_KEYS))).all():
                if k in seen and seen[k] != v:
                    return True
                seen[k] = v
        return False

    def _conflicts(self, entity_id: str, nkeys: dict[str, str]) -> bool:
        existing = self.s.execute(
            select(EntityKey.key_name, EntityKey.key_value).where(EntityKey.entity_id == entity_id)
        ).all()
        have: dict[str, set[str]] = {}
        for k, v in existing:
            have.setdefault(k, set()).add(v)
        for k in CONFLICT_KEYS:
            if k in nkeys and k in have and nkeys[k] not in have[k]:
                return True
        return False

    def _fuzzy_candidates(self, kind: str, obs_hints: dict[str, list[str]], attrs: dict[str, Any],
                          observed_at: datetime, nkeys: dict[str, str]) -> list[Candidate]:
        if not obs_hints:
            return []
        pairs = [(n, v) for n, vals in obs_hints.items() for v in vals]
        rows = self.s.execute(
            select(EntityHint.entity_id).where(
                EntityHint.kind == kind,
                or_(*[and_(EntityHint.hint_name == n, EntityHint.hint_value == v) for n, v in pairs]),
            ).distinct()
        ).scalars().all()
        # Near-miss hostnames (e.g. "web01" vs "web-01") via prefix scan on the short name.
        for h in obs_hints.get("hostname", [])[:3]:
            if len(h) >= 4:
                rows += self.s.execute(
                    select(EntityHint.entity_id).where(EntityHint.kind == kind, EntityHint.hint_name == "hostname",
                                                       EntityHint.hint_value.like(f"{h[:4]}%")).distinct().limit(50)
                ).scalars().all()
        out: list[Candidate] = []
        for eid in dict.fromkeys(rows):
            if nkeys and self._conflicts(eid, nkeys):
                continue
            ent = self.s.get(Entity, eid)
            if ent is None:
                continue
            ch: dict[str, set[str]] = {}
            for n, v in self.s.execute(select(EntityHint.hint_name, EntityHint.hint_value)
                                       .where(EntityHint.entity_id == eid)).all():
                ch.setdefault(n, set()).add(v)
            if kind == "asset":
                c = score_asset(obs_hints, attrs, observed_at, ent, ch, self.ip_window)
                provisional = not ch.get("hostname") and not ch.get("fqdn")
                if provisional and "ip match within window" in c.reasons and (obs_hints.get("hostname") or obs_hints.get("fqdn")):
                    c.score, c.provisional = max(c.score, 0.7), True
                    c.reasons.append("upgrades a nameless IP-only record")
                out.append(c)
            elif kind == "identity":
                best = max((fuzz.token_sort_ratio(a, b) / 100.0 for a in obs_hints.get("display_name", [])
                            for b in ch.get("display_name", set())), default=0.0)
                if best >= 0.9:
                    out.append(Candidate(eid, round(best * 0.8, 3), [f"display name similarity {best:.2f}"],
                                         exact=best == 1.0))
        prov = [c for c in out if c.provisional]
        if kind == "asset" and len(prov) == 1 and not any(c.exact for c in out):
            prov[0].score = round(min(1.0, prov[0].score + 0.15), 3)  # single nameless record at this IP
        exact = [c for c in out if c.exact]
        if kind == "asset" and len(exact) == 1 and exact[0].score >= 0.5:
            exact[0].score = round(min(1.0, exact[0].score + 0.15), 3)
            exact[0].reasons.append("only entity with this exact name")
        return sorted(out, key=lambda c: c.score, reverse=True)

    def register(self, entity: Entity, kind: str, keys: dict[str, Any], attributes: dict[str, Any]) -> list[tuple[str, str]]:
        """Index strong keys and weak hints for an entity after a match/create.

        A key already owned by *another* entity is never moved (that would silently merge two things);
        it is returned as a collision so the caller can surface it for review."""
        collisions: list[tuple[str, str]] = []
        pairs = list(normalize_keys(kind, keys).items())
        if kind == "identity":
            pairs += [("email", str(a).lower()) for a in (attributes.get("email_aliases") or []) if "@" in str(a)]
        for name, value in pairs:
            exists = self.s.execute(select(EntityKey).where(EntityKey.kind == kind, EntityKey.key_name == name,
                                                            EntityKey.key_value == value)).scalars().first()
            if exists is None:
                self.s.add(EntityKey(entity_id=entity.id, kind=kind, key_name=name, key_value=value))
            elif exists.entity_id != entity.id:
                collisions.append((name, value))
        for name, values in hints_for(kind, attributes).items():
            for v in values:
                exists = self.s.execute(select(EntityHint).where(EntityHint.entity_id == entity.id,
                                                                 EntityHint.hint_name == name,
                                                                 EntityHint.hint_value == v)).scalars().first()
                if exists is None:
                    self.s.add(EntityHint(entity_id=entity.id, kind=kind, hint_name=name, hint_value=v))
                else:
                    exists.seen_at = utcnow()
        self.s.flush()
        return collisions

    def key_owner(self, kind: str, name: str, value: str) -> str | None:
        return self.s.execute(select(EntityKey.entity_id).where(EntityKey.kind == kind, EntityKey.key_name == name,
                                                                EntityKey.key_value == value)).scalars().first()

    def absorb_provisional(self, entity: Entity, attrs: dict[str, Any], observed_at: datetime) -> list[str]:
        """Merge a single nameless (IP-only) asset seen at the same IP within the window into ``entity``."""
        ips = hints_for("asset", attrs).get("ip", [])
        if not ips or not (hints_for("asset", attrs).get("hostname") or hints_for("asset", attrs).get("fqdn")):
            return []
        cands = set(self.s.execute(select(EntityHint.entity_id).where(
            EntityHint.kind == "asset", EntityHint.hint_name == "ip", EntityHint.hint_value.in_(ips),
            EntityHint.entity_id != entity.id)).scalars().all())
        prov = []
        for eid in cands:
            names = self.s.execute(select(EntityHint.id).where(EntityHint.entity_id == eid, EntityHint.hint_name.in_(
                ("hostname", "fqdn")))).first()
            other = self.s.get(Entity, eid)
            if names or other is None or abs(_aware(other.last_seen) - _aware(observed_at)) > self.ip_window:
                continue
            ok = self.s.execute(select(EntityKey.key_name).where(EntityKey.entity_id == eid,
                                                                 EntityKey.key_name.in_(CROSS_TOOL_KEYS))).first()
            if ok is None and not self._conflicts(entity.id, {k: v for k, v in self._keys(eid).items()}):
                prov.append(eid)
        if len(prov) != 1:
            return []
        merge_entities(self.s, prov[0], entity.id, reason="named record at same IP upgraded a nameless record")
        return prov

    def absorb_identity_aliases(self, entity: Entity) -> list[str]:
        r"""Order independence for users: a SAM-only identity created earlier (e.g. from ``ACME\jane.doe`` before the
        directory record arrived) whose derived UPN equals one of this entity's UPN/email keys is merged into it -
        only when exactly one such provisional identity exists and no strong keys conflict."""
        mine = {v for (v,) in self.s.execute(select(EntityKey.key_value).where(
            EntityKey.entity_id == entity.id, EntityKey.key_name.in_(("upn", "email")))).all()}
        if not mine:
            return []
        cands = set(self.s.execute(select(EntityHint.entity_id).where(
            EntityHint.kind == "identity", EntityHint.hint_name == "derived_upn", EntityHint.hint_value.in_(mine),
            EntityHint.entity_id != entity.id)).scalars())
        prov = []
        for eid in cands:
            has_upn = self.s.execute(select(EntityKey.id).where(EntityKey.entity_id == eid,
                                                                EntityKey.key_name.in_(("upn", "email", "entra_object_id")))).first()
            if has_upn is None and not self._conflicts(entity.id, self._keys(eid)):
                prov.append(eid)
        merged: list[str] = []
        if len(prov) == 1:
            merge_entities(self.s, prov[0], entity.id, reason="directory identity absorbed an earlier account-name-only record")
            merged.append(prov[0])
        # A directory record (entra_object_id) is authoritative for the addresses it lists (primary + proxy
        # addresses are unique per tenant): address-only identities created earlier from an alias or an old
        # address are the same mailbox.
        if self.s.execute(select(EntityKey.id).where(EntityKey.entity_id == entity.id,
                                                     EntityKey.key_name == "entra_object_id")).first() is not None:
            owners = set(self.s.execute(select(EntityKey.entity_id).where(
                EntityKey.kind == "identity", EntityKey.key_name.in_(("upn", "email")), EntityKey.key_value.in_(mine),
                EntityKey.entity_id != entity.id)).scalars())
            for eid in sorted(owners):
                other = self._keys(eid)
                if set(other) <= {"upn", "email"} and not self._conflicts(entity.id, other):
                    merge_entities(self.s, eid, entity.id, reason="directory identity owns this address (alias / former address)")
                    merged.append(eid)
        return merged

    def _keys(self, entity_id: str) -> dict[str, str]:
        return {k: v for k, v in self.s.execute(select(EntityKey.key_name, EntityKey.key_value)
                                                .where(EntityKey.entity_id == entity_id)).all()}

    # ------------------------------------------------------------------ analyst workflow & metrics

    def override(self, unresolved_id: str, entity_id: str | None, by: Principal, reason: str = "") -> SourceRecord:
        """Analyst decision: link the queued record to ``entity_id`` (or create a new entity if None)."""
        if not by.can(Perm.RESOLVE_ENTITIES):
            raise PermissionError("resolve_entities permission required")
        item = self.s.get(UnresolvedItem, unresolved_id)
        if item is None or item.status != "open":
            raise ValueError("unresolved item not open")
        rec = self.s.get(SourceRecord, item.source_record_id)
        assert rec is not None
        attrs = rec.normalized.get("attributes", {})
        keys = rec.normalized.get("keys", {})
        if entity_id is None:
            ent = Entity(kind=rec.kind, display_name=_display(rec.kind, attrs, keys), attributes=dict(attrs))
            self.s.add(ent)
            self.s.flush()
        else:
            ent = self.s.get(Entity, entity_id)
            if ent is None:
                raise ValueError("unknown entity")
        rec.entity_id = ent.id
        rec.resolution_method = "override"
        rec.resolution_confidence = 1.0
        self.register(ent, rec.kind, keys, attrs)
        self.s.add(ResolutionOverride(kind=rec.kind, tool=rec.tool, source_type=rec.source_type,
                                      source_id=rec.source_id, entity_id=ent.id, decided_by=by.id, reason=reason))
        item.status, item.resolved_by = "resolved", by.id
        AuditLog(self.s).append(actor_type=by.actor_type, actor_id=by.id, event_type="resolution.override",
                                subject_type="source_record", subject_id=rec.id,
                                payload={"entity_id": ent.id, "reason": reason, "unresolved_id": item.id})
        return rec

    def match_rate(self, kind: str) -> dict[str, Any]:
        total = self.s.execute(select(func.count()).select_from(SourceRecord)
                               .where(SourceRecord.kind == kind)).scalar() or 0
        resolved = self.s.execute(select(func.count()).select_from(SourceRecord)
                                  .where(SourceRecord.kind == kind, SourceRecord.entity_id.is_not(None))).scalar() or 0
        by_method = dict(self.s.execute(
            select(SourceRecord.resolution_method, func.count()).where(SourceRecord.kind == kind)
            .group_by(SourceRecord.resolution_method)).all())
        entities = self.s.execute(select(func.count()).select_from(Entity).where(Entity.kind == kind)).scalar() or 0
        return {
            "kind": kind,
            "source_records": total,
            "resolved": resolved,
            "unresolved": total - resolved,
            "match_rate": round(resolved / total, 4) if total else None,
            "canonical_entities": entities,
            "by_method": {str(k): v for k, v in by_method.items()},
        }


def _display(kind: str, attrs: dict[str, Any], keys: dict[str, Any]) -> str:
    if kind == "asset":
        return str(attrs.get("fqdn") or attrs.get("hostname") or next(iter(keys.values()), "asset"))
    if kind == "identity":
        return str(keys.get("upn") or keys.get("email") or attrs.get("display_name") or "identity")
    return str(keys.get("value") or attrs.get("value") or kind)


def merge_entities(session: Session, src_id: str, dst_id: str, *, reason: str, actor: str = "agent:resolution") -> None:
    """Re-point everything that references ``src_id`` to ``dst_id`` and remove ``src_id`` (audited)."""
    from soc_platform.core.models import CaseEntity, Evidence, Relation

    src, dst = session.get(Entity, src_id), session.get(Entity, dst_id)
    if src is None or dst is None or src_id == dst_id:
        return
    for model, col in ((SourceRecord, SourceRecord.entity_id), (EntityHint, EntityHint.entity_id),
                       (Evidence, Evidence.entity_id), (ResolutionOverride, ResolutionOverride.entity_id)):
        for row in session.execute(select(model).where(col == src_id)).scalars():
            row.entity_id = dst_id
    for k in session.execute(select(EntityKey).where(EntityKey.entity_id == src_id)).scalars():
        k.entity_id = dst_id
    for r in session.execute(select(Relation).where((Relation.src_id == src_id) | (Relation.dst_id == src_id))).scalars():
        ns, nd = (dst_id if r.src_id == src_id else r.src_id), (dst_id if r.dst_id == src_id else r.dst_id)
        dup = session.execute(select(Relation).where(Relation.src_id == ns, Relation.dst_id == nd,
                                                     Relation.rel_type == r.rel_type, Relation.id != r.id)).scalars().first()
        if dup is not None or ns == nd:
            session.delete(r)
        else:
            r.src_id, r.dst_id = ns, nd
    for ce in session.execute(select(CaseEntity).where(CaseEntity.entity_id == src_id)).scalars():
        ce.entity_id = dst_id
    merged = dict(dst.attributes or {})
    for k, v in (src.attributes or {}).items():
        if k == "by_tool":
            merged["by_tool"] = {**(v or {}), **(merged.get("by_tool") or {})}
        else:
            merged.setdefault(k, v)
    dst.attributes = merged
    dst.first_seen = min(_aware(dst.first_seen), _aware(src.first_seen))
    session.flush()
    session.delete(src)
    session.flush()
    AuditLog(session).append(actor_type="agent", actor_id=actor, event_type="resolution.merge", subject_type="entity",
                             subject_id=dst_id, payload={"merged": src_id, "reason": reason})
