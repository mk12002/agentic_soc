"""Shared, time-aware context store (section 5.3, IM-T03).

``ingest()`` takes a ``NormalizedRecord`` from any connector, keeps full source
provenance (and the raw payload in object storage), resolves entities through
the ``EntityResolver`` and links events to the entities they reference. Pivot
and timeline queries serve all three domains from the same store.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from pathlib import Path
from typing import Any

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from soc_platform.core.entity_resolution import EntityResolver, ResolutionResult, _display, norm_indicator
from soc_platform.core.models import Entity, EntityKey, Relation, SourceRecord, UnresolvedItem, utcnow
from soc_platform.core.schema import EntityRef, NormalizedRecord


class RawStore:
    """Object storage for raw source payloads (VM-T05). Local filesystem in dev; blob in prod.

    Payloads are encrypted at rest when ``SOC_DATA_KEY`` is configured (mandatory in prod)."""

    def __init__(self, root: str | Path, cipher: Any = "auto") -> None:
        from soc_platform.core.crypto import get_cipher

        self.root = Path(root)
        self.cipher = get_cipher() if cipher == "auto" else cipher

    def put(self, tool: str, source_type: str, source_id: str, payload: dict[str, Any]) -> str:
        from soc_platform.core.crypto import write_protected

        digest = hashlib.sha256(f"{tool}|{source_type}|{source_id}".encode()).hexdigest()[:32]
        path = self.root / _safe(tool) / _safe(source_type) / f"{digest}.json"
        write_protected(path, json.dumps(payload, default=str, indent=1).encode("utf-8"), self.cipher)
        return str(path)

    def get(self, ref: str) -> dict[str, Any]:
        from soc_platform.core.crypto import read_protected

        p = Path(ref).resolve()
        if self.root.resolve() not in p.parents:
            raise PermissionError("raw reference outside the raw store")
        return json.loads(read_protected(p, self.cipher).decode("utf-8"))


def _safe(part: str) -> str:
    """Path component from tool/stream names: no traversal, no separators."""
    return "".join(ch if ch.isalnum() or ch in "-_." else "_" for ch in str(part)).strip(".") or "_"


class ContextStore:
    def __init__(self, session: Session, raw_store: RawStore | None = None,
                 resolver: EntityResolver | None = None) -> None:
        self.s = session
        self.raw = raw_store
        self.resolver = resolver or EntityResolver(session)

    # ------------------------------------------------------------------ ingest

    def ingest(self, rec: NormalizedRecord) -> SourceRecord:
        observed = rec.observed_at or utcnow()
        src = self.s.execute(select(SourceRecord).where(
            SourceRecord.tool == rec.tool, SourceRecord.source_type == rec.source_type,
            SourceRecord.source_id == rec.source_id)).scalars().first()
        normalized = rec.model_dump(mode="json", exclude={"raw"})
        if src is None:
            src = SourceRecord(kind=rec.kind, tool=rec.tool, source_type=rec.source_type, source_id=rec.source_id,
                               first_seen=observed)
            self.s.add(src)
        src.normalized = normalized
        src.last_seen = observed
        src.fetched_at = utcnow()
        src.deep_link = rec.deep_link
        if rec.raw is not None and self.raw is not None:
            src.raw_ref = self.raw.put(rec.tool, rec.source_type, rec.source_id, rec.raw)
        self.s.flush()

        if rec.is_entity:
            if src.entity_id is None:
                self._resolve_entity_record(src, rec.kind, rec.keys, rec.attributes, observed)
            else:
                ent = self.s.get(Entity, src.entity_id)
                if ent is not None:
                    self._touch(ent, rec.attributes, observed, rec.tool)
                    collisions = self.resolver.register(ent, rec.kind, rec.keys, rec.attributes)
                    if rec.kind == "identity":
                        self.resolver.absorb_identity_aliases(ent)
                    self._queue_collisions(src, ent, rec.kind, collisions)
        else:
            event = self._event_entity(src, rec, observed)
            for ref in rec.refs:
                target = self.resolve_ref(ref, rec.tool, observed, source=src)
                if target is not None:
                    self.relate(event.id, target.id, ref.role, source_tool=rec.tool, when=observed)
        return src

    def resolve_ref(self, ref: EntityRef, tool: str, observed: datetime,
                    source: SourceRecord | None = None) -> Entity | None:
        keys = dict(ref.keys)
        if ref.kind == "indicator":
            itype = ref.attributes.get("type") or next(iter(keys), "value")
            value = keys.get("value") or next(iter(keys.values()), "")
            keys = {"value": norm_indicator(str(itype), str(value))}
        res = self.resolver.resolve(ref.kind, keys=keys, attributes=ref.attributes, tool=tool,
                                    source_type=f"ref:{ref.role}", source_id=json.dumps(keys, sort_keys=True),
                                    observed_at=observed, reference=True)
        if res.status == "unresolved":
            if source is not None:
                self._queue(source, ref.kind, res, reason=f"ambiguous {ref.kind} reference ({ref.role})",
                            extra={"ref": ref.model_dump()})
            return None
        return self._materialise(res, ref.kind, keys, ref.attributes, observed, tool)

    def _resolve_entity_record(self, src: SourceRecord, kind: str, keys: dict[str, Any],
                               attrs: dict[str, Any], observed: datetime) -> None:
        if kind == "indicator":
            keys = {"value": norm_indicator(str(attrs.get("type", "")), str(keys.get("value") or attrs.get("value", "")))}
        res = self.resolver.resolve(kind, keys=keys, attributes=attrs, tool=src.tool, source_type=src.source_type,
                                    source_id=src.source_id, observed_at=observed)
        if res.status == "unresolved":
            src.resolution_method = res.method
            src.resolution_confidence = res.confidence
            self._queue(src, kind, res, reason=f"{res.method} match")
            return
        ent = self._materialise(res, kind, keys, attrs, observed, src.tool)
        src.entity_id = ent.id
        src.resolution_method = res.method
        src.resolution_confidence = res.confidence
        if kind == "asset":
            self.resolver.absorb_provisional(ent, attrs, observed)
        elif kind == "identity":
            self.resolver.absorb_identity_aliases(ent)

    def _materialise(self, res: ResolutionResult, kind: str, keys: dict[str, Any], attrs: dict[str, Any],
                     observed: datetime, tool: str) -> Entity:
        if res.entity_id:
            from soc_platform.core.entity_resolution import merge_entities

            for other in res.merge_ids:
                merge_entities(self.s, other, res.entity_id, reason=f"authoritative {tool} record matched both")
            ent = self.s.get(Entity, res.entity_id)
            assert ent is not None
            self._touch(ent, attrs, observed, tool)
        else:
            ent = Entity(kind=kind, display_name=_display(kind, attrs, keys), attributes=dict(attrs),
                         confidence=res.confidence, first_seen=observed, last_seen=observed,
                         canonical_key=keys.get("value") if kind == "indicator" else None)
            ent.attributes["by_tool"] = {tool: dict(attrs)}
            self.s.add(ent)
            self.s.flush()
        self.resolver.register(ent, kind, keys, attrs)
        if kind == "identity":
            self.resolver.absorb_identity_aliases(ent)
        return ent

    def _touch(self, ent: Entity, attrs: dict[str, Any], observed: datetime, tool: str) -> None:
        if ent.kind == "asset":
            fq = attrs.get("fqdn") or (attrs.get("hostname") if "." in str(attrs.get("hostname") or "") else None)
            if fq and "." not in (ent.display_name or ""):
                ent.display_name = str(fq).lower()
        merged = dict(ent.attributes or {})
        by_tool = dict(merged.get("by_tool") or {})
        by_tool[tool] = {**by_tool.get(tool, {}), **attrs}
        for k, v in attrs.items():
            if v not in (None, "", [], {}):
                merged.setdefault(k, v)
        merged["by_tool"] = by_tool
        ent.attributes = merged
        if observed and (ent.last_seen is None or observed.replace(tzinfo=None) > ent.last_seen.replace(tzinfo=None)):
            ent.last_seen = observed

    def _event_entity(self, src: SourceRecord, rec: NormalizedRecord, observed: datetime) -> Entity:
        key = f"{rec.tool}:{rec.source_type}:{rec.source_id}"
        ent = self.s.execute(select(Entity).where(Entity.kind == rec.kind, Entity.canonical_key == key)).scalars().first()
        attrs = {**rec.attributes, "severity": rec.severity, "tool": rec.tool, "dimension": rec.dimension,
                 "deep_link": rec.deep_link}
        if ent is None:
            ent = Entity(kind=rec.kind, canonical_key=key, display_name=rec.title or key, attributes=attrs,
                         first_seen=observed, last_seen=observed)
            self.s.add(ent)
            self.s.flush()
        else:
            ent.attributes = {**(ent.attributes or {}), **attrs}
            ent.last_seen = observed
        src.entity_id = ent.id
        src.resolution_method = "event"
        src.resolution_confidence = 1.0
        return ent

    def _queue_collisions(self, src: SourceRecord, ent: Entity, kind: str, collisions: list[tuple[str, str]]) -> None:
        """A re-synced record now carries a key another entity owns (e.g. an address reassigned to a different
        user, or a corrupted record). Never merge automatically; ask an analyst."""
        from soc_platform.core.entity_resolution import Candidate

        owners = {}
        for name, value in collisions:
            owner = self.resolver.key_owner(kind, name, value)
            if owner and owner != ent.id:
                owners.setdefault(owner, []).append(f"{name}={value}")
        if owners:
            res = ResolutionResult("unresolved", None, "key_collision", 0.0,
                                   [Candidate(ent.id, 1.0, ["current owner of this record"])] +
                                   [Candidate(o, 0.0, [f"already owns {', '.join(v)}"]) for o, v in owners.items()])
            self._queue(src, kind, res, reason="key_collision: record carries keys owned by another entity")

    def _queue(self, src: SourceRecord, kind: str, res: ResolutionResult, reason: str,
               extra: dict[str, Any] | None = None) -> None:
        open_item = self.s.execute(select(UnresolvedItem).where(
            UnresolvedItem.source_record_id == src.id, UnresolvedItem.status == "open",
            UnresolvedItem.kind == kind)).scalars().first()
        cands = [{"entity_id": c.entity_id, "score": c.score, "reasons": c.reasons} for c in res.candidates]
        if extra:
            cands.append({"context": extra})
        if open_item is None:
            self.s.add(UnresolvedItem(source_record_id=src.id, kind=kind, candidates=cands, reason=reason))
        else:
            open_item.candidates = cands

    # ------------------------------------------------------------------ relations & queries

    def relate(self, src_id: str, dst_id: str, rel_type: str, *, source_tool: str | None = None,
               when: datetime | None = None, attributes: dict[str, Any] | None = None) -> Relation:
        rel = self.s.execute(select(Relation).where(Relation.src_id == src_id, Relation.dst_id == dst_id,
                                                    Relation.rel_type == rel_type)).scalars().first()
        when = when or utcnow()
        if rel is None:
            rel = Relation(src_id=src_id, dst_id=dst_id, rel_type=rel_type, source_tool=source_tool,
                           attributes=attributes or {}, first_seen=when, last_seen=when)
            self.s.add(rel)
        else:
            rel.last_seen = when
            if attributes:
                rel.attributes = {**rel.attributes, **attributes}
        self.s.flush()
        return rel

    def find(self, kind: str, key_name: str, value: str) -> Entity | None:
        if kind == "indicator" and key_name != "value":
            value, key_name = norm_indicator(key_name, value), "value"
        from soc_platform.core.entity_resolution import normalize_keys

        nk = normalize_keys(kind, {key_name: value})
        if not nk:
            return None
        k, v = next(iter(nk.items()))
        eid = self.s.execute(select(EntityKey.entity_id).where(EntityKey.kind == kind, EntityKey.key_name == k,
                                                               EntityKey.key_value == v)).scalar()
        return self.s.get(Entity, eid) if eid else None

    def keys_of(self, entity_id: str) -> dict[str, str]:
        """Strong identifiers of an entity (first value per key name) - used to build action targets."""
        out: dict[str, str] = {}
        for name, value in self.s.execute(select(EntityKey.key_name, EntityKey.key_value)
                                          .where(EntityKey.entity_id == entity_id)).all():
            out.setdefault(name, value)
        return out

    def neighbors(self, entity_id: str, *, kinds: set[str] | None = None,
                  since: datetime | None = None) -> list[tuple[Relation, Entity]]:
        rels = self.s.execute(select(Relation).where(or_(Relation.src_id == entity_id,
                                                         Relation.dst_id == entity_id))).scalars().all()
        out = []
        for r in rels:
            if since and r.last_seen.replace(tzinfo=None) < since.replace(tzinfo=None):
                continue
            other_id = r.dst_id if r.src_id == entity_id else r.src_id
            other = self.s.get(Entity, other_id)
            if other is not None and (kinds is None or other.kind in kinds):
                out.append((r, other))
        return out

    def events_for(self, entity_id: str, *, kinds: set[str] | None = None,
                   since: datetime | None = None, until: datetime | None = None) -> list[Entity]:
        events = [e for _, e in self.neighbors(entity_id) if e.kind not in {"asset", "identity", "indicator"}]
        if kinds:
            events = [e for e in events if e.kind in kinds]
        if since:
            events = [e for e in events if e.first_seen.replace(tzinfo=None) >= since.replace(tzinfo=None)]
        if until:
            events = [e for e in events if e.first_seen.replace(tzinfo=None) <= until.replace(tzinfo=None)]
        return events

    def timeline(self, entity_ids: list[str], *, since: datetime | None = None,
                 until: datetime | None = None) -> list[dict[str, Any]]:
        """Unified chronological timeline across all tools for a set of entities (IM-F05)."""
        seen: dict[str, Entity] = {}
        for eid in entity_ids:
            for ev in self.events_for(eid, since=since, until=until):
                seen[ev.id] = ev
        rows = [
            {"ts": ev.first_seen.isoformat(), "kind": ev.kind, "title": ev.display_name,
             "tool": (ev.attributes or {}).get("tool"), "severity": (ev.attributes or {}).get("severity"),
             "deep_link": (ev.attributes or {}).get("deep_link"), "event_id": ev.id}
            for ev in seen.values()
        ]
        return sorted(rows, key=lambda r: r["ts"])
