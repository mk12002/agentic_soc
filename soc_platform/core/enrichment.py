"""Parallel, partial-result-tolerant context enrichment (IM-F04, IM-T04, IM-F15, NFR-05, IM-T08).

For each (entity type, value) the orchestrator fans out to every enabled connector
that supports that lookup, each with its own timeout. Results become ``Evidence``
rows on the case (with source, dimension and deep link). Sources that time out or
fail are recorded and surfaced by name - the investigation completes and is marked
incomplete instead of failing or silently omitting them.
"""

from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutTimeout
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any, Iterable

from sqlalchemy.orm import Session

from soc_platform.connectors.base import BaseConnector, LookupResult
from soc_platform.connectors.registry import ConnectorRegistry
from soc_platform.core.audit import AuditLog
from soc_platform.core.context_store import ContextStore
from soc_platform.core.models import EnrichmentCache, Evidence, utcnow

# Which lookup types feed which context dimension (section 7.2).
DIMENSIONS = {
    "endpoint": ("host", "hash", "user"),
    "identity": ("user", "ip"),
    "privileged_access": ("user", "host"),
    "dns": ("domain", "host", "ip"),
    "deception": ("ip", "host"),
    "exposure": ("host", "cve"),
    "cloud": ("host", "cve"),
    "email": ("user", "domain", "url", "hash", "email_message"),
    "threat_intel": ("ip", "domain", "url", "hash", "cve"),
    "ticketing": ("host",),
}


@dataclass
class Target:
    etype: str   # host | user | ip | domain | url | hash | cve | email_message
    value: str
    entity_id: str | None = None
    context: dict[str, Any] = field(default_factory=dict)


@dataclass
class EnrichmentOutcome:
    evidence: list[Evidence]
    queried: list[str]
    unavailable: list[dict[str, str]]
    elapsed_ms: float

    @property
    def complete(self) -> bool:
        return not self.unavailable

    def completeness(self) -> dict[str, Any]:
        return {"complete": self.complete, "sources_queried": sorted(set(self.queried)),
                "unavailable": self.unavailable, "elapsed_ms": round(self.elapsed_ms, 1)}


class EnrichmentOrchestrator:
    def __init__(self, session: Session, registry: ConnectorRegistry, *, timeout_s: float = 20.0,
                 cache_ttl: timedelta = timedelta(minutes=30), max_workers: int = 16) -> None:
        self.s = session
        self.registry = registry
        self.timeout_s = timeout_s
        self.cache_ttl = cache_ttl
        self.max_workers = max_workers
        self.store = ContextStore(session)

    def _connectors_for(self, etype: str, dimensions: Iterable[str] | None) -> list[BaseConnector]:
        conns = self.registry.with_lookup(etype)
        if dimensions:
            dims = set(dimensions)
            conns = [c for c in conns if c.dimension in dims or (c.dimension == "cloud" and "exposure" in dims)]
        return conns

    def _cached(self, key: str) -> LookupResult | None:
        row = self.s.get(EnrichmentCache, key)
        if row is None:
            return None
        if utcnow() - row.fetched_at.replace(tzinfo=utcnow().tzinfo) > self.cache_ttl:
            return None
        p = row.payload
        return LookupResult(p["source"], p["dimension"], p["ok"], summary=p.get("summary", ""),
                            error=p.get("error"), deep_link=p.get("deep_link"), signals=p.get("signals") or {})

    def enrich(self, case_id: str, targets: list[Target], *, dimensions: Iterable[str] | None = None,
               actor: str = "agent:enrichment") -> EnrichmentOutcome:
        t0 = time.perf_counter()
        jobs: list[tuple[Target, BaseConnector, str]] = []
        for t in targets:
            for c in self._connectors_for(t.etype, dimensions):
                jobs.append((t, c, f"{c.tool}|{t.etype}|{t.value.lower()}"))

        results: dict[int, LookupResult] = {}
        pending: dict[int, Any] = {}
        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            for i, (t, c, key) in enumerate(jobs):
                hit = self._cached(key)
                if hit is not None:
                    results[i] = hit
                    continue
                pending[i] = pool.submit(c.lookup, t.etype, t.value, **t.context)
            deadline = time.perf_counter() + self.timeout_s
            for i, fut in pending.items():
                t, c, _ = jobs[i]
                try:
                    results[i] = fut.result(timeout=max(0.01, deadline - time.perf_counter()))
                except FutTimeout:
                    results[i] = LookupResult(c.tool, c.dimension, False, error=f"timeout after {self.timeout_s}s")
                except Exception as exc:  # connector bug: never fail the investigation
                    results[i] = LookupResult(c.tool, c.dimension, False, error=f"{type(exc).__name__}: {exc}")

        evidence: list[Evidence] = []
        unavailable: list[dict[str, str]] = []
        queried: list[str] = []
        for i, (t, c, key) in enumerate(jobs):
            r = results[i]
            queried.append(c.tool)
            if not r.ok:
                unavailable.append({"source": c.tool, "lookup": f"{t.etype}:{t.value}", "error": r.error or "unknown"})
                continue
            if i in pending:
                self.s.merge(EnrichmentCache(key=key, source=c.tool, payload={
                    "source": r.source, "dimension": r.dimension, "ok": r.ok, "summary": r.summary, "error": r.error,
                    "deep_link": r.deep_link, "signals": r.signals}, fetched_at=utcnow()))
            # Records returned by lookups also land in the shared context store (linking entities).
            for rec in r.records:
                try:
                    with self.s.begin_nested():
                        self.store.ingest(rec)
                except Exception:
                    pass
            ev = Evidence(case_id=case_id, entity_id=t.entity_id, dimension=r.dimension or c.dimension,
                          source_tool=c.tool, summary=r.summary, deep_link=r.deep_link,
                          data={"lookup": t.etype, "value": t.value, "elapsed_ms": r.elapsed_ms, "signals": r.signals,
                                "records": [x.model_dump(mode="json", exclude={"raw"}) for x in r.records[:25]]})
            self.s.add(ev)
            evidence.append(ev)
        self.s.flush()
        out = EnrichmentOutcome(evidence, queried, unavailable, (time.perf_counter() - t0) * 1000)
        AuditLog(self.s).append(actor_type="agent", actor_id=actor, event_type="enrichment.completed",
                                subject_type="case", subject_id=case_id,
                                payload={"targets": [f"{t.etype}:{t.value}" for t in targets],
                                         **out.completeness(), "evidence_ids": [e.id for e in evidence]})
        return out


def evidence_for_llm(evidence: list[Evidence]) -> list[dict[str, Any]]:
    """Stable E-numbered evidence list for grounded reasoning (ids map back to Evidence rows)."""
    return [{"id": f"E{i + 1}", "evidence_row": e.id, "claim": e.summary, "source": e.source_tool,
             "dimension": e.dimension, "deep_link": e.deep_link, "is_inference": e.is_inference}
            for i, e in enumerate(evidence) if e.summary]
