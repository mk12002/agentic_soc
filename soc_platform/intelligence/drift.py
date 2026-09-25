"""Model and detection drift monitoring (R14, NFR-13, NFR-15).

Accuracy can degrade silently after go-live (new lure styles, a tool changing its alert taxonomy, a
connector going quiet). Per domain this compares a recent window with a baseline window on:

* agreement with analyst dispositions (the ground truth that is available in production)
* verdict mix shift, measured as a population stability index (PSI) over system verdicts
* mean system confidence

and raises a ``model_drift`` insight with the figures when agreement drops by more than
``agreement_drop`` or PSI exceeds ``psi_alert`` (0.2 is the conventional "significant shift" level).
Nothing here uses a model: every number is computed from stored verdicts and dispositions.
"""

from __future__ import annotations

import math
from collections import Counter
from datetime import timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from soc_platform.core.models import Case, Disposition, utcnow

BUCKETS = ("malicious", "suspicious", "spam", "safe", "benign", "true_positive", "false_positive", "undetermined")


def _psi(base: Counter, cur: Counter) -> float:
    keys = set(base) | set(cur)
    nb, nc = sum(base.values()) or 1, sum(cur.values()) or 1
    total = 0.0
    for k in keys:
        pb = max(base.get(k, 0) / nb, 1e-4)
        pc = max(cur.get(k, 0) / nc, 1e-4)
        total += (pc - pb) * math.log(pc / pb)
    return round(total, 4)


def _agree(rows: list[Disposition]) -> float | None:
    from soc_platform.core.cases import _bucket

    if not rows:
        return None
    return round(sum(1 for d in rows if _bucket(d.system_verdict) == _bucket(d.analyst_verdict)) / len(rows), 4)


def drift_report(session: Session, *, recent_days: int = 7, baseline_days: int = 28, min_sample: int = 20,
                 agreement_drop: float = 0.1, psi_alert: float = 0.2) -> dict[str, Any]:
    now = utcnow()
    r0, b0 = now - timedelta(days=recent_days), now - timedelta(days=recent_days + baseline_days)
    out: dict[str, Any] = {"window": {"recent_days": recent_days, "baseline_days": baseline_days}, "domains": {}}
    for dom in ("phishing", "incident"):
        cases = list(session.execute(select(Case).where(Case.domain == dom, Case.created_at >= b0)).scalars())
        disp = list(session.execute(select(Disposition).where(Disposition.domain == dom,
                                                              Disposition.created_at >= b0)).scalars())

        def when(x):
            t = x.created_at
            return t if t.tzinfo else t.replace(tzinfo=now.tzinfo)

        cur_c = [c for c in cases if when(c) >= r0]
        base_c = [c for c in cases if when(c) < r0]
        cur_d = [d for d in disp if when(d) >= r0]
        base_d = [d for d in disp if when(d) < r0]
        vb, vc = Counter(c.verdict or "undetermined" for c in base_c), Counter(c.verdict or "undetermined" for c in cur_c)
        a_b, a_c = _agree(base_d), _agree(cur_d)
        conf_b = round(sum(c.confidence or 0 for c in base_c) / len(base_c), 3) if base_c else None
        conf_c = round(sum(c.confidence or 0 for c in cur_c) / len(cur_c), 3) if cur_c else None
        enough = len(base_c) >= min_sample and len(cur_c) >= min_sample
        psi = _psi(vb, vc) if enough else None
        reasons = []
        if a_b is not None and a_c is not None and len(cur_d) >= min_sample and len(base_d) >= min_sample \
                and a_b - a_c > agreement_drop:
            reasons.append(f"analyst agreement fell from {a_b:.0%} to {a_c:.0%}")
        if psi is not None and psi > psi_alert:
            reasons.append(f"verdict mix shifted (PSI {psi:.2f} > {psi_alert})")
        out["domains"][dom] = {
            "cases": {"baseline": len(base_c), "recent": len(cur_c)},
            "dispositions": {"baseline": len(base_d), "recent": len(cur_d)},
            "agreement": {"baseline": a_b, "recent": a_c}, "psi_verdicts": psi,
            "mean_confidence": {"baseline": conf_b, "recent": conf_c},
            "verdict_mix": {"baseline": dict(vb), "recent": dict(vc)},
            "status": "drift" if reasons else ("insufficient_data" if not enough else "stable"),
            "reasons": reasons}
    return out


def drift_insights(session: Session, **kw: Any) -> list[Any]:
    from soc_platform.intelligence.correlation import _key
    from soc_platform.intelligence.models import Insight

    rep = drift_report(session, **kw)
    found = []
    for dom, d in rep["domains"].items():
        if d["status"] != "drift":
            continue
        found.append(Insight(
            rule="model_drift", dedupe_key=_key("drift", dom, utcnow().strftime("%Y-%W")), severity="high",
            title=f"{dom.title()} verdict quality drifting: " + "; ".join(d["reasons"]), score=70.0,
            entity_ids=[], domains=[dom],
            evidence=[{"ref": dom, "signal": "drift", "source": "drift_monitor", "summary": r} for r in d["reasons"]]
                     + [{"ref": dom, "signal": "figures", "source": "drift_monitor",
                         "summary": f"agreement {d['agreement']}, PSI {d['psi_verdicts']}, confidence {d['mean_confidence']}"}],
            next_steps=["Review a sample of recent disagreements in shadow-mode metrics",
                        "Check connector freshness for sources feeding this domain",
                        "Re-run the golden evaluation set (scripts/eval_phishing.py) before re-tuning"],
            requirement_refs=["R14", "NFR-13", "NFR-15"]))
    return found
