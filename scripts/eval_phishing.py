"""Evaluate phishing analysis backends on labelled and unlabelled email sets.

    python scripts/eval_phishing.py [--engine] [--extra DIR ...] [--out FILE]

Sets: artifacts/phishing/corpus (labelled via labels.json), artifacts/phishing/samples (label from
filename), and any --extra directory (unlabelled; e.g. a local folder of real reported mail that
must never be committed). Engine runs offline: external lookups and LLM calls are disabled.
"""

from __future__ import annotations

import argparse
import json
import time
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def sample_label(name: str) -> str | None:
    n = name.lower()
    if "legit" in n:
        return "safe"
    if any(k in n for k in ("phish", "bec", "malspam", "spear")):
        return "malicious"
    return None


def load_sets(extra: list[str]) -> list[tuple[str, Path, str | None]]:
    items = []
    corpus = ROOT / "artifacts" / "phishing" / "corpus"
    labels = json.loads((corpus / "labels.json").read_text()) if (corpus / "labels.json").exists() else {}
    for n, l in labels.items():
        items.append(("corpus", corpus / f"{n}.eml", l))
    for f in sorted((ROOT / "artifacts" / "phishing" / "samples").glob("*.eml")):
        items.append(("samples", f, sample_label(f.name)))
    for d in extra:
        for f in sorted(Path(d).glob("*.eml")):
            items.append((Path(d).name, f, None))
    return items


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--engine", action="store_true")
    ap.add_argument("--extra", nargs="*", default=[])
    ap.add_argument("--out", default=None)
    a = ap.parse_args()

    from soc_platform.connectors.registry import ConnectorRegistry
    from soc_platform.domains.phishing.agents.analyzer import EngineAnalyzer, HeuristicAnalyzer
    from soc_platform.domains.phishing.agents.decompose import decompose

    from soc_platform.domains.phishing.supplier import load_suppliers

    heur = HeuristicAnalyzer(org_domains=["cci-demo.com"], threat_intel=ConnectorRegistry.all_fake().get("threat_intel"),
                             partner_domains=[d for sup in load_suppliers() for d in sup.domains])
    eng = EngineAnalyzer(offline=True) if a.engine else None
    rows = []
    t_load = time.perf_counter()
    for set_name, path, label in load_sets(a.extra):
        raw = path.read_bytes()
        em = decompose(raw)
        t = time.perf_counter()
        h = heur.analyze(em, raw)
        th = (time.perf_counter() - t) * 1000
        row = {"set": set_name, "file": path.name if set_name in {"corpus", "samples"} else f"<{set_name} #{len(rows)}>",
               "label": label, "heuristic": h.verdict, "heuristic_score": h.score, "heuristic_ms": round(th, 1)}
        if eng is not None:
            t = time.perf_counter()
            try:
                e = eng.analyze(em, raw)
                row.update({"engine": e.verdict, "engine_score": e.score, "engine_ms": round((time.perf_counter() - t) * 1000, 1),
                            "engine_missing_agents": e.missing_agents, "agent_scores": e.raw.get("agent_scores")})
            except Exception as exc:
                row.update({"engine": "error", "engine_error": f"{type(exc).__name__}: {exc}"[:200]})
        rows.append(row)
    summary = {}
    for backend in ("heuristic", "engine"):
        lab = [r for r in rows if r.get("label") and backend in r]
        if not lab:
            continue
        def bucket(v):
            return "malicious" if v in {"malicious", "suspicious"} else "benign"
        # "suspicious" labels are positives too: a miss on them must count as a false negative
        tp = sum(1 for r in lab if bucket(r[backend]) == "malicious" and bucket(r["label"]) == "malicious")
        fn = sum(1 for r in lab if bucket(r[backend]) == "benign" and bucket(r["label"]) == "malicious")
        fp = sum(1 for r in lab if bucket(r[backend]) == "malicious" and bucket(r["label"]) != "malicious")
        tn = len(lab) - tp - fn - fp
        exact = sum(1 for r in lab if r[backend] == r["label"])
        summary[backend] = {"labelled": len(lab), "exact_verdict_match": exact, "tp": tp, "fn": fn, "fp": fp, "tn": tn,
                            "detection_rate": round(tp / (tp + fn), 3) if tp + fn else None,
                            "false_positive_rate": round(fp / (fp + tn), 3) if fp + tn else None,
                            "unlabelled_verdicts": dict(Counter(r[backend] for r in rows if not r.get("label")))}
    out = {"summary": summary, "rows": rows, "total_seconds": round(time.perf_counter() - t_load, 1)}
    text = json.dumps(out, indent=1, default=str)
    if a.out:
        Path(a.out).write_text(text, encoding="utf-8")
    print(json.dumps(summary, indent=1))


if __name__ == "__main__":
    main()
