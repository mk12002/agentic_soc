"""Evaluate phishing analysis backends on labelled and unlabelled email sets.

    python scripts/eval_phishing.py [--engine] [--no-context] [--labelled DIR ...] [--extra DIR ...] [--out FILE]

Sets: artifacts/phishing/corpus (labelled via labels.json), artifacts/phishing/samples (label from
filename), any --labelled directory with its own labels.json (e.g. a generated estate's corpus - analysed against
that estate's own fixtures, organisation domain and suppliers), and any --extra directory (unlabelled; e.g. a local
folder of real reported mail that must never be committed).

With --engine three backends are scored: the heuristic analyser, the ML engine, and the two combined as the platform
combines them (CompositeAnalyzer.fuse). The engine gets the same platform context as in production (the heuristic's
threat-intel results; the recipient's contact history, department and arrival time) unless --no-context is given, so
the effect of that context can be measured. Each model is also scored on its own ("per_model"). Engine runs offline:
external lookups and LLM calls disabled.
"""

from __future__ import annotations

import argparse
import json
import os
import time
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
POSITIVE = {"malicious", "suspicious"}


def sample_label(name: str) -> str | None:
    n = name.lower()
    if "legit" in n:
        return "safe"
    if any(k in n for k in ("phish", "bec", "malspam", "spear")):
        return "malicious"
    return None


def load_sets(extra: list[str], labelled: list[str] | None = None) -> list[tuple[str, Path | None, list[tuple[Path, str | None]]]]:
    """[(set name, estate root or None for the built-in estate, [(file, label)])]"""
    sets = []
    corpus = ROOT / "artifacts" / "phishing" / "corpus"
    labels = json.loads((corpus / "labels.json").read_text()) if (corpus / "labels.json").exists() else {}
    sets.append(("corpus", None, [(corpus / f"{n}.eml", lbl) for n, lbl in labels.items()]))
    sets.append(("samples", None, [(f, sample_label(f.name)) for f in sorted((ROOT / "artifacts" / "phishing" / "samples").glob("*.eml"))]))
    for d in labelled or []:
        d = Path(d)
        lab = json.loads((d / "labels.json").read_text())
        estate = d.parent if (d.parent / "fixtures").is_dir() else None
        sets.append((d.parent.name or d.name, estate, [(d / f"{n}.eml", lbl) for n, lbl in lab.items()]))
    for d in extra:
        sets.append((Path(d).name, None, [(f, None) for f in sorted(Path(d).glob("*.eml"))]))
    return sets


def auc(pos: list[float], neg: list[float]) -> float | None:
    """Probability a random malicious message scores above a random legitimate one (0.5 = coin flip)."""
    if not pos or not neg:
        return None
    return round(sum(1.0 if p > n else 0.5 if p == n else 0.0 for p in pos for n in neg) / (len(pos) * len(neg)), 3)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--engine", action="store_true")
    ap.add_argument("--no-context", action="store_true", help="run the engine without the platform context")
    ap.add_argument("--extra", nargs="*", default=[])
    ap.add_argument("--labelled", nargs="*", default=[])
    ap.add_argument("--out", default=None)
    a = ap.parse_args()

    from soc_platform.connectors.registry import ConnectorRegistry
    from soc_platform.domains.phishing.agents.analyzer import CompositeAnalyzer, EngineAnalyzer, HeuristicAnalyzer
    from soc_platform.domains.phishing.agents.decompose import decompose
    from soc_platform.domains.phishing.service import behavior_context
    from soc_platform.domains.phishing.supplier import load_suppliers

    eng = EngineAnalyzer(offline=True) if a.engine else None
    rows = []
    t_load = time.perf_counter()
    base_env = {k: os.environ.get(k) for k in ("SOC_FIXTURES_DIR", "SOC_SUPPLIERS_FILE")}
    for set_name, estate, items in load_sets(a.extra, a.labelled):
        # each estate is analysed against its own tools, organisation and suppliers
        for k, v in base_env.items():
            os.environ.pop(k, None) if v is None else os.environ.__setitem__(k, v)
        org = "acme-demo.com"
        if estate is not None:
            os.environ["SOC_FIXTURES_DIR"] = str(estate / "fixtures")
            if (estate / "suppliers.yaml").exists():
                os.environ["SOC_SUPPLIERS_FILE"] = str(estate / "suppliers.yaml")
            org = json.loads((estate / "estate.json").read_text()).get("org", org) if (estate / "estate.json").exists() else org
        reg = ConnectorRegistry.all_fake()
        heur = HeuristicAnalyzer(org_domains=[org], threat_intel=reg.get("threat_intel"),
                                 partner_domains=[d for sup in load_suppliers() for d in sup.domains])
        entra = reg.get("entra")

        def department_of(upn: str, entra=entra) -> str | None:
            try:
                return entra.get(f"/v1.0/users/{upn}").get("department")
            except Exception:  # noqa: BLE001 - an unknown user simply has no department
                return None

        for path, label in items:
            raw = path.read_bytes()
            em = decompose(raw)
            t = time.perf_counter()
            h = heur.analyze(em, raw)
            th = (time.perf_counter() - t) * 1000
            row = {"set": set_name, "file": path.name if label is not None else f"<{set_name} #{len(rows)}>",
                   "label": label, "heuristic": h.verdict, "heuristic_score": h.score, "heuristic_ms": round(th, 1)}
            if eng is not None:
                ctx = None if a.no_context else {
                    "threat_intel": h.raw.get("threat_intel", []),
                    "behavior": behavior_context(em, None, org_domains=[org], registry=reg, department_of=department_of)}
                t = time.perf_counter()
                try:
                    e = eng.analyze(em, raw, ctx) if ctx else eng.analyze(em, raw)
                    row.update({"engine": e.verdict, "engine_score": e.score,
                                "engine_ms": round((time.perf_counter() - t) * 1000, 1),
                                "engine_missing_agents": e.missing_agents, "agent_scores": e.raw.get("agent_scores"),
                                "behavior_context": (ctx or {}).get("behavior")})
                    c = CompositeAnalyzer.fuse(h, e)
                    row.update({"combined": c.verdict, "combined_score": c.score, "fusion_note": c.raw.get("fusion_note")})
                except Exception as exc:  # noqa: BLE001 - recorded in the evaluation row as an engine error
                    row.update({"engine": "error", "engine_error": f"{type(exc).__name__}: {exc}"[:200]})
            rows.append(row)
    for k, v in base_env.items():
        os.environ.pop(k, None) if v is None else os.environ.__setitem__(k, v)

    def bucket(v):
        return "malicious" if v in POSITIVE else "benign"

    summary: dict = {}
    for backend in ("heuristic", "engine", "combined"):
        lab = [r for r in rows if r.get("label") and backend in r]
        if not lab:
            continue
        # "suspicious" labels are positives too: a miss on them must count as a false negative
        tp = sum(1 for r in lab if bucket(r[backend]) == "malicious" and bucket(r["label"]) == "malicious")
        fn = sum(1 for r in lab if bucket(r[backend]) == "benign" and bucket(r["label"]) == "malicious")
        fp = sum(1 for r in lab if bucket(r[backend]) == "malicious" and bucket(r["label"]) != "malicious")
        tn = len(lab) - tp - fn - fp
        exact = sum(1 for r in lab if r[backend] == r["label"])
        summary[backend] = {"labelled": len(lab), "exact_verdict_match": exact, "tp": tp, "fn": fn, "fp": fp, "tn": tn,
                            "detection_rate": round(tp / (tp + fn), 3) if tp + fn else None,
                            "false_positive_rate": round(fp / (fp + tn), 3) if fp + tn else None,
                            "legitimate_declared_malicious": sum(1 for r in lab if r[backend] == "malicious"
                                                                 and bucket(r["label"]) != "malicious"),
                            "unlabelled_verdicts": dict(Counter(r[backend] for r in rows if not r.get("label"))),
                            "misses": [f"{r['set']}/{r['file']}: label {r['label']}, got {r[backend]}"
                                       for r in lab if bucket(r[backend]) != bucket(r["label"])]}
        ms = sorted(r[f"{backend}_ms"] for r in rows if f"{backend}_ms" in r)
        if ms:
            summary[backend]["median_ms"] = ms[len(ms) // 2]
    scored = [r for r in rows if r.get("label") and r.get("agent_scores")]
    if scored:
        summary["per_model"] = {}
        for agent in sorted({k for r in scored for k in r["agent_scores"]}):
            pos = [r["agent_scores"][agent] or 0 for r in scored if agent in r["agent_scores"] and r["label"] in POSITIVE]
            neg = [r["agent_scores"][agent] or 0 for r in scored if agent in r["agent_scores"] and r["label"] not in POSITIVE]
            summary["per_model"][agent] = {"auc": auc(pos, neg), "legit_scored_0.5_plus": sum(1 for x in neg if x >= 0.5),
                                           "malicious_scored_below_0.5": sum(1 for x in pos if x < 0.5),
                                           "malicious": len(pos), "legit": len(neg)}
    out = {"summary": summary, "rows": rows, "total_seconds": round(time.perf_counter() - t_load, 1)}
    text = json.dumps(out, indent=1, default=str)
    if a.out:
        Path(a.out).write_text(text, encoding="utf-8")
    print(json.dumps(summary, indent=1))


if __name__ == "__main__":
    main()
