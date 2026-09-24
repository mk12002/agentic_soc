"""Run end-to-end audits for all .eml files in email_drop and write detailed reports.

This script ingests each email through the live API, polls final reports,
and evaluates:
- overall verdict reasonableness vs expected label heuristic
- per-agent score behavior and contribution patterns
- counterfactual consistency
- threat storyline structure quality
- repetitive score risk across agents
"""

from __future__ import annotations
from soc_platform.domains.phishing.engine.paths import PHISHING_HOME

import json
import math
import os
import time
import uuid
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib import error, request

BASE_URL = os.getenv("EMAIL_SECURITY_BASE_URL", "http://127.0.0.1:8000")
EMAIL_DROP_DIR = (PHISHING_HOME / "email_drop")
OUTPUT_ROOT = (PHISHING_HOME / "analysis_reports")
POLL_ATTEMPTS = 45
POLL_SLEEP_SECONDS = 2
BATCH_POLL_MAX_SECONDS = 900
ADJUDICATED_LABELS_PATH = Path(
    os.getenv(
        "EMAIL_AUDIT_LABELS_FILE",
        str(PHISHING_HOME / "configs/adjudicated_labels.json"),
    )
)
RELIABILITY_HISTORY_PATH = OUTPUT_ROOT / "reliability_history.jsonl"

BLOCK_THRESHOLDS = {
    "malicious": 0.75,
    "high_risk": 0.55,
    "suspicious": 0.4,
}


@dataclass
class EmailAuditResult:
    file_path: str
    analysis_id: str | None
    expected_label: str
    expected_label_source: str
    status: str
    message: str
    report: dict[str, Any] | None
    checks: dict[str, Any]


def _parse_root_limits() -> dict[Path, int | None]:
    raw = os.getenv("EMAIL_AUDIT_ROOT_LIMITS", "").strip()
    if not raw:
        return {EMAIL_DROP_DIR: None}

    try:
        payload = json.loads(raw)
    except Exception:
        return {EMAIL_DROP_DIR: None}

    if not isinstance(payload, dict):
        return {EMAIL_DROP_DIR: None}

    limits: dict[Path, int | None] = {}
    for key, value in payload.items():
        try:
            root = Path(str(key)).expanduser().resolve()
        except Exception:
            continue

        if value is None:
            limits[root] = None
            continue

        try:
            limit = int(value)
        except Exception:
            continue
        limits[root] = max(0, limit)

    return limits or {EMAIL_DROP_DIR: None}


def _collect_email_files() -> list[Path]:
    roots = _parse_root_limits()
    selected: list[Path] = []
    seen: set[Path] = set()

    for root, limit in sorted(roots.items(), key=lambda item: str(item[0])):
        if root.is_file():
            candidates = [root] if root.suffix.lower() == ".eml" else []
        elif root.is_dir():
            candidates = sorted(root.rglob("*.eml"))
        else:
            continue

        if limit is not None:
            candidates = candidates[:limit]

        for path in candidates:
            try:
                resolved = path.resolve()
            except Exception:
                resolved = path
            if resolved in seen:
                continue
            seen.add(resolved)
            selected.append(path)

    return sorted(selected)


def _http_json(url: str, method: str = "GET", data: bytes | None = None, headers: dict[str, str] | None = None) -> dict[str, Any]:
    req = request.Request(url, data=data, method=method)
    for key, value in (headers or {}).items():
        req.add_header(key, value)
    with request.urlopen(req, timeout=60) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _api_reachable() -> tuple[bool, str]:
    probe_paths = ("/health", "/openapi.json", "/docs")
    for path in probe_paths:
        probe_url = f"{BASE_URL}{path}"
        try:
            req = request.Request(probe_url, method="GET")
            with request.urlopen(req, timeout=5):
                return True, probe_url
        except Exception:
            continue
    return False, ""


def _ingest_eml(path: Path) -> dict[str, Any]:
    boundary = "----EmailBoundary" + uuid.uuid4().hex
    with path.open("rb") as handle:
        payload_data = handle.read()

    body_parts = [
        f"--{boundary}\r\n".encode("utf-8"),
        f"Content-Disposition: form-data; name=\"file\"; filename=\"{path.name}\"\r\n".encode("utf-8"),
        b"Content-Type: message/rfc822\r\n\r\n",
        payload_data,
        b"\r\n",
        f"--{boundary}--\r\n".encode("utf-8"),
    ]
    body = b"".join(body_parts)

    return _http_json(
        f"{BASE_URL}/ingest-raw-email",
        method="POST",
        data=body,
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
    )


def _poll_report(analysis_id: str) -> dict[str, Any] | None:
    for _ in range(POLL_ATTEMPTS):
        try:
            return _http_json(f"{BASE_URL}/reports/{analysis_id}")
        except error.HTTPError as exc:
            if exc.code == 404:
                time.sleep(POLL_SLEEP_SECONDS)
                continue
            raise
    return None


def _load_adjudicated_labels() -> dict[str, str]:
    if not ADJUDICATED_LABELS_PATH.exists():
        return {}
    try:
        payload = json.loads(ADJUDICATED_LABELS_PATH.read_text(encoding="utf-8"))
    except Exception:
        return {}

    if not isinstance(payload, dict):
        return {}

    labels: dict[str, str] = {}
    for key, value in payload.items():
        label = str(value).strip().lower()
        if label in {"benign", "malicious", "unknown"}:
            labels[str(key).strip().lower()] = label
    return labels


def _expected_label(file_path: str, adjudicated_labels: dict[str, str]) -> tuple[str, str]:
    name = file_path.lower()
    base = Path(file_path).name.lower()

    if base in adjudicated_labels:
        return adjudicated_labels[base], "adjudicated"

    # Also allow full-path keys in adjudicated map.
    for key, label in adjudicated_labels.items():
        if key and key in name:
            return label, "adjudicated"

    if "ieee icnpcv 2026 - payment reminder.eml" in name:
        return "benign", "heuristic"
    if "spamassassin/003" in name or "/dataset_samples/003" in name:
        return "malicious", "heuristic"
    if "spamassassin_ham" in name or any(token in name for token in ["/dataset_samples/014", "/dataset_samples/016", "/dataset_samples/017"]):
        return "benign", "heuristic"
    if any(token in name for token in ["malspam", "spearphish", "bec", "live_check"]):
        return "malicious", "heuristic"
    if any(token in name for token in ["legit", "live_check", "invite"]):
        return "benign", "heuristic"
    return "unknown", "heuristic"


def _verdict_reasonableness(expected: str, verdict: str, risk: float) -> tuple[bool, str]:
    if expected == "benign":
        ok = (verdict == "safe" and risk < 0.1) or (verdict in {"likely_safe"} and risk < 0.4) or (verdict == "suspicious" and risk < 0.4)
        return ok, "Benign expected -> safe/likely_safe/<0.4 suspicious with modest score"
    if expected == "malicious":
        ok = verdict in {"suspicious", "high_risk", "malicious"} and risk >= 0.4
        return ok, "Malicious expected -> should be at least suspicious and exceed suspicious boundary"
    return True, "No strong prior label expectation"


def _agent_score_checks(agent_results: list[dict[str, Any]], expected: str) -> dict[str, Any]:
    by_agent = {str(item.get("agent_name")): float(item.get("risk_score", 0.0) or 0.0) for item in agent_results}
    sorted_scores = sorted(by_agent.items(), key=lambda kv: kv[1], reverse=True)
    top_agent, top_score = sorted_scores[0] if sorted_scores else ("none", 0.0)
    avg_score = sum(by_agent.values()) / len(by_agent) if by_agent else 0.0

    if expected == "malicious":
        appropriate = top_score >= 0.55 or avg_score >= 0.35
        reason = "Malicious samples should surface at least one high-signal agent or elevated aggregate risk"
    elif expected == "benign":
        appropriate = top_score < 0.6 and avg_score < 0.35
        reason = "Benign samples should avoid uniformly high-risk outputs across agents"
    else:
        appropriate = True
        reason = "No strict expectation for unknown label"

    return {
        "top_agent": top_agent,
        "top_score": round(top_score, 4),
        "avg_agent_score": round(avg_score, 4),
        "appropriate": appropriate,
        "reason": reason,
        "scores": by_agent,
    }


def _counterfactual_checks(verdict: str, counterfactual: Any) -> dict[str, Any]:
    threshold = BLOCK_THRESHOLDS.get(str(verdict))
    if not isinstance(counterfactual, dict):
        return {
            "has_counterfactual": False,
            "valid": False,
            "reason": "counterfactual_result is not a dict",
        }

    if threshold is None:
        return {
            "has_counterfactual": True,
            "valid": bool(counterfactual.get("reason")),
            "reason": "No blocking boundary expected for likely_safe",
        }

    is_cf = bool(counterfactual.get("is_counterfactual"))
    if is_cf:
        new_score = counterfactual.get("new_normalized_score")
        valid = isinstance(new_score, (float, int)) and float(new_score) < threshold
        return {
            "has_counterfactual": True,
            "valid": valid,
            "reason": "Counterfactual flip should reduce score below boundary",
            "threshold": threshold,
            "new_normalized_score": new_score,
            "agents_altered": counterfactual.get("agents_altered", []),
        }

    return {
        "has_counterfactual": True,
        "valid": bool(counterfactual.get("reason")),
        "reason": "No flip found should include reason",
        "threshold": threshold,
    }


def _storyline_checks(storyline: Any) -> dict[str, Any]:
    if not isinstance(storyline, list):
        return {
            "has_storyline": False,
            "valid": False,
            "reason": "threat_storyline is not a list",
            "phases": [],
        }

    phases = [str(item.get("phase")) for item in storyline if isinstance(item, dict)]
    has_containment = "Containment" in phases
    has_minimum_structure = len(storyline) >= 2
    valid = has_containment and has_minimum_structure

    return {
        "has_storyline": True,
        "valid": valid,
        "reason": "Expected at least two storyline entries including Containment",
        "phases": phases,
        "event_count": len(storyline),
    }


def _stddev(values: list[float]) -> float:
    if len(values) < 2:
        return 0.0
    mean = sum(values) / len(values)
    var = sum((v - mean) ** 2 for v in values) / len(values)
    return math.sqrt(var)


def _binary_expected_label(label: str) -> int | None:
    if label == "malicious":
        return 1
    if label == "benign":
        return 0
    return None


def _expected_calibration_error(scores: list[float], labels: list[int], bins: int = 10) -> float:
    if not scores or not labels or len(scores) != len(labels):
        return 0.0

    ece = 0.0
    total = len(scores)
    for i in range(max(1, bins)):
        low = i / bins
        high = (i + 1) / bins
        idx = [j for j, score in enumerate(scores) if low <= score < high or (i == bins - 1 and score == 1.0)]
        if not idx:
            continue
        bin_scores = [scores[j] for j in idx]
        bin_labels = [labels[j] for j in idx]
        conf = sum(bin_scores) / len(bin_scores)
        acc = sum(bin_labels) / len(bin_labels)
        ece += (len(idx) / total) * abs(conf - acc)
    return round(ece, 4)


def _binary_reliability(scores: list[float], labels: list[int], threshold: float = 0.5) -> dict[str, Any]:
    if not scores or not labels or len(scores) != len(labels):
        return {
            "count": 0,
            "precision": None,
            "recall": None,
            "f1": None,
            "accuracy": None,
            "brier": None,
            "ece": None,
            "tp": 0,
            "fp": 0,
            "tn": 0,
            "fn": 0,
        }

    tp = fp = tn = fn = 0
    for score, label in zip(scores, labels):
        pred = 1 if float(score) >= threshold else 0
        if pred == 1 and label == 1:
            tp += 1
        elif pred == 1 and label == 0:
            fp += 1
        elif pred == 0 and label == 0:
            tn += 1
        else:
            fn += 1

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    accuracy = (tp + tn) / len(scores) if scores else 0.0
    brier = sum((float(score) - int(label)) ** 2 for score, label in zip(scores, labels)) / len(scores)
    ece = _expected_calibration_error(scores, labels)

    return {
        "count": len(scores),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "accuracy": round(accuracy, 4),
        "brier": round(brier, 4),
        "ece": ece,
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
    }


def _build_markdown(results: list[EmailAuditResult], repetitive: dict[str, Any], reliability: dict[str, Any]) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    lines: list[str] = []
    lines.append("# Batch EML Audit Report")
    lines.append("")
    lines.append(f"Generated: {now}")
    lines.append(f"Target API: `{BASE_URL}`")
    lines.append("")

    total = len(results)
    completed = sum(1 for r in results if r.status == "ok")
    verdict_ok = sum(1 for r in results if r.checks.get("overall", {}).get("verdict_reasonable") is True)
    agent_ok = sum(1 for r in results if r.checks.get("agents", {}).get("appropriate") is True)
    cf_ok = sum(1 for r in results if r.checks.get("counterfactual", {}).get("valid") is True)
    sl_ok = sum(1 for r in results if r.checks.get("storyline", {}).get("valid") is True)

    lines.append("## Summary")
    lines.append(f"- Emails tested: `{total}`")
    lines.append(f"- Completed reports: `{completed}`")
    lines.append(f"- Overall verdict reasonableness pass: `{verdict_ok}/{total}`")
    lines.append(f"- Agent-score appropriateness pass: `{agent_ok}/{total}`")
    lines.append(f"- Counterfactual validity pass: `{cf_ok}/{total}`")
    lines.append(f"- Storyline validity pass: `{sl_ok}/{total}`")
    lines.append("")

    lines.append("## Repetitive Score Diagnostics")
    lines.append("- Heuristic: low variability (`stddev < 0.05`) or very low unique rounded values may indicate repetitive scoring.")
    for agent, data in sorted(repetitive.items()):
        lines.append(
            f"- `{agent}`: n={data['count']}, mean={data['mean']:.4f}, stddev={data['stddev']:.4f}, "
            f"unique_3dp={data['unique_rounded']}, repetitive_flag={data['repetitive_flag']}"
        )
    lines.append("")

    lines.append("## Reliability Metrics")
    lines.append("- Thresholded binary metrics with calibration diagnostics (`brier`, `ece`).")
    overall = reliability.get("overall_system", {})
    if overall:
        lines.append(
            "- `overall_system`: "
            f"count={overall.get('count')} precision={overall.get('precision')} recall={overall.get('recall')} "
            f"f1={overall.get('f1')} accuracy={overall.get('accuracy')} brier={overall.get('brier')} ece={overall.get('ece')}"
        )
    for agent, metrics in sorted((reliability.get("agents") or {}).items()):
        lines.append(
            f"- `{agent}`: count={metrics.get('count')} precision={metrics.get('precision')} "
            f"recall={metrics.get('recall')} f1={metrics.get('f1')} accuracy={metrics.get('accuracy')} "
            f"brier={metrics.get('brier')} ece={metrics.get('ece')}"
        )
    lines.append("")

    lines.append("## Per-Email Analysis")
    for idx, item in enumerate(results, start=1):
        lines.append(f"### {idx}. `{item.file_path}`")
        lines.append(f"- Status: `{item.status}`")
        lines.append(f"- Message: {item.message}")
        lines.append(f"- Analysis ID: `{item.analysis_id}`")
        lines.append(f"- Expected Label: `{item.expected_label}` (source: `{item.expected_label_source}`)")

        if item.report:
            verdict = item.report.get("verdict")
            risk = item.report.get("overall_risk_score")
            lines.append(f"- Verdict: `{verdict}` | Risk: `{risk}`")
            lines.append(f"- Recommended Actions: `{item.report.get('recommended_actions', [])}`")

        overall = item.checks.get("overall", {})
        lines.append(
            f"- Overall Correctness: `{overall.get('verdict_reasonable')}` ({overall.get('reason', 'n/a')})"
        )

        agents = item.checks.get("agents", {})
        lines.append(
            f"- Agent Correctness: `{agents.get('appropriate')}` | Top Agent: `{agents.get('top_agent')}` "
            f"({agents.get('top_score')}) | Avg Agent Score: `{agents.get('avg_agent_score')}`"
        )
        if agents.get("scores"):
            compact = ", ".join(f"{k}={v:.3f}" for k, v in sorted(agents["scores"].items()))
            lines.append(f"- Agent Scores: {compact}")

        cf = item.checks.get("counterfactual", {})
        lines.append(f"- Counterfactual Correctness: `{cf.get('valid')}` ({cf.get('reason')})")
        if cf.get("agents_altered") is not None:
            lines.append(f"- Counterfactual Details: threshold={cf.get('threshold')} new_score={cf.get('new_normalized_score')} agents_altered={cf.get('agents_altered')}")

        sl = item.checks.get("storyline", {})
        lines.append(f"- Storyline Correctness: `{sl.get('valid')}` ({sl.get('reason')})")
        lines.append(f"- Storyline Phases: `{sl.get('phases', [])}`")
        lines.append("")

    return "\n".join(lines)


def main() -> int:
    reachable, probe_url = _api_reachable()
    if not reachable:
        print(f"API preflight failed. Could not reach service at {BASE_URL} (probes: /health, /openapi.json, /docs)")
        return 2
    print(f"API preflight passed via: {probe_url}")

    email_files = _collect_email_files()
    if not email_files:
        print("No .eml files found under the configured email audit roots.")
        return 1

    run_id = datetime.now(timezone.utc).strftime("batch_eml_audit_%Y%m%d_%H%M%S")
    out_dir = OUTPUT_ROOT / run_id
    out_dir.mkdir(parents=True, exist_ok=True)

    results: list[EmailAuditResult] = []
    agent_scores: dict[str, list[float]] = {}
    pending: dict[str, dict[str, str]] = {}
    adjudicated_labels = _load_adjudicated_labels()

    # Ingest all emails first to keep queue behavior realistic and avoid per-email polling bias.
    for path in email_files:
        expected, expected_source = _expected_label(str(path), adjudicated_labels)
        try:
            ingest = _ingest_eml(path)
            analysis_id = str(ingest.get("analysis_id") or "")
            if not analysis_id:
                results.append(
                    EmailAuditResult(
                        file_path=str(path),
                        analysis_id=None,
                        expected_label=expected,
                        expected_label_source=expected_source,
                        status="error",
                        message="ingest_missing_analysis_id",
                        report=None,
                        checks={},
                    )
                )
                continue

            pending[analysis_id] = {
                "file_path": str(path),
                "expected_label": expected,
                "expected_label_source": expected_source,
            }
            print(f"[INGESTED] {path.name} -> analysis_id={analysis_id}")
        except Exception as exc:  # pragma: no cover - runtime campaign handling
            results.append(
                EmailAuditResult(
                    file_path=str(path),
                    analysis_id=None,
                    expected_label=expected,
                    expected_label_source=expected_source,
                    status="error",
                    message=f"{type(exc).__name__}: {exc}",
                    report=None,
                    checks={},
                )
            )
            print(f"[ERROR][INGEST] {path.name}: {exc}")

    start_time = time.time()
    completed: dict[str, dict[str, Any]] = {}
    while pending and (time.time() - start_time) < BATCH_POLL_MAX_SECONDS:
        just_completed: list[str] = []
        for analysis_id, meta in pending.items():
            try:
                report = _http_json(f"{BASE_URL}/reports/{analysis_id}")
                completed[analysis_id] = {
                    "report": report,
                    "file_path": meta["file_path"],
                    "expected_label": meta["expected_label"],
                    "expected_label_source": meta["expected_label_source"],
                }
                just_completed.append(analysis_id)
            except error.HTTPError as exc:
                if exc.code != 404:
                    just_completed.append(analysis_id)
                    completed[analysis_id] = {
                        "error": f"HTTPError: {exc}",
                        "file_path": meta["file_path"],
                        "expected_label": meta["expected_label"],
                        "expected_label_source": meta["expected_label_source"],
                    }
            except Exception as exc:  # pragma: no cover
                just_completed.append(analysis_id)
                completed[analysis_id] = {
                    "error": f"{type(exc).__name__}: {exc}",
                    "file_path": meta["file_path"],
                    "expected_label": meta["expected_label"],
                    "expected_label_source": meta["expected_label_source"],
                }

        for analysis_id in just_completed:
            pending.pop(analysis_id, None)

        if pending:
            time.sleep(POLL_SLEEP_SECONDS)

    # Build detailed results from completed and timed-out analyses.
    for analysis_id, item in completed.items():
        file_path = item["file_path"]
        expected = item["expected_label"]
        expected_source = item["expected_label_source"]
        if item.get("report") is None:
            results.append(
                EmailAuditResult(
                    file_path=file_path,
                    analysis_id=analysis_id,
                    expected_label=expected,
                    expected_label_source=expected_source,
                    status="error",
                    message=item.get("error", "report_fetch_error"),
                    report=None,
                    checks={},
                )
            )
            continue

        report = item["report"]
        verdict = str(report.get("verdict", "unknown"))
        risk = float(report.get("overall_risk_score", 0.0) or 0.0)
        verdict_ok, verdict_reason = _verdict_reasonableness(expected, verdict, risk)
        agents_check = _agent_score_checks(report.get("agent_results", []) or [], expected)
        cf_check = _counterfactual_checks(verdict, report.get("counterfactual_result"))
        sl_check = _storyline_checks(report.get("threat_storyline"))

        for agent_name, score in agents_check.get("scores", {}).items():
            agent_scores.setdefault(agent_name, []).append(float(score))

        checks = {
            "overall": {
                "verdict_reasonable": verdict_ok,
                "reason": verdict_reason,
            },
            "agents": agents_check,
            "counterfactual": cf_check,
            "storyline": sl_check,
        }

        results.append(
            EmailAuditResult(
                file_path=file_path,
                analysis_id=analysis_id,
                expected_label=expected,
                expected_label_source=expected_source,
                status="ok",
                message="analysis_completed",
                report=report,
                checks=checks,
            )
        )
        print(f"[OK] {Path(file_path).name} -> verdict={verdict} risk={risk:.4f} analysis_id={analysis_id}")

    for analysis_id, meta in pending.items():
        results.append(
            EmailAuditResult(
                file_path=meta["file_path"],
                analysis_id=analysis_id,
                expected_label=meta["expected_label"],
                expected_label_source=meta["expected_label_source"],
                status="timeout",
                message="report_not_ready_within_timeout",
                report=None,
                checks={},
            )
        )
        print(f"[TIMEOUT] {Path(meta['file_path']).name} -> analysis_id={analysis_id}")

    results.sort(key=lambda r: r.file_path)

    repetitive: dict[str, Any] = {}
    for agent, values in sorted(agent_scores.items()):
        rounded = {round(v, 3) for v in values}
        sigma = _stddev(values)
        repetitive_flag = sigma < 0.05 or len(rounded) <= 3
        repetitive[agent] = {
            "count": len(values),
            "mean": sum(values) / len(values) if values else 0.0,
            "stddev": sigma,
            "unique_rounded": len(rounded),
            "repetitive_flag": repetitive_flag,
            "values": [round(v, 4) for v in values],
        }

    reliability_inputs: dict[str, list[tuple[float, int]]] = defaultdict(list)
    overall_inputs: list[tuple[float, int]] = []
    for item in results:
        if item.status != "ok" or not item.report:
            continue
        label = _binary_expected_label(item.expected_label)
        if label is None:
            continue

        overall_inputs.append((float(item.report.get("overall_risk_score", 0.0) or 0.0), label))
        for entry in item.report.get("agent_results", []) or []:
            agent_name = str(entry.get("agent_name") or "")
            if not agent_name:
                continue
            score = float(entry.get("risk_score", 0.0) or 0.0)
            reliability_inputs[agent_name].append((score, label))

    reliability: dict[str, Any] = {"agents": {}}
    if overall_inputs:
        overall_scores = [row[0] for row in overall_inputs]
        overall_labels = [row[1] for row in overall_inputs]
        reliability["overall_system"] = _binary_reliability(overall_scores, overall_labels)
    else:
        reliability["overall_system"] = _binary_reliability([], [])

    for agent_name, rows in sorted(reliability_inputs.items()):
        scores = [row[0] for row in rows]
        labels = [row[1] for row in rows]
        reliability["agents"][agent_name] = _binary_reliability(scores, labels)

    serializable_results = []
    for r in results:
        serializable_results.append(
            {
                "file_path": r.file_path,
                "analysis_id": r.analysis_id,
                "expected_label": r.expected_label,
                "expected_label_source": r.expected_label_source,
                "status": r.status,
                "message": r.message,
                "checks": r.checks,
                "report": r.report,
            }
        )

    json_path = out_dir / "batch_audit_results.json"
    json_path.write_text(
        json.dumps(
            {
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "base_url": BASE_URL,
                "email_drop_dir": str(EMAIL_DROP_DIR),
                "adjudicated_labels_file": str(ADJUDICATED_LABELS_PATH),
                "tested_files": [str(p) for p in email_files],
                "results": serializable_results,
                "repetitive_score_diagnostics": repetitive,
                "reliability_metrics": reliability,
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    md_path = out_dir / "batch_audit_report.md"
    md_path.write_text(_build_markdown(results, repetitive, reliability), encoding="utf-8")

    history_record = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "run_id": run_id,
        "output_dir": str(out_dir),
        "email_count": len(email_files),
        "reliability_metrics": reliability,
    }
    RELIABILITY_HISTORY_PATH.parent.mkdir(parents=True, exist_ok=True)
    with RELIABILITY_HISTORY_PATH.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(history_record) + "\n")

    print(f"OUTPUT_DIR={out_dir}")
    print(f"REPORT_MD={md_path}")
    print(f"REPORT_JSON={json_path}")
    print(f"RELIABILITY_HISTORY={RELIABILITY_HISTORY_PATH}")
    status_counts: dict[str, int] = defaultdict(int)
    for item in results:
        status_counts[item.status] += 1

    completed_ok = status_counts.get("ok", 0)
    failures = status_counts.get("error", 0) + status_counts.get("timeout", 0)
    if completed_ok == 0 or failures > 0:
        print(f"Batch audit failed quality criteria: ok={completed_ok}, failures={failures}, status_counts={dict(status_counts)}")
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
