"""What the platform can actually do on this host: the optional capabilities that depend on libraries outside Python.

A missing system library once switched off QR decoding and the phishing ML engine with nothing but a warning in the
server log: pyzbar needs the zbar shared library (``libzbar0`` on Linux), XGBoost / LightGBM need OpenMP
(``libgomp1``), and the import simply failed. Analysis kept working on what was left, so nobody noticed. Each probe
below tells apart

* ``ok``            - loaded and usable;
* ``off``           - switched off by a setting (a decision, not a fault);
* ``not_installed`` - the Python package is absent (a deployment without that option);
* ``broken``        - the package is installed but cannot be loaded (a missing system library, a corrupt install, the
  trained models not fetched) or a setting asks for it and it cannot run. This is the state that must be seen: it is
  reported on ``/health``, the console's banner, the Integrations screen, ``config check``, a Prometheus gauge and a
  high finding that is notified like any other.

Probes import the modules once per process (an import that failed fails the same way until the process restarts) and
never call out; ``refresh()`` runs them again.
"""

from __future__ import annotations

import importlib
import importlib.util
import os
import socket
import threading
from collections.abc import Callable
from pathlib import Path
from typing import Any

STATES = ("ok", "off", "not_installed", "broken")
_lock = threading.Lock()
_cache: list[dict[str, Any]] | None = None


def _installed(module: str) -> bool:
    """Whether the package is present at all (without importing it)."""
    try:
        return importlib.util.find_spec(module.split(".")[0]) is not None
    except (ImportError, ValueError):
        return False


def _import(module: str) -> Any:
    return importlib.import_module(module)


def _load(modules: list[str]) -> tuple[str, str]:
    """('ok', '') | ('not_installed', which) | ('broken', 'module: error')."""
    missing = [m for m in modules if not _installed(m)]
    if missing:
        return "not_installed", ", ".join(missing)
    for m in modules:
        try:
            _import(m)
        except Exception as exc:  # noqa: BLE001 - the failure itself is what is reported (often OSError from a DLL / .so)
            msg = " ".join(str(exc).split())[:240] or type(exc).__name__
            return "broken", f"{m}: {type(exc).__name__}: {msg}"
    return "ok", ""


def _system_library_hint(detail: str) -> str:
    low = detail.lower()
    if "zbar" in low:
        return ("install the zbar shared library (Linux: apt-get install libzbar0; Windows: the pyzbar wheel bundles it - "
                "install the Microsoft Visual C++ 2013 x64 runtime it needs), then restart the platform")
    if "gomp" in low or "openmp" in low or "vcomp" in low:
        return ("install the OpenMP runtime (Linux: apt-get install libgomp1; Windows: the Microsoft Visual C++ "
                "2015-2022 x64 redistributable), then restart the platform")
    if "dll load failed" in low or ".so" in low or "shared" in low or "oserror" in low:
        return "a system library this package needs is missing: install it (see the error) and restart the platform"
    return "reinstall the platform's packages from the lock (deploy/windows/install.ps1 or the image) and restart"


def _engine_mode() -> str:
    m = (os.environ.get("SOC_PHISHING_ENGINE") or "auto").strip().lower()
    return "on" if m in {"1", "true", "on", "yes"} else "off" if m in {"0", "false", "off", "no"} else "auto"


def _models_state() -> tuple[bool, str]:
    """The engine's trained models are present and real (not Git LFS pointer files left by a clone without LFS)."""
    # the folder the engine loads from (engine/paths.py: SOC_PHISHING_HOME, else <repository>/artifacts/phishing)
    home = os.environ.get("SOC_PHISHING_HOME") or str(Path(__file__).resolve().parents[2] / "artifacts" / "phishing")
    models = Path(home) / "models"
    files = sorted(models.rglob("*.joblib")) if models.is_dir() else []
    if not files:
        return False, f"no trained models in {models}"
    pointers = [f.name for f in files if f.stat().st_size < 512 and f.read_bytes()[:40].startswith(b"version https://git-lfs")]
    if pointers:
        return False, f"{len(pointers)} model file(s) are Git LFS pointers, not models (e.g. {pointers[0]}): run git lfs pull"
    return True, ""


def _probe_engine() -> dict[str, Any]:
    mode = _engine_mode()
    base = {"name": "phishing_engine", "label": "Phishing ML engine",
            "impact": "reported e-mails are analysed by the rule-based analyser only (no trained models)"}
    if mode == "off":
        return {**base, "state": "off", "detail": "SOC_PHISHING_ENGINE=0", "fix": ""}
    state, detail = _load(["joblib", "sklearn", "xgboost", "lightgbm", "langgraph"])
    if state == "ok":
        ok, why = _models_state()
        if not ok:
            return {**base, "state": "broken", "detail": why, "fix": "fetch the trained models (git lfs pull, or the release's artifacts folder)"}
        return {**base, "state": "ok", "detail": "", "fix": ""}
    if state == "not_installed" and mode == "auto":
        return {**base, "state": "not_installed", "detail": f"not installed: {detail}",
                "fix": "install requirements/phishing.txt (or the Windows engine lock) to enable it"}
    if state == "not_installed":
        return {**base, "state": "broken", "detail": f"SOC_PHISHING_ENGINE=1 but not installed: {detail}",
                "fix": "install the engine's packages, or set SOC_PHISHING_ENGINE=auto"}
    return {**base, "state": "broken", "detail": detail, "fix": _system_library_hint(detail)}


def _probe_simple(name: str, label: str, modules: list[str], impact: str, optional_extra: bool = False) -> Callable[[], dict[str, Any]]:
    def probe() -> dict[str, Any]:
        state, detail = _load(modules)
        if state == "not_installed":
            fix = ("install requirements/phishing.txt to enable it" if optional_extra
                   else "reinstall the platform's packages from the lock (it is part of the platform)")
            # a core package missing from a core install is a fault, not an option
            return {"name": name, "label": label, "state": "not_installed" if optional_extra else "broken",
                    "detail": f"not installed: {detail}", "fix": fix, "impact": impact}
        if state == "broken":
            return {"name": name, "label": label, "state": "broken", "detail": detail,
                    "fix": _system_library_hint(detail), "impact": impact}
        return {"name": name, "label": label, "state": "ok", "detail": "", "fix": "", "impact": impact}
    return probe


def _probe_yara() -> dict[str, Any]:
    probe = _probe_simple("yara_rules", "Attachment YARA rules", ["yara"],
                          "the ML engine's attachment agent skips its YARA rules (macro / script attachments score lower)",
                          optional_extra=True)
    if _engine_mode() == "off":
        return {**probe(), "state": "off", "detail": "the ML engine is off (SOC_PHISHING_ENGINE=0)", "fix": ""}
    return probe()


PROBES: list[Callable[[], dict[str, Any]]] = [
    _probe_simple("qr_decoding", "QR-code decoding", ["PIL", "pyzbar.pyzbar"],
                  "QR codes in reported e-mails are not decoded, so links hidden in them are not checked"),
    _probe_simple("fuzzy_hashing", "Attachment fuzzy hashing", ["ppdeep"],
                  "similar attachments are not grouped into campaigns by fuzzy hash"),
    _probe_engine,
    _probe_yara,
]


def report(*, refresh: bool = False) -> list[dict[str, Any]]:
    """Every capability with its state, why, what it costs and the fix (one probe run per process unless refreshed)."""
    global _cache
    with _lock:
        if _cache is None or refresh:
            _cache = [p() for p in PROBES]
        return [dict(c) for c in _cache]


def refresh() -> list[dict[str, Any]]:
    return report(refresh=True)


def broken(items: list[dict[str, Any]] | None = None) -> list[dict[str, Any]]:
    return [c for c in (items if items is not None else report()) if c["state"] == "broken"]


def summary() -> dict[str, Any]:
    """For /health: 'degraded' and the labels of what cannot run, or 'ok'."""
    bad = broken()
    return {"status": "degraded" if bad else "ok", "degraded": [c["name"] for c in bad]}


def log_problems() -> None:
    """At start-up: one structured line per broken capability (the log was the only sign before)."""
    from soc_platform.core.observability import event

    for c in broken():
        event("capability.broken", 40, capability=c["name"], detail=c["detail"], fix=c["fix"])


def raise_or_resolve(s: Any) -> None:
    """Keep one high ``platform_capability`` finding in step with what this host can do (notified like any other)."""
    from sqlalchemy import select

    from soc_platform.core.models import utcnow
    from soc_platform.intelligence.correlation import _key
    from soc_platform.intelligence.models import Insight

    host = socket.gethostname()
    key = _key("capability", host)
    cur = s.execute(select(Insight).where(Insight.dedupe_key == key)).scalars().first()
    bad = broken(refresh())
    if not bad:
        if cur is not None and cur.status in {"new", "acknowledged"}:
            cur.status, cur.decided_by = "resolved", "system:capabilities"
        return
    title = f"Platform capability unavailable on {host}: " + ", ".join(c["label"] for c in bad)
    evidence = [{"ref": c["name"], "signal": "capability_broken", "source": "platform",
                 "summary": f"{c['label']}: {c['detail']} - impact: {c['impact']}"[:400]} for c in bad]
    steps = [f"{c['label']}: {c['fix']}" for c in bad] + ["Then check Integrations -> Platform capabilities (or /health)"]
    if cur is None:
        s.add(Insight(rule="platform_capability", dedupe_key=key, severity="high", score=70.0, title=title[:300],
                      entity_ids=[], domains=[], evidence=evidence, next_steps=steps, requirement_refs=["NFR-13"]))
    else:
        cur.title, cur.evidence, cur.next_steps, cur.last_seen = title[:300], evidence, steps, utcnow()
        if cur.status not in {"new", "acknowledged"}:
            cur.status = "new"
