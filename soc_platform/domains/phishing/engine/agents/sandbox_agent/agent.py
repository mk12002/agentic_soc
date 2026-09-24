"""Sandbox behavior agent with Create -> Detonate -> Monitor -> Destroy lifecycle."""

from __future__ import annotations
from soc_platform.domains.phishing.engine.paths import PHISHING_HOME

import csv
import hashlib
import math
import re
import shlex
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import docker
import httpx
from docker.errors import DockerException, ImageNotFound, NotFound

from soc_platform.domains.phishing.engine.agents.sandbox_agent.inference import predict
from soc_platform.domains.phishing.engine.agents.sandbox_agent.model_loader import load_model
from soc_platform.domains.phishing.engine.configs.settings import settings
from soc_platform.domains.phishing.engine.services.logging_service import get_agent_logger

logger = get_agent_logger("sandbox_agent")

RISKY_EXTENSIONS = {
    ".exe",
    ".dll",
    ".js",
    ".ps1",
    ".docm",
    ".xlsm",
    ".hta",
    ".vbs",
    ".scr",
}
SHELL_TOKENS = {"/bin/sh", "sh", "/bin/bash", "bash", "cmd.exe", "powershell"}
NETWORK_TOOL_TOKENS = {"curl", "wget", "powershell", "python", "perl"}
SENSITIVE_DIRS = ("/etc", "/bin", "/usr", "/root", "/var", "/home")
SUSPICIOUS_IMPORT_STRINGS = [b"VirtualAlloc", b"WriteProcessMemory", b"CreateRemoteThread", b"powershell"]
WORKSPACE_ROOT = PHISHING_HOME
SANDBOX_RUNTIME_CSV = WORKSPACE_ROOT / "datasets" / "sandbox_behavior" / "runtime_observations.csv"
SANDBOX_CONTAINER_LABEL = "soc_platform.domains.phishing.engine.sandbox=detonation"

EXECVE_RE = re.compile(r"execve\(\"(?P<exe>[^\"]+)\"(?:,\s*\[(?P<argv>.*?)\])?")
CONNECT_RE = re.compile(r"sin_addr=inet_addr\(\"(?P<ip>\d+\.\d+\.\d+\.\d+)\"\)", re.IGNORECASE)
OPEN_WRITE_RE = re.compile(
    r"(?:open|openat)\([^\"]*\"(?P<path>/[^\"]+)\"[^\n]*O_(?:WRONLY|RDWR|CREAT|TRUNC)",
    re.IGNORECASE,
)


def _clamp(value: float) -> float:
    return max(0.0, min(1.0, round(value, 4)))

def _classify_malware_family(behavior: dict[str, Any]) -> str:
    exec_chain = " ".join(behavior.get("exec_chain", [])).lower()
    ips = behavior.get("remote_ips", [])
    writes = " ".join(behavior.get("sensitive_writes", [])).lower()

    if "powershell" in exec_chain and ips:
        return "Generic.Downloader (PowerShell)"
    if "wmic" in exec_chain and "shadowcopy" in exec_chain:
        return "Ransomware.Behavior (ShadowCopy)"
    if "cmd.exe" in exec_chain and "/c" in exec_chain and ips:
        return "Trojan.Dropper (CMD)"
    if "curl" in exec_chain or "wget" in exec_chain:
        return "Generic.Downloader (Curl/Wget)"
    if "reg" in exec_chain and "add" in exec_chain and "run" in exec_chain:
        return "Persistence.Registry"
    if writes and ("temp" in writes or "appdata" in writes):
        return "Trojan.Dropper (TempFS)"
    if ips:
        return "Trojan.Network"
    if behavior.get("shell_spawned"):
        return "Suspicious.Shell"
    
    return "Unknown/Heuristic"

def _generate_console_screenshot(behavior: dict[str, Any], target_name: str) -> list[dict[str, str]]:
    screens = []
    base_time = int(time.time())
    
    screens.append({
        "timestamp": f"T+0s",
        "text": f"[INIT] Detonating sample: {target_name}\\n[INFO] Setting up virtual container environment..."
    })
    
    if behavior.get("exec_chain"):
        screens.append({
            "timestamp": f"T+2s",
            "text": f"[EXEC] Process spawned:\\n  -> {str(behavior['exec_chain'][0])[:60]}..."
        })
    
    if behavior.get("remote_ips"):
        ips = ", ".join(behavior["remote_ips"][:2])
        screens.append({
            "timestamp": f"T+4s",
            "text": f"[NET] Outbound connection attempted:\\n  -> SYN sent to {ips}"
        })
        
    if behavior.get("sensitive_writes"):
        writes = "\\n  -> ".join(behavior["sensitive_writes"][:2])
        screens.append({
            "timestamp": f"T+5s",
            "text": f"[FS] Sensitive file modification:\\n  -> {writes}"
        })
        
    screens.append({
        "timestamp": f"T+8s",
        "text": f"[TERM] Execution timeout reached. Terminating container."
    })
    return screens


def _safe_stop_remove(container: Any) -> None:
    container_id = getattr(container, "id", "unknown")
    try:
        container.stop(timeout=2)
    except Exception as exc:
        logger.debug("Container stop ignored", container_id=container_id, error=str(exc))
    try:
        container.remove(force=True)
    except Exception as exc:
        logger.warning("Container remove failed", container_id=container_id, error=str(exc))


def _parse_docker_timestamp(raw: str | None) -> float | None:
    if not raw:
        return None
    try:
        # Docker timestamps commonly end with "Z" and may include subsecond precision.
        return datetime.fromisoformat(raw.replace("Z", "+00:00")).timestamp()
    except Exception:
        return None


def _cleanup_stale_detonation_containers(docker_client: Any, stale_seconds: int) -> None:
    now = time.time()
    removed = 0
    scanned = 0
    try:
        containers = docker_client.containers.list(all=True, filters={"label": SANDBOX_CONTAINER_LABEL})
    except Exception as exc:
        logger.warning("Unable to list stale detonation containers", error=str(exc))
        return

    for container in containers:
        scanned += 1
        try:
            container.reload()
            state = (container.attrs or {}).get("State", {})
            status = str(state.get("Status", "")).lower()
            started_ts = _parse_docker_timestamp(state.get("StartedAt"))
            created_ts = _parse_docker_timestamp((container.attrs or {}).get("Created"))
            ref_ts = started_ts or created_ts
            age = (now - ref_ts) if ref_ts else (stale_seconds + 1)
            if status in {"exited", "dead", "created"} or age >= stale_seconds:
                _safe_stop_remove(container)
                removed += 1
        except Exception as exc:
            logger.debug("Stale container cleanup skip", error=str(exc))

    if removed:
        logger.info(
            "Sandbox stale container cleanup complete",
            scanned=scanned,
            removed=removed,
            stale_seconds=stale_seconds,
        )


def _is_private_ip(ip: str) -> bool:
    if ip.startswith("10.") or ip.startswith("127."):
        return True
    if ip.startswith("192.168."):
        return True
    if ip.startswith("169.254."):
        return True
    if ip.startswith("172."):
        try:
            second = int(ip.split(".", 2)[1])
            return 16 <= second <= 31
        except Exception:
            return False
    return False


def _file_entropy(path: Path) -> float:
    data = path.read_bytes()
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    entropy = 0.0
    total = len(data)
    for count in counts:
        if not count:
            continue
        p = count / total
        entropy -= p * math.log2(p)
    return round(entropy, 2)


def _static_attachment_score(target: Path) -> float:
    score = 0.0
    ext = target.suffix.lower()
    
    filename = target.name.lower()
    parts = filename.split(".")
    # Catch double extensions in sandbox as well
    if len(parts) > 2 and parts[-1] in [e.strip(".") for e in RISKY_EXTENSIONS]:
        score += 0.85
        ext = f".{parts[-1]}"

    if ext in RISKY_EXTENSIONS:
        score += 0.55

    try:
        blob = target.read_bytes()
    except OSError:
        return _clamp(score)

    entropy = _file_entropy(target)
    if entropy >= 7.1:
        score += 0.22

    if any(token in blob.lower() for token in SUSPICIOUS_IMPORT_STRINGS):
        score += 0.42

    lower_blob = blob.lower()
    if ext in {".docm", ".xlsm"} and b"vba" in lower_blob:
        score += 0.85

    return _clamp(score)


def _derive_training_row(
    *,
    target: Path,
    signals: dict[str, Any],
    timed_out: bool,
    exit_code: int,
    risk_score: float,
) -> dict[str, Any]:
    exec_chain = signals.get("exec_chain", []) or []
    lowered_exec = [str(item).lower() for item in exec_chain]
    shell_count = sum(1 for exe in lowered_exec if any(token in exe for token in SHELL_TOKENS))
    network_tool_count = sum(1 for exe in lowered_exec if any(token in exe for token in NETWORK_TOOL_TOKENS))
    suspicious_process_count = shell_count + network_tool_count

    if signals.get("critical_chain_detected"):
        suspicious_process_count += 1

    row = {
        "sample_id": f"runtime_{int(time.time() * 1000)}_{target.stem}",
        "file_extension": target.suffix.lower() or "unknown",
        "executed": 1,
        "return_code": int(exit_code),
        "timed_out": int(timed_out),
        "spawned_processes": max(len(exec_chain), 0),
        "suspicious_process_count": suspicious_process_count,
        "file_entropy": _file_entropy(target),
        "connect_calls": len(signals.get("remote_ips", []) or []),
        "execve_calls": len(exec_chain),
        "file_write_calls": len(signals.get("sensitive_writes", []) or []),
        "sequence_length": len(exec_chain) + len(signals.get("remote_ips", []) or []) + len(signals.get("sensitive_writes", []) or []),
        "sequence_process_calls": len(exec_chain),
        "sequence_network_calls": len(signals.get("remote_ips", []) or []),
        "sequence_filesystem_calls": len(signals.get("sensitive_writes", []) or []),
        "sequence_registry_calls": 0,
        "sequence_memory_calls": 0,
        "critical_chain_detected": int(bool(signals.get("critical_chain_detected"))),
        "behavior_risk_score": _clamp(risk_score),
        # Weak-supervision bootstrap: keep as pseudo-label until SOC verdict is joined.
        "pseudo_label": int(risk_score >= 0.86),
        "label": "",
        "source": "runtime_detonation",
        "filename": target.name,
    }
    return row


def _append_runtime_observation(row: dict[str, Any]) -> None:
    SANDBOX_RUNTIME_CSV.parent.mkdir(parents=True, exist_ok=True)
    columns = [
        "sample_id",
        "filename",
        "file_extension",
        "executed",
        "return_code",
        "timed_out",
        "spawned_processes",
        "suspicious_process_count",
        "file_entropy",
        "connect_calls",
        "execve_calls",
        "file_write_calls",
        "sequence_length",
        "sequence_process_calls",
        "sequence_network_calls",
        "sequence_filesystem_calls",
        "sequence_registry_calls",
        "sequence_memory_calls",
        "critical_chain_detected",
        "behavior_risk_score",
        "pseudo_label",
        "label",
        "source",
    ]
    file_exists = SANDBOX_RUNTIME_CSV.exists()
    with SANDBOX_RUNTIME_CSV.open("a", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=columns)
        if not file_exists:
            writer.writeheader()
        writer.writerow({col: row.get(col, "") for col in columns})


def _choose_exec_command(sample_path: str, ext: str) -> str:
    quoted = shlex.quote(sample_path)
    if ext == ".py":
        return f"python3 {quoted}"
    if ext in {".sh", ".bash"}:
        return f"sh {quoted}"
    if ext in {".js", ".mjs"}:
        return f"node {quoted}"
    if ext in {".pl"}:
        return f"perl {quoted}"
    return quoted


def _extract_behavior_from_strace(logs: str) -> dict[str, Any]:
    exec_chain: list[str] = []
    remote_ips: list[str] = []
    sensitive_writes: list[str] = []

    for line in logs.splitlines():
        exec_match = EXECVE_RE.search(line)
        if exec_match:
            exe = exec_match.group("exe")
            if exe:
                exec_chain.append(exe)

        connect_match = CONNECT_RE.search(line)
        if connect_match:
            ip = connect_match.group("ip")
            if ip and not _is_private_ip(ip):
                remote_ips.append(ip)

        write_match = OPEN_WRITE_RE.search(line)
        if write_match:
            path = write_match.group("path")
            if path and path.startswith(SENSITIVE_DIRS):
                sensitive_writes.append(path)

    unique_exec_chain = list(dict.fromkeys(exec_chain))[:32]
    unique_remote_ips = list(dict.fromkeys(remote_ips))[:16]
    unique_sensitive_writes = list(dict.fromkeys(sensitive_writes))[:16]

    lowered_exec = [item.lower() for item in unique_exec_chain]
    shell_spawned = any(any(token in exe for token in SHELL_TOKENS) for exe in lowered_exec)
    network_tool_spawned = any(any(token in exe for token in NETWORK_TOOL_TOKENS) for exe in lowered_exec)
    critical_chain_detected = shell_spawned and (network_tool_spawned or bool(unique_remote_ips))

    return {
        "exec_chain": unique_exec_chain,
        "remote_ips": unique_remote_ips,
        "sensitive_writes": unique_sensitive_writes,
        "shell_spawned": shell_spawned,
        "network_tool_spawned": network_tool_spawned,
        "critical_chain_detected": critical_chain_detected,
    }


def _score_behavior_signals(signals: dict[str, Any], timed_out: bool, nonzero_exit: bool) -> tuple[float, list[str]]:
    score = 0.0
    indicators: list[str] = []

    if signals.get("exec_chain"):
        score += 0.12
        indicators.append("sandbox_exec_activity")

    if signals.get("shell_spawned"):
        score += 0.5
        indicators.append("shell_spawn_detected")

    remote_ips = signals.get("remote_ips", []) or []
    if remote_ips:
        score += 0.45
        indicators.append("remote_connect_detected")

    writes = signals.get("sensitive_writes", []) or []
    if writes:
        score += 0.25
        indicators.append("sensitive_fs_modification")

    if signals.get("critical_chain_detected"):
        score += 0.2
        indicators.append("critical_chain_detected")

    if timed_out:
        score += 0.1
        indicators.append("detonation_timeout")

    if nonzero_exit:
        score += 0.06
        indicators.append("nonzero_exit_status")

    score = _clamp(score)
    if signals.get("shell_spawned") or remote_ips:
        score = max(score, 0.86)

    return score, indicators


def _detonate_attachment(docker_client: Any, target: Path) -> tuple[float, list[str], dict[str, Any], dict[str, Any]]:
    image = settings.sandbox_detonation_image
    timeout_seconds = int(settings.sandbox_timeout_seconds)
    sample_name = f"sample{target.suffix.lower() or '.bin'}"
    sample_path = f"/tmp/{sample_name}"
    ext = target.suffix.lower()

    try:
        docker_client.images.get(image)
    except ImageNotFound:
        docker_client.images.pull(image)

    sample_hash = hashlib.sha256(str(target).encode("utf-8", errors="ignore")).hexdigest()[:12]
    container_name = f"sandbox-det-{int(time.time())}-{sample_hash}"

    container_kwargs: dict[str, Any] = {
        "image": image,
        "command": ["sh", "-lc", "while true; do sleep 1; done"],
        "detach": True,
        "working_dir": "/sandbox",
        "name": container_name,
        "volumes": {
            str(target.resolve()): {
                "bind": sample_path,
                "mode": "ro",
            }
        },
        "read_only": True,
        "tmpfs": {
            "/sandbox": "rw,noexec,nosuid,nodev,size=256m",
            "/tmp": "rw,noexec,nosuid,nodev,size=128m",
        },
        "cap_drop": ["ALL"],
        "security_opt": ["no-new-privileges"],
        "mem_limit": f"{max(64, int(settings.sandbox_memory_limit_mb))}m",
        "pids_limit": max(32, int(settings.sandbox_pids_limit)),
        "user": str(settings.sandbox_non_root_user or "65534:65534"),
        "labels": {
            "soc_platform.domains.phishing.engine.sandbox": "detonation",
            "email_security.component": "sandbox_agent",
            "email_security.sample": sample_hash,
        },
    }
    if not bool(settings.sandbox_allow_network):
        container_kwargs["network_disabled"] = True

    try:
        container = docker_client.containers.create(**container_kwargs)
    except TypeError:
        # Compatibility fallback for older daemons that reject one or more hardening args.
        for key in ("security_opt", "pids_limit", "tmpfs"):
            container_kwargs.pop(key, None)
        container = docker_client.containers.create(**container_kwargs)

    indicators: list[str] = []
    behavior: dict[str, Any] = {
        "exec_chain": [],
        "remote_ips": [],
        "sensitive_writes": [],
        "shell_spawned": False,
        "network_tool_spawned": False,
        "critical_chain_detected": False,
    }

    timed_out = False
    nonzero_exit = False
    exit_code = 0

    try:
        logger.info("Sandbox detonation started", attachment=str(target), image=image, timeout_seconds=timeout_seconds)
        container.start()
        detonation_cmd = _choose_exec_command(sample_path=sample_path, ext=ext)
        shell_cmd = (
            f"set -e; "
            f"chmod +x {shlex.quote(sample_path)} || true; "
            f"if command -v strace >/dev/null 2>&1; then "
            f"  timeout {max(2, timeout_seconds - 2)}s strace -f -tt -s 256 -e trace=process,network,file {detonation_cmd}; "
            f"else "
            f"  echo '__NO_STRACE__'; "
            f"  timeout {max(2, timeout_seconds - 2)}s {detonation_cmd}; "
            f"fi"
        )

        started = time.monotonic()
        
        # Capture exec output directly instead of relying on detached container logs
        exec_result = container.exec_run(["sh", "-lc", shell_cmd], detach=False)
        
        # Since timeout is built into shell_cmd, exec_run will block for at most timeout_seconds
        exit_code = exec_result.exit_code if exec_result.exit_code is not None else 0
        nonzero_exit = exit_code != 0
        raw_logs = exec_result.output.decode("utf-8", errors="replace") if isinstance(exec_result.output, (bytes, bytearray)) else str(exec_result.output)
        if "__NO_STRACE__" in raw_logs:
            indicators.append("sandbox_strace_unavailable")
            raw_logs = raw_logs.replace("__NO_STRACE__", "")

        if exit_code == 124 or time.monotonic() - started > timeout_seconds - 1:
            timed_out = True
            try:
                container.kill()
            except Exception:
                pass
            
        behavior = _extract_behavior_from_strace(raw_logs)

        score, score_indicators = _score_behavior_signals(
            signals=behavior,
            timed_out=timed_out,
            nonzero_exit=nonzero_exit,
        )
        indicators.extend(score_indicators)

        training_row = _derive_training_row(
            target=target,
            signals=behavior,
            timed_out=timed_out,
            exit_code=exit_code,
            risk_score=score,
        )
        _append_runtime_observation(training_row)

        logger.info(
            "Sandbox detonation complete",
            attachment=str(target),
            elapsed_seconds=round(time.monotonic() - started, 3),
            exit_code=exit_code,
            timed_out=timed_out,
            heuristic_score=score,
            exec_chain_count=len(behavior.get("exec_chain", []) or []),
            remote_ip_count=len(behavior.get("remote_ips", []) or []),
            sensitive_write_count=len(behavior.get("sensitive_writes", []) or []),
            critical_chain_detected=bool(behavior.get("critical_chain_detected")),
        )

        return score, indicators, behavior, training_row

    finally:
        _safe_stop_remove(container)


def _compute_static_score(attachment: dict[str, Any], target: Path) -> float:
    static_score = attachment.get("static_score", attachment.get("static_risk_score"))
    if isinstance(static_score, (int, float)):
        return _clamp(float(static_score))
    return _static_attachment_score(target)


def _is_high_static_suspicion(target: Path, static_score: float) -> bool:
    ext = target.suffix.lower()
    if static_score >= 0.85:
        return True
    return ext in {".docm", ".xlsm", ".exe", ".dll", ".js", ".ps1"} and static_score >= 0.7


def _should_detonate(attachment: dict[str, Any], target: Path) -> tuple[bool, float, str]:
    static_score = _compute_static_score(attachment, target)
    if static_score >= 0.45:
        return True, static_score, "static_score_threshold"
    if target.suffix.lower() in RISKY_EXTENSIONS:
        return True, static_score, "risky_extension"
    return False, static_score, "low_suspicion"


def _attachment_priority_item(attachment: dict[str, Any]) -> tuple[float, int]:
    target = Path(attachment.get("path", ""))
    if not target.exists():
        return -1.0, 0
    static_score = _compute_static_score(attachment, target)
    ext_risky = 1 if target.suffix.lower() in RISKY_EXTENSIONS else 0
    return static_score, ext_risky


def _detonate_via_executor(target: Path) -> tuple[float, list[str], dict[str, Any], dict[str, Any]]:
    """Detonate attachment through remote sandbox executor service."""
    executor_url = str(settings.sandbox_executor_url or "").strip().rstrip("/")
    if not executor_url:
        raise OSError("sandbox_executor_url_not_configured")

    headers: dict[str, str] = {}
    shared_token = str(settings.sandbox_executor_shared_token or "").strip()
    if shared_token:
        headers["x-sandbox-token"] = shared_token

    endpoint = f"{executor_url}/detonate"
    timeout_seconds = max(1.0, float(settings.sandbox_executor_timeout_seconds))
    payload = {"attachment_path": str(target)}

    with httpx.Client(timeout=timeout_seconds) as client:
        response = client.post(endpoint, json=payload, headers=headers)
        response.raise_for_status()
        data = response.json() or {}

    heuristic_score = _clamp(float(data.get("heuristic_score", 0.0) or 0.0))
    indicators = [str(item) for item in (data.get("indicators") or []) if str(item).strip()]

    behavior_data = data.get("behavior") or {}
    behavior = behavior_data if isinstance(behavior_data, dict) else {}
    if not behavior:
        behavior = {
            "exec_chain": [],
            "remote_ips": [],
            "sensitive_writes": [],
            "shell_spawned": False,
            "network_tool_spawned": False,
            "critical_chain_detected": False,
        }

    training_row_data = data.get("training_row") or {}
    if isinstance(training_row_data, dict) and training_row_data:
        training_row = dict(training_row_data)
    else:
        training_row = _derive_training_row(
            target=target,
            signals=behavior,
            timed_out=False,
            exit_code=0,
            risk_score=heuristic_score,
        )

    return heuristic_score, indicators, behavior, training_row


def analyze(data: dict[str, Any]) -> dict[str, Any]:
    logger.info("Starting analysis", agent="sandbox_agent")
    attachments = data.get("attachments", []) or []
    if not attachments:
        return {
            "agent_name": "sandbox_agent",
            "risk_score": 0.0,
            "behavior_risk_score": 0.0,
            "confidence": 0.75,
            "indicators": ["no_attachments_for_sandbox"],
            "behavior_summary": {},
        }

    risk = 0.0
    indicators: list[str] = []
    behavior_summary: dict[str, Any] = {}
    analysis_mode = "fallback_static"
    operational_alert: dict[str, Any] | None = None
    high_static_suspicion = False
    model = load_model()

    detonate_fn: Any = None
    local_docker_enabled = bool(settings.sandbox_local_docker_enabled)

    if local_docker_enabled:
        try:
            docker_client = docker.from_env()
            _cleanup_stale_detonation_containers(
                docker_client=docker_client,
                stale_seconds=max(300, int(settings.sandbox_cleanup_stale_seconds)),
            )
            detonate_fn = lambda target: _detonate_attachment(docker_client, target)
            analysis_mode = "docker"
        except (DockerException, NotFound, OSError) as exc:
            indicators.append("docker_sandbox_unavailable")
            indicators.append("soc_operational_alert:sandbox_backend_unavailable")
            operational_alert = {
                "code": "sandbox_backend_unavailable",
                "severity": "warning",
                "message": "Local Docker sandbox is unavailable; fallback static mode in effect.",
            }
            logger.warning("Sandbox unavailable, falling back to static behavior hints", error=str(exc))
    else:
        executor_url = str(settings.sandbox_executor_url or "").strip()
        if executor_url:
            indicators.append("sandbox_executor_mode")
            detonate_fn = _detonate_via_executor
            analysis_mode = "executor"
        else:
            indicators.append("sandbox_local_docker_disabled")

    if detonate_fn is None:
        analysis_mode = "fallback_static"
        for attachment in attachments[:5]:
            filename = str(attachment.get("filename") or "").lower()
            target = Path(attachment.get("path", ""))
            if target.exists():
                static_score = _compute_static_score(attachment, target)
                if _is_high_static_suspicion(target, static_score):
                    high_static_suspicion = True
                    risk += 0.85 * static_score
                    indicators.append(f"fallback_high_static_combo:{target.name}")
                else:
                    risk += 0.45 * static_score
            else:
                indicators.append(f"missing_attachment_path:{attachment.get('filename', 'unknown')}")
            if any(token in filename for token in ["invoice", "payment", "urgent", "update"]):
                risk += 0.08
                indicators.append(f"suspicious_attachment_name:{filename}")
    else:
        max_detonations = max(1, int(settings.sandbox_max_detonations))
        prioritized = sorted(
            attachments,
            key=lambda item: _attachment_priority_item(item),
            reverse=True,
        )

        for index, attachment in enumerate(prioritized):
            target = Path(attachment.get("path", ""))
            if not target.exists():
                indicators.append(f"missing_attachment_path:{attachment.get('filename', 'unknown')}")
                continue

            if index >= max_detonations:
                indicators.append(f"sandbox_skipped_budget:{target.name}")
                continue

            should_detonate, static_score, detonation_reason = _should_detonate(attachment, target)
            if _is_high_static_suspicion(target, static_score):
                high_static_suspicion = True
            if not should_detonate:
                indicators.append(f"sandbox_skipped_low_suspicion:{target.name}")
                continue

            indicators.append(f"sandbox_detonation_reason:{detonation_reason}:{target.name}")
            indicators.append(f"sandbox_static_score:{static_score:.3f}:{target.name}")

            try:
                detonation_score, detonation_indicators, behavior, training_row = detonate_fn(target)
            except Exception as exc:
                if local_docker_enabled:
                    indicators.append("docker_sandbox_unavailable")
                else:
                    indicators.append("sandbox_executor_unavailable")
                indicators.append("soc_operational_alert:sandbox_backend_unavailable")
                analysis_mode = "fallback_static"
                if operational_alert is None:
                    operational_alert = {
                        "code": "sandbox_backend_unavailable",
                        "severity": "warning",
                        "message": "Sandbox backend unavailable during detonation; fallback static scoring applied.",
                    }
                logger.warning("Sandbox detonation path unavailable", target=str(target), error=str(exc))
                if _is_high_static_suspicion(target, static_score):
                    risk += 0.85 * static_score
                    indicators.append(f"fallback_high_static_combo:{target.name}")
                else:
                    risk += 0.45 * static_score
                continue

            ml_prediction = predict(training_row, model=model)
            ml_risk = float(ml_prediction.get("risk_score", 0.0))
            ml_conf = float(ml_prediction.get("confidence", 0.0))

            if ml_conf > 0.0:
                fused_score = _clamp((0.65 * ml_risk) + (0.35 * detonation_score))
                risk += fused_score
                indicators.extend([f"{tag}:{target.name}" for tag in ml_prediction.get("indicators", [])])
            else:
                fused_score = detonation_score
                risk += detonation_score

            indicators.extend([f"{indicator}:{target.name}" for indicator in detonation_indicators])
            
            # Enrich behavior with malware family and console screenshots
            family = _classify_malware_family(behavior)
            if family != "Unknown/Heuristic":
                indicators.append(f"malware_family:{family}:{target.name}")
            
            behavior["malware_family"] = family
            behavior["console_screenshots"] = _generate_console_screenshot(behavior, target.name)
            
            behavior_summary[target.name] = behavior
            behavior_summary[target.name]["derived_training_row"] = training_row
            behavior_summary[target.name]["heuristic_risk_score"] = _clamp(detonation_score)
            behavior_summary[target.name]["ml_prediction"] = ml_prediction
            behavior_summary[target.name]["fused_risk_score"] = _clamp(fused_score)

            logger.info(
                "Sandbox attachment scoring",
                attachment=target.name,
                heuristic_score=_clamp(detonation_score),
                ml_score=_clamp(ml_risk),
                ml_confidence=_clamp(ml_conf),
                fused_score=_clamp(fused_score),
                indicator_count=len(detonation_indicators) + len(ml_prediction.get("indicators", [])),
            )

            if target.suffix.lower() in RISKY_EXTENSIONS:
                risk += 0.08
                indicators.append(f"risky_executable_attachment:{target.name}")

    final_risk = _clamp(risk)
    fallback_indicators = {
        "docker_sandbox_unavailable",
        "sandbox_local_docker_disabled",
        "sandbox_executor_unavailable",
    }
    if analysis_mode == "fallback_static" and high_static_suspicion:
        final_risk = _clamp(max(final_risk, 0.45))
        indicators.append("fallback_static_suspicious_floor")

    result = {
        "agent_name": "sandbox_agent",
        "risk_score": final_risk,
        "behavior_risk_score": final_risk,
        "confidence": _clamp(0.45 if any(item in fallback_indicators for item in indicators) else 0.86),
        "analysis_mode": analysis_mode,
        "indicators": indicators[:30],
        "behavior_summary": behavior_summary,
    }
    if operational_alert is not None:
        result["operational_alert"] = operational_alert
    logger.info("Analysis complete", risk_score=result["risk_score"])
    return result
