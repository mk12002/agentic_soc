"""Isolated sandbox detonation executor service.

Runs detonation requests behind a narrow HTTP API so the main sandbox agent
can avoid direct Docker socket access.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import docker
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel
import uvicorn

from soc_platform.domains.phishing.engine.agents.sandbox_agent.agent import _detonate_attachment
from soc_platform.domains.phishing.engine.configs.settings import settings
from soc_platform.domains.phishing.engine.services.logging_service import get_service_logger, setup_logging

logger = get_service_logger("sandbox_executor")
app = FastAPI(title="Sandbox Executor", version="0.1.0")


class DetonateRequest(BaseModel):
    attachment_path: str


class DetonateResponse(BaseModel):
    heuristic_score: float
    indicators: list[str]
    behavior: dict[str, Any]
    training_row: dict[str, Any]


def _validate_token(token: str | None) -> None:
    expected = (settings.sandbox_executor_shared_token or "").strip()
    if not expected:
        return
    if (token or "").strip() != expected:
        raise HTTPException(status_code=401, detail="Invalid sandbox executor token")


def _validate_attachment_path(path: Path) -> None:
    root = Path(settings.sandbox_executor_attachment_root).resolve()
    try:
        candidate = path.resolve()
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Invalid attachment path: {exc}") from exc

    try:
        candidate.relative_to(root)
    except ValueError:
        raise HTTPException(status_code=403, detail="Attachment path outside allowed root")
    if not candidate.exists() or not candidate.is_file():
        raise HTTPException(status_code=404, detail="Attachment path not found")


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/detonate", response_model=DetonateResponse)
def detonate(req: DetonateRequest, x_sandbox_token: str | None = Header(default=None)) -> DetonateResponse:
    _validate_token(x_sandbox_token)
    target = Path(req.attachment_path)
    _validate_attachment_path(target)

    try:
        client = docker.from_env()
        score, indicators, behavior, training_row = _detonate_attachment(client, target)
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("Sandbox executor detonation failed", error=str(exc), path=str(target))
        raise HTTPException(status_code=500, detail=f"Detonation failed: {exc}") from exc

    return DetonateResponse(
        heuristic_score=float(score),
        indicators=[str(item) for item in indicators],
        behavior=behavior,
        training_row=training_row,
    )


def main() -> None:
    setup_logging(settings.log_dir, settings.app_log_level, settings.log_format)
    uvicorn.run(
        "soc_platform.domains.phishing.engine.sandbox.executor_service:app",
        host="0.0.0.0",  # nosec B104
        port=8099,
        log_level=str(settings.app_log_level).lower(),
    )


if __name__ == "__main__":
    main()
