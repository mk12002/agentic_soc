"""Model loader for sandbox behavior models."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Optional

from soc_platform.domains.phishing.engine.agents.ml_runtime import load_model_bundle, resolve_model_path
from soc_platform.domains.phishing.engine.configs.settings import settings
from soc_platform.domains.phishing.engine.services.logging_service import get_agent_logger

logger = get_agent_logger("sandbox_agent")


class ModelLoader:
    """Loads and caches sandbox model artifacts."""

    def __init__(self, model_path: str | None = None):
        self.model_path = resolve_model_path(model_path or settings.sandbox_model_path)
        self._model: Optional[Any] = None

    def load_model(self) -> Any:
        if self._model is not None:
            return self._model
        logger.info("Loading model", path=str(self.model_path))
        self._model = load_model_bundle(self.model_path)
        if self._model is None:
            logger.warning("No trained sandbox model found; heuristic mode only")
        return self._model

    def is_loaded(self) -> bool:
        return self._model is not None


_LOADER = ModelLoader()


def load_model(model_path: str | None = None) -> Any:
    """Convenience function to load a cached sandbox model."""
    global _LOADER
    if model_path:
        _LOADER = ModelLoader(model_path)
    return _LOADER.load_model()
