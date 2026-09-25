"""Model loader for URL reputation models."""

from __future__ import annotations

from typing import Any, Optional

from soc_platform.domains.phishing.engine.agents.ml_runtime import load_model_bundle, resolve_model_path
from soc_platform.domains.phishing.engine.configs.settings import settings
from soc_platform.domains.phishing.engine.services.logging_service import get_agent_logger

logger = get_agent_logger("url_agent")


class ModelLoader:
    """Loads and caches the ML model for url_agent."""

    def __init__(self, model_path: str | None = None):
        self.model_path = resolve_model_path(model_path or settings.url_model_path)
        self._model: Optional[Any] = None

    def load_model(self) -> Any:
        if self._model is not None:
            return self._model
        logger.info("Loading model", path=str(self.model_path))
        self._model = load_model_bundle(self.model_path)
        if self._model is None:
            logger.warning("No trained model found; falling back to heuristic mode")
        return self._model


_LOADER = ModelLoader()


def load_model(model_path: str | None = None) -> Any:
    """Convenience function to load a cached URL model."""
    global _LOADER
    if model_path:
        _LOADER = ModelLoader(model_path)
    return _LOADER.load_model()
