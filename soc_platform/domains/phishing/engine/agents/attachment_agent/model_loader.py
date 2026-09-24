"""Model loader for attachment static-analysis models."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Optional

from soc_platform.domains.phishing.engine.agents.ml_runtime import load_model_bundle, resolve_model_path
from soc_platform.domains.phishing.engine.configs.settings import settings
from soc_platform.domains.phishing.engine.services.logging_service import get_agent_logger

logger = get_agent_logger("attachment_agent")

EXPECTED_ATTACHMENT_FEATURES = [
    "attachment_count",
    "risky_ext_ratio",
    "suspicious_import_ratio",
    "macro_ratio",
    "avg_entropy",
    "avg_size_mb",
]


def _is_supported_attachment_bundle(bundle: Any) -> bool:
    """Accept only runtime-compatible 6-feature static attachment models."""
    if not isinstance(bundle, dict):
        return False

    feature_names = bundle.get("features")
    n_features = bundle.get("n_features")

    if isinstance(feature_names, list) and feature_names:
        return feature_names == EXPECTED_ATTACHMENT_FEATURES

    # Backward-compatible fallback when older bundles only include n_features.
    try:
        return int(n_features) == len(EXPECTED_ATTACHMENT_FEATURES)
    except Exception:
        return False


class ModelLoader:
    """Loads and caches attachment model artifacts."""

    def __init__(self, model_path: str | None = None):
        self.model_path = resolve_model_path(model_path or settings.attachment_model_path)
        self._model: Optional[Any] = None

    def load_model(self) -> Any:
        if self._model is not None:
            return self._model
        logger.info("Loading model", path=str(self.model_path))
        loaded = load_model_bundle(self.model_path)
        if loaded is not None and not _is_supported_attachment_bundle(loaded):
            logger.error(
                "Attachment model rejected due to incompatible schema",
                expected_features=EXPECTED_ATTACHMENT_FEATURES,
                got_features=loaded.get("features") if isinstance(loaded, dict) else None,
                got_n_features=loaded.get("n_features") if isinstance(loaded, dict) else None,
            )
            loaded = None

        self._model = loaded
        if self._model is None:
            logger.warning("No trained model found; falling back to heuristic mode")
        return self._model


_LOADER = ModelLoader()


def load_model(model_path: str | None = None) -> Any:
    """Convenience function to load a cached attachment model."""
    global _LOADER
    if model_path:
        _LOADER = ModelLoader(model_path)
    return _LOADER.load_model()
