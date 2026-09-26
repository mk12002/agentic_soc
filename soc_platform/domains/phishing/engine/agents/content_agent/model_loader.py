"""Model loader for content phishing detection agent."""

from __future__ import annotations

import pickle
from typing import Any

import joblib

from soc_platform.domains.phishing.engine.agents.ml_runtime import resolve_model_path
from soc_platform.domains.phishing.engine.configs.settings import settings
from soc_platform.domains.phishing.engine.integrity import verify as verify_artifact
from soc_platform.domains.phishing.engine.services.logging_service import get_agent_logger

logger = get_agent_logger("content_agent")


class ModelLoader:
    """Loads and caches model artifacts for content analysis."""

    def __init__(self, model_path: str | None = None):
        self.model_path = resolve_model_path(
            model_path or settings.content_model_path,
            required_files=("config.json", "model.joblib", "model.pkl"),
        )
        self._model: Any | None = None

    def _load_transformer_pipeline(self) -> Any:
        try:
            from transformers import pipeline
        except Exception:
            return None

        config_file = self.model_path / "config.json"
        if not config_file.exists():
            return None

        logger.info("Loading local transformer pipeline", path=str(self.model_path))
        pipe = pipeline(
            "text-classification",
            model=str(self.model_path),
            tokenizer=str(self.model_path),
            truncation=True,
            local_files_only=True,
        )
        return {"kind": "transformer_pipeline", "model": pipe}

    def _load_joblib_or_pickle(self) -> Any:
        candidates = ["model.joblib", "model.pkl"]
        for name in candidates:
            artifact = self.model_path / name
            if not artifact.exists():
                continue

            logger.info("Loading content model artifact", path=str(artifact))
            if artifact.suffix == ".joblib":
                verify_artifact(artifact)
                loaded = joblib.load(artifact)
            else:
                verify_artifact(artifact)
                with open(artifact, "rb") as handle:
                    loaded = pickle.load(handle)  # nosec B301

            if isinstance(loaded, dict) and "model" in loaded:
                loaded.setdefault("kind", "sklearn_bundle")
                return loaded
            return {"kind": "sklearn_model", "model": loaded}
        return None

    def load_model(self) -> Any:
        if self._model is not None:
            return self._model

        if not self.model_path.exists():
            logger.warning("Content model path not found", path=str(self.model_path))
            return None

        self._model = self._load_transformer_pipeline() or self._load_joblib_or_pickle()
        if self._model is None:
            logger.warning("No trained model found; falling back to heuristic mode")
        return self._model


_LOADER = ModelLoader()


def load_model(model_path: str | None = None) -> Any:
    """Convenience function to load cached content model."""
    global _LOADER
    if model_path:
        _LOADER = ModelLoader(model_path=model_path)
    return _LOADER.load_model()
