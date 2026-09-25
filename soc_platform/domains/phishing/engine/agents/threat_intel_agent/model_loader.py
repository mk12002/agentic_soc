"""
Model loader for the Threat Intelligence Agent.

Handles loading, caching, and version management of the XGBoost ML model.
"""

from typing import Optional
import xgboost as xgb

from soc_platform.domains.phishing.engine.agents.ml_runtime import resolve_model_path
from soc_platform.domains.phishing.engine.services.logging_service import get_agent_logger

logger = get_agent_logger("threat_intel_agent")


class ModelLoader:
    """Loads and caches the XGBoost ML model for threat_intel_agent."""

    def __init__(self, model_path: str = "models/threat_intel_agent/"):
        self.model_path = resolve_model_path(
            model_path,
            required_files=("threat_intel_xgb.json",),
        )
        self._model: Optional[xgb.XGBClassifier] = None

    def load_model(self) -> Optional[xgb.XGBClassifier]:
        """
        Load the model from disk.

        Returns:
            The loaded XGBClassifier object, or None if not found.
        """
        if self._model is not None:
            return self._model

        # Attempt to load the JSON artifact
        artifact = self.model_path / "threat_intel_xgb.json"
        
        try:
            if not artifact.exists():
                logger.warning("No trained model found at {}; using placeholder", str(artifact))
                return None
                
            logger.info("Loading XGBoost model from {}", str(artifact))
            model = xgb.XGBClassifier()
            model.load_model(str(artifact))
            self._model = model
            logger.info("Successfully loaded Threat Intel XGBoost model")
            return self._model
            
        except Exception as e:
            logger.error("Failed to load XGBoost model: {}", e)
            return None

    def is_loaded(self) -> bool:
        """Check whether the model is currently loaded."""
        return self._model is not None


_LOADER = ModelLoader()


def load_model(model_path: str = "models/threat_intel_agent/") -> Optional[xgb.XGBClassifier]:
    """Convenience function to load the agent model."""
    global _LOADER
    if model_path != "models/threat_intel_agent/":
        _LOADER = ModelLoader(model_path)
    return _LOADER.load_model()
