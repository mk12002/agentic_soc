"""Model loader for the user behavior XGBoost pipeline."""

from __future__ import annotations

from typing import Optional
import xgboost as xgb

from soc_platform.domains.phishing.engine.agents.ml_runtime import resolve_model_path
from soc_platform.domains.phishing.engine.services.logging_service import get_agent_logger
from soc_platform.domains.phishing.engine.configs.settings import settings

logger = get_agent_logger("user_behavior_agent")

class ModelLoader:
    def __init__(self, model_path: str | None = None):
        tgt_path = model_path or settings.user_behavior_model_path
        if not tgt_path:
            tgt_path = "models/user_behavior_agent/"
        self.model_path = resolve_model_path(tgt_path, required_files=("user_behavior_xgb.json",))
        self._model: Optional[xgb.XGBClassifier] = None

    def load_model(self) -> Optional[xgb.XGBClassifier]:
        if self._model is not None:
            return self._model
            
        artifact = self.model_path / "user_behavior_xgb.json"
        try:
            if not artifact.exists():
                logger.warning("No artifact at {}; using fallback", str(artifact))
                return None
                
            logger.info("Loading UBA XGBoost from {}", str(artifact))
            model = xgb.XGBClassifier()
            model.load_model(str(artifact))
            self._model = model
            return self._model
        except Exception as e:
            logger.error("Failed to load UBA XGBoost model: {}", e)
            return None


_LOADER = ModelLoader()

def load_model(model_path: str | None = None) -> Optional[xgb.XGBClassifier]:
    global _LOADER
    if model_path:
        _LOADER = ModelLoader(model_path)
    return _LOADER.load_model()
