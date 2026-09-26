"""
Model Warmup System for 30GB RAM Optimization.

Preloads all agent models at startup for faster inference and more predictable
first-request latency. With 30GB RAM, keeping all models in memory is feasible
and significantly improves performance.
"""

from __future__ import annotations

import importlib
import time
from typing import Any

from soc_platform.domains.phishing.engine.services.logging_service import get_service_logger

# Resolve settings at runtime to avoid duplicate instances when imported under
# different package names (tests may mutate the `email_security`-prefixed module).


def _get_settings_module():
    try:
        m = importlib.import_module("soc_platform.domains.phishing.engine.configs.settings")
        return getattr(m, "settings", None)
    except Exception:
        try:
            m = importlib.import_module("soc_platform.domains.phishing.engine.configs.settings")
            return getattr(m, "settings", None)
        except Exception:
            return None

logger = get_service_logger("model_warmup")


class ModelWarmup:
    """Orchestrates preloading of all agent models at startup."""

    def __init__(self):
        self.loaded_models: dict[str, Any] = {}
        self.warmup_times: dict[str, float] = {}

    def warmup_all_models(self) -> dict[str, dict[str, Any]]:
        """
        Preload all agent models in priority order.
        
        Returns:
            Dictionary with warmup statistics for each agent.
        """
        current_settings = _get_settings_module()
        if not (current_settings and getattr(current_settings, "enable_model_preloading", False)):
            logger.info("Model preloading disabled via config")
            return {}

        logger.info("Starting model preloading phase...")
        results = {}

        # Priority order: most-used agents first
        agents = [
            ("header_agent", self._warmup_header_agent),
            ("content_agent", self._warmup_content_agent),
            ("url_agent", self._warmup_url_agent),
            ("attachment_agent", self._warmup_attachment_agent),
            ("sandbox_agent", self._warmup_sandbox_agent),
            ("threat_intel_agent", self._warmup_threat_intel_agent),
            ("user_behavior_agent", self._warmup_user_behavior_agent),
        ]

        for agent_name, warmup_fn in agents:
            try:
                start = time.perf_counter()
                model = warmup_fn()
                elapsed_ms = (time.perf_counter() - start) * 1000

                self.loaded_models[agent_name] = model
                self.warmup_times[agent_name] = elapsed_ms

                status = "✓ loaded" if model is not None else "⚠ fallback"
                logger.info(
                    f"Warmed up {agent_name}",
                    elapsed_ms=round(elapsed_ms, 2),
                    status=status,
                )
                results[agent_name] = {
                    "status": status,
                    "elapsed_ms": round(elapsed_ms, 2),
                    "model": model,
                }
            except Exception as exc:
                logger.warning(
                    f"Failed to preload {agent_name}",
                    error=str(exc),
                )
                results[agent_name] = {
                    "status": "failed",
                    "error": str(exc),
                }

        total_ms = sum(self.warmup_times.values())
        logger.info(
            "Model preloading complete",
            total_ms=round(total_ms, 2),
            models_loaded=len(self.loaded_models),
        )

        return results

    def _warmup_header_agent(self) -> Any:
        """Preload header agent model."""
        from soc_platform.domains.phishing.engine.agents.header_agent.model_loader import load_model
        return load_model()

    def _warmup_content_agent(self) -> Any:
        """Preload content agent model."""
        from soc_platform.domains.phishing.engine.agents.content_agent.model_loader import load_model
        return load_model()

    def _warmup_url_agent(self) -> Any:
        """Preload URL agent model."""
        from soc_platform.domains.phishing.engine.agents.url_agent.model_loader import load_model
        return load_model()

    def _warmup_attachment_agent(self) -> Any:
        """Preload attachment agent model."""
        from soc_platform.domains.phishing.engine.agents.attachment_agent.model_loader import load_model
        return load_model()

    def _warmup_sandbox_agent(self) -> Any:
        """Preload sandbox agent model."""
        from soc_platform.domains.phishing.engine.agents.sandbox_agent.model_loader import load_model
        return load_model()

    def _warmup_threat_intel_agent(self) -> Any:
        """Preload threat intel agent model."""
        from soc_platform.domains.phishing.engine.agents.threat_intel_agent.model_loader import load_model
        return load_model()

    def _warmup_user_behavior_agent(self) -> Any:
        """Preload user behavior agent model."""
        from soc_platform.domains.phishing.engine.agents.user_behavior_agent.model_loader import load_model
        return load_model()

    def get_warmup_summary(self) -> str:
        """Return a human-readable summary of warmup results."""
        if not self.warmup_times:
            return "No models were preloaded"

        lines = [
            "Model Warmup Summary:",
            "─" * 50,
        ]
        for agent, elapsed_ms in sorted(self.warmup_times.items()):
            lines.append(f"  {agent:<30} {elapsed_ms:>8.1f} ms")

        total_ms = sum(self.warmup_times.values())
        lines.append("─" * 50)
        lines.append(f"  {'Total':<30} {total_ms:>8.1f} ms")
        return "\n".join(lines)


def warmup_models_at_startup() -> dict[str, dict[str, Any]]:
    """
    Convenience function to warmup all models and caches.
    Call this during application startup (e.g., in main API entrypoint).
    """
    warmup = ModelWarmup()
    results = warmup.warmup_all_models()
    logger.info(warmup.get_warmup_summary())

    # Also initialize caches
    _warmup_caches()

    return results


def warmup_orchestrator_at_startup() -> None:
    """
    Warmup only the components needed by the orchestrator (caches, etc).
    Does NOT preload agent models to save RAM and avoid missing volume errors.
    """
    logger.info("Orchestrator warmup started...")
    _warmup_caches()
    logger.info("Orchestrator warmup complete")


def _warmup_caches() -> None:
    """Initialize and warm up all caching layers."""
    try:
        logger.info("Warming up caching layers...")
        
        # Initialize deduplication cache
        from soc_platform.domains.phishing.engine.orchestrator.deduplication import get_dedup_cache
        dedup_cache = get_dedup_cache()
        logger.info("Deduplication cache initialized", enabled=dedup_cache.enabled)
        
        # Initialize IOC cache
        from soc_platform.domains.phishing.engine.action_layer.ioc_cache import get_ioc_cache
        ioc_cache = get_ioc_cache()
        logger.info(
            "IOC cache initialized",
            max_memory_mb=ioc_cache.max_memory_mb,
        )
        
        # Check if Azure Search is configured
        from soc_platform.domains.phishing.engine.action_layer.azure_search_client import is_azure_search_available
        azure_available = is_azure_search_available()
        logger.info("Azure Search availability", available=azure_available)
        
        logger.info("Cache warmup complete")
        
    except Exception as e:
        logger.warning("Error during cache warmup", error=str(e))


if __name__ == "__main__":
    """Quick test of model warmup."""
    results = warmup_models_at_startup()
    print("\nWarmup Results:")
    for agent, info in results.items():
        print(f"  {agent}: {info.get('status', 'unknown')}")
