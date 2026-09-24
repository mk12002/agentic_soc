"""Garuda endpoint threat hunting integration package."""

from soc_platform.domains.phishing.engine.garuda_integration.bridge import trigger_garuda_investigation

__all__ = ["trigger_garuda_investigation"]
