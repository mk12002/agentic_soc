"""
Agents package for the Agentic Email Security System.

Each sub-package contains an independent AI agent that analyzes
a specific aspect of an email for phishing detection.
"""

import importlib


def _get_agent_func(module_name: str):
    def wrapper(*args, **kwargs):
        module = importlib.import_module(f"soc_platform.domains.phishing.engine.agents.{module_name}")
        return module.analyze(*args, **kwargs)
    return wrapper

AGENT_REGISTRY = {
    "header_agent": _get_agent_func("header_agent"),
    "content_agent": _get_agent_func("content_agent"),
    "url_agent": _get_agent_func("url_agent"),
    "attachment_agent": _get_agent_func("attachment_agent"),
    "sandbox_agent": _get_agent_func("sandbox_agent"),
    "threat_intel_agent": _get_agent_func("threat_intel_agent"),
    "user_behavior_agent": _get_agent_func("user_behavior_agent"),
}

__all__ = ["AGENT_REGISTRY"]

