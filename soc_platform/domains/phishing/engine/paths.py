"""Filesystem locations for the phishing engine.

``PHISHING_HOME`` holds runtime artifacts (models, config, reference data, local
stores). Override with ``SOC_PHISHING_HOME`` (e.g. a mounted volume in Docker).
"""

from __future__ import annotations

import os
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[4]
PHISHING_HOME = Path(os.environ.get("SOC_PHISHING_HOME") or (REPO_ROOT / "artifacts" / "phishing")).resolve()
ENV_FILE = Path(os.environ.get("SOC_ENV_FILE") or (REPO_ROOT / ".env"))
