"""Pytest shared setup for consistent import paths."""

from __future__ import annotations

import importlib
import os
import sys
import tempfile
from pathlib import Path

from soc_platform.domains.phishing.engine.paths import PHISHING_HOME

# Engine endpoint tests exercise functionality directly; auth itself is covered by test_api_security.py,
# which enables it explicitly. Pin the setting so results do not depend on a developer's .env.
os.environ["API_AUTH_ENABLED"] = "0"

# --- IOC_DB_PATH override for local development ---
# The .env file sets IOC_DB_PATH=/app/data/ioc_store.db (Docker path).
# When running tests locally, /app/ doesn't exist and can't be created.
# Override BEFORE any agent modules are imported (they trigger module-level init).
if not os.environ.get("IOC_DB_PATH"):
    _ioc_test_dir = Path(tempfile.gettempdir()) / "email_security_test"
    _ioc_test_dir.mkdir(parents=True, exist_ok=True)
    os.environ["IOC_DB_PATH"] = str(_ioc_test_dir / "ioc_store.db")

REPO_ROOT = PHISHING_HOME
EMAIL_SECURITY_ROOT = PHISHING_HOME
for entry in (str(REPO_ROOT), str(EMAIL_SECURITY_ROOT)):
    if entry not in sys.path:
        pass  # (package import; no sys.path hack needed)
# Ensure local "datasets" package wins over third-party packages with same name.
existing = sys.modules.get("datasets")
if existing is not None:
    existing_file = str(getattr(existing, "__file__", "") or "")
    if existing_file and "site-packages" in existing_file.lower():
        del sys.modules["datasets"]

importlib.invalidate_caches()
