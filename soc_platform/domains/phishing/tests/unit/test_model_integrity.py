"""Pickle/joblib model artifacts are verified against the manifest before deserialisation."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from soc_platform.domains.phishing.engine import integrity


def test_shipped_models_verify():
    for rel in integrity._manifest():
        integrity.verify(integrity.PHISHING_HOME / "models" / rel)


def test_tampered_model_is_refused(tmp_path, monkeypatch):
    models = tmp_path / "models" / "header_agent"
    models.mkdir(parents=True)
    real = integrity.PHISHING_HOME / "models" / "header_agent" / "model.joblib"
    shutil.copy(real, models / "model.joblib")
    (tmp_path / "models" / "MANIFEST.sha256").write_text(
        f"{integrity._sha256(real)}  header_agent/model.joblib\n", encoding="utf-8")
    monkeypatch.setattr(integrity, "PHISHING_HOME", tmp_path)
    monkeypatch.setattr(integrity, "MANIFEST", tmp_path / "models" / "MANIFEST.sha256")
    integrity._manifest.cache_clear()
    integrity.verify(models / "model.joblib")                    # untouched copy passes
    with (models / "model.joblib").open("ab") as fh:              # attacker appends a payload
        fh.write(b"cos\nsystem\n(S'calc'\ntR.")
    with pytest.raises(integrity.ModelIntegrityError):
        integrity.verify(models / "model.joblib")
    rogue = tmp_path / "models" / "rogue.pkl"
    rogue.write_bytes(b"x")
    with pytest.raises(integrity.ModelIntegrityError):            # unlisted artifacts are refused
        integrity.verify(rogue)
    integrity._manifest.cache_clear()
