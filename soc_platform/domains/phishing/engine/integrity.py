"""Model artifact integrity (supply-chain protection for pickle/joblib models).

joblib/pickle files execute code when loaded, so a tampered model file is equivalent to
code execution. Every such artifact is checked against ``models/MANIFEST.sha256`` before
it is deserialised. Regenerate the manifest only through the model release process:

    python -m soc_platform.domains.phishing.engine.integrity --write
"""

from __future__ import annotations

import hashlib
import os
import sys
from functools import lru_cache
from pathlib import Path

from soc_platform.domains.phishing.engine.paths import PHISHING_HOME

MANIFEST = PHISHING_HOME / "models" / "MANIFEST.sha256"
PICKLE_SUFFIXES = {".joblib", ".pkl", ".pickle"}


class ModelIntegrityError(RuntimeError):
    pass


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


@lru_cache(maxsize=1)
def _manifest() -> dict[str, str]:
    if not MANIFEST.exists():
        return {}
    out = {}
    for line in MANIFEST.read_text(encoding="utf-8").splitlines():
        if line.strip() and not line.startswith("#"):
            digest, rel = line.split(None, 1)
            out[rel.strip().replace("\\", "/")] = digest.strip().lower()
    return out


def verify(path: str | Path) -> None:
    """Raise ModelIntegrityError unless ``path`` matches the manifest (pickle-type files only)."""
    p = Path(path).resolve()
    if p.suffix.lower() not in PICKLE_SUFFIXES:
        return
    manifest = _manifest()
    strict = os.environ.get("SOC_REQUIRE_MODEL_MANIFEST", "1") != "0"
    try:
        rel = p.relative_to((PHISHING_HOME / "models").resolve()).as_posix()
    except ValueError:
        rel = None
    expected = manifest.get(rel) if rel else None
    if expected is None:
        if strict:
            raise ModelIntegrityError(f"{p} is not listed in {MANIFEST}; refusing to unpickle an unverified artifact")
        return
    actual = _sha256(p)
    if actual != expected:
        raise ModelIntegrityError(f"{p} sha256 {actual[:12]}... does not match manifest {expected[:12]}...")


def write_manifest() -> Path:
    root = PHISHING_HOME / "models"
    lines = ["# sha256  path (relative to models/) - pickle/joblib artifacts verified before load"]
    for f in sorted(root.rglob("*")):
        if f.is_file() and f.suffix.lower() in PICKLE_SUFFIXES:
            lines.append(f"{_sha256(f)}  {f.relative_to(root).as_posix()}")
    MANIFEST.write_text("\n".join(lines) + "\n", encoding="utf-8")
    _manifest.cache_clear()
    return MANIFEST


if __name__ == "__main__":
    if "--write" in sys.argv:
        print("wrote", write_manifest())
    else:
        for rel in _manifest():
            verify(PHISHING_HOME / "models" / rel)
        print("all manifest entries verified")
