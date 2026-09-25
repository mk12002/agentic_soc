"""Encryption at rest for raw tool payloads and reported emails (NFR-08, R10).

Raw payloads and ``.eml`` files hold personal data and credentials-in-the-clear more often than
anyone expects, so they are encrypted with Fernet (AES-128-CBC + HMAC-SHA256) when
``SOC_DATA_KEY`` is set (comma-separated keys: the first encrypts, all decrypt, so keys can be
rotated without re-encrypting everything at once). In ``prod`` a key is mandatory.

Generate a key:  python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken, MultiFernet

from soc_platform.config import Settings, get_settings

MAGIC = b"SOCENC1:"


class DataProtectionError(RuntimeError):
    pass


class DataCipher:
    def __init__(self, keys: list[str]) -> None:
        if not keys:
            raise DataProtectionError("no data keys configured")
        try:
            self._f = MultiFernet([Fernet(k.encode() if isinstance(k, str) else k) for k in keys])
        except (ValueError, TypeError) as exc:
            raise DataProtectionError("SOC_DATA_KEY is not a valid Fernet key") from exc

    def encrypt(self, data: bytes) -> bytes:
        return MAGIC + self._f.encrypt(data)

    def decrypt(self, blob: bytes) -> bytes:
        if not blob.startswith(MAGIC):
            return blob  # legacy plaintext written before encryption was enabled
        try:
            return self._f.decrypt(blob[len(MAGIC):])
        except InvalidToken as exc:
            raise DataProtectionError("cannot decrypt payload (wrong key or tampered)") from exc

    def rotate(self, blob: bytes) -> bytes:
        return MAGIC + self._f.rotate(blob[len(MAGIC):]) if blob.startswith(MAGIC) else self.encrypt(blob)


def get_cipher(settings: Settings | None = None) -> DataCipher | None:
    st = settings or get_settings()
    if st.data_keys:
        return DataCipher(st.data_keys)
    if st.environment == "prod":
        raise DataProtectionError("SOC_DATA_KEY is required in prod (encryption at rest for raw payloads)")
    return None


def write_protected(path: str | Path, data: bytes, cipher: DataCipher | None = None) -> Path:
    """Atomically write ``data`` (encrypted when a key is configured) with owner-only permissions."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    c = cipher if cipher is not None else get_cipher()
    blob = c.encrypt(data) if c else data
    fd, tmp = tempfile.mkstemp(dir=p.parent, prefix=".tmp-")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(blob)
        os.chmod(tmp, 0o600)
        os.replace(tmp, p)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise
    return p


def seal_file(path: str | Path, cipher: DataCipher | None = None) -> Path:
    """Encrypt an already-written file in place (e.g. a generated report) when a data key is configured."""
    p = Path(path)
    data = p.read_bytes()
    if data.startswith(MAGIC):
        return p
    return write_protected(p, data, cipher)


def read_protected(path: str | Path, cipher: DataCipher | None = None) -> bytes:
    blob = Path(path).read_bytes()
    if not blob.startswith(MAGIC):
        return blob
    c = cipher if cipher is not None else get_cipher()
    if c is None:
        raise DataProtectionError(f"{path} is encrypted but SOC_DATA_KEY is not set")
    return c.decrypt(blob)
