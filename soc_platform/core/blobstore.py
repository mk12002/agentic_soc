"""Where the platform's stored files live: raw vendor payloads, reported e-mails and generated reports.

One reference string points at a blob, whatever stores it:

* ``file`` (default) - a file under ``SOC_RAW_PAYLOAD_DIR`` / ``SOC_REPORT_OUTPUT_DIR``; the reference is its path.
  Right for one host, or several hosts sharing one volume.
* ``database`` (``SOC_BLOB_STORE=database``) - a row in ``blobs``; the reference is ``db:<key>``. Every replica on
  every host reads it, it is committed in the same transaction as the record that points at it (no orphan file, no
  missing file), and the database's own high availability, backups and point-in-time recovery cover it. Nothing
  else to make highly available.

Both are encrypted at rest with ``SOC_DATA_KEY`` (``core/crypto.py``). Reads follow the reference, not the setting, so
files written before a switch stay readable; ``python -m soc_platform blobs migrate`` moves them into the database.
"""

from __future__ import annotations

import hashlib
from datetime import datetime
from pathlib import Path
from typing import Any

from sqlalchemy import Integer, LargeBinary, String, select
from sqlalchemy.orm import Mapped, Session, mapped_column

from soc_platform.config import Settings, get_settings
from soc_platform.core.db import Base, UTCDateTime

DB_PREFIX = "db:"
BACKENDS = ("file", "database")


class Blob(Base):
    __tablename__ = "blobs"

    key: Mapped[str] = mapped_column(String(512), primary_key=True)
    data: Mapped[bytes] = mapped_column(LargeBinary)              # ciphertext when a data key is configured
    size: Mapped[int] = mapped_column(Integer)                    # plaintext bytes
    sha256: Mapped[str] = mapped_column(String(64))               # of the plaintext: integrity check on read
    created_at: Mapped[datetime] = mapped_column(UTCDateTime())


class BlobMissing(FileNotFoundError):
    """The reference points at nothing (deleted by retention, or a file on another host's disk)."""


def backend(settings: Settings | None = None) -> str:
    return (settings or get_settings()).blob_store


def is_db_ref(ref: str | None) -> bool:
    return bool(ref) and str(ref).startswith(DB_PREFIX)


def ref_name(ref: str) -> str:
    """The file name a reference stands for (download name, content type)."""
    return Path(ref[len(DB_PREFIX):] if is_db_ref(ref) else ref).name


class BlobStore:
    def __init__(self, session: Session, settings: Settings | None = None, cipher: Any = "auto") -> None:
        from soc_platform.core.crypto import get_cipher

        self.s = session
        self.settings = settings or get_settings()
        self.cipher = get_cipher(self.settings) if cipher == "auto" else cipher

    @property
    def backend(self) -> str:
        return self.settings.blob_store

    def put(self, path: str | Path, key: str, data: bytes) -> str:
        """Store ``data``: at ``path`` (file backend) or under ``key`` (database backend). Returns the reference.
        Writing the same key again replaces it (content-addressed callers write identical bytes)."""
        if self.backend != "database":
            from soc_platform.core.crypto import write_protected

            return str(write_protected(path, data, self.cipher))
        from soc_platform.core.models import utcnow

        blob = self.cipher.encrypt(data) if self.cipher else data
        row = self.s.get(Blob, key)
        digest = hashlib.sha256(data).hexdigest()
        if row is None:
            self.s.add(Blob(key=key, data=blob, size=len(data), sha256=digest, created_at=utcnow()))
        elif row.sha256 != digest:
            row.data, row.size, row.sha256, row.created_at = blob, len(data), digest, utcnow()
        self.s.flush()
        return DB_PREFIX + key

    def store_generated(self, path: str | Path, key: str) -> str:
        """A file a library wrote to local disk (python-docx, python-pptx, zipfile): sealed in place on the file
        backend, moved into the database (and the local copy removed) on the database backend."""
        p = Path(path)
        if self.backend != "database":
            from soc_platform.core.crypto import seal_file

            return str(seal_file(p, self.cipher))
        ref = self.put(p, key, p.read_bytes())
        p.unlink(missing_ok=True)
        return ref

    def get(self, ref: str) -> bytes:
        if is_db_ref(ref):
            row = self.s.get(Blob, ref[len(DB_PREFIX):])
            if row is None:
                raise BlobMissing(ref)
            data = self._decrypt(bytes(row.data), ref)
            if hashlib.sha256(data).hexdigest() != row.sha256:
                from soc_platform.core.crypto import DataProtectionError

                raise DataProtectionError(f"{ref} does not match its recorded checksum")
            return data
        from soc_platform.core.crypto import read_protected

        if not Path(ref).is_file():
            raise BlobMissing(ref)
        return read_protected(ref, self.cipher)

    def exists(self, ref: str | None) -> bool:
        if not ref:
            return False
        if is_db_ref(ref):
            return self.s.execute(select(Blob.key).where(Blob.key == ref[len(DB_PREFIX):])).first() is not None
        return Path(ref).is_file()

    def delete(self, ref: str | None) -> bool:
        if not ref:
            return False
        if is_db_ref(ref):
            row = self.s.get(Blob, ref[len(DB_PREFIX):])
            if row is None:
                return False
            self.s.delete(row)
            self.s.flush()
            return True
        p = Path(ref)
        try:
            if p.is_file():
                p.unlink()
                return True
        except OSError:
            return False
        return False

    def _decrypt(self, blob: bytes, ref: str) -> bytes:
        from soc_platform.core.crypto import MAGIC, DataProtectionError

        if not blob.startswith(MAGIC):
            if self.cipher is not None and self.cipher.strict:
                raise DataProtectionError(f"{ref} is not encrypted (run `python -m soc_platform blobs reencrypt`)")
            return blob
        if self.cipher is None:
            raise DataProtectionError(f"{ref} is encrypted but SOC_DATA_KEY is not set")
        return self.cipher.decrypt(blob)


def migrate_to_database(session: Session, settings: Settings | None = None, *, batch: int = 200) -> dict[str, Any]:
    """Move every file-backed reference into ``blobs`` and repoint the record. Idempotent (database references are
    skipped) and safe: a file that cannot be read is reported, not lost, and no file is deleted here - ``files``
    lists the moved ones for the caller to remove once the transaction has committed."""
    from soc_platform.core.crypto import get_cipher
    from soc_platform.core.models import SourceRecord
    from soc_platform.domains.phishing.models import Submission
    from soc_platform.domains.vulnerability.models import ReportRun

    st = (settings or get_settings()).model_copy(update={"blob_store": "database"})
    store = BlobStore(session, st, cipher=get_cipher(st, strict=False))   # legacy plaintext files move (and get sealed)
    out: dict[str, Any] = {"moved": 0, "missing": [], "already": 0, "files": []}
    targets = ((SourceRecord, "raw_ref", "raw"), (Submission, "raw_path", "phishing"), (ReportRun, "path", "reports"))
    for model, column, prefix in targets:
        col = getattr(model, column)
        rows = session.execute(select(model).where(col.is_not(None))).scalars().all()
        for i, row in enumerate(rows, 1):
            ref = getattr(row, column)
            if is_db_ref(ref):
                out["already"] += 1
                continue
            try:
                data = store.get(ref)
            except (BlobMissing, OSError) as exc:
                out["missing"].append({"table": model.__tablename__, "id": row.id, "ref": ref, "error": type(exc).__name__})
                continue
            key = f"{prefix}/{_relative_key(ref, prefix)}"
            setattr(row, column, store.put(ref, key, data))
            out["moved"] += 1
            out["files"].append(ref)
            if i % batch == 0:
                session.flush()
    session.flush()
    return out


def reencrypt(session: Session, settings: Settings | None = None, *, batch: int = 200) -> dict[str, Any]:
    """Seal every stored blob under the newest key (``SOC_DATA_KEY``'s first): legacy plaintext is encrypted and
    data under an older key is re-encrypted, so the old key can then be retired. Idempotent; a blob that cannot be
    read is reported, not changed."""
    from soc_platform.core.crypto import MAGIC, DataProtectionError, get_cipher, write_protected
    from soc_platform.core.models import SourceRecord
    from soc_platform.domains.phishing.models import Submission
    from soc_platform.domains.vulnerability.models import ReportRun

    st = settings or get_settings()
    cipher = get_cipher(st, strict=False)
    if cipher is None:
        raise DataProtectionError("SOC_DATA_KEY is not set: nothing to encrypt with")
    out: dict[str, Any] = {"database": 0, "file": 0, "unreadable": []}
    n = 0
    for row in session.execute(select(Blob)).scalars():
        raw = bytes(row.data)
        try:
            data = cipher.decrypt(raw)
        except DataProtectionError:
            out["unreadable"].append({"ref": DB_PREFIX + row.key})
            continue
        row.data = cipher.rotate(raw) if raw.startswith(MAGIC) else cipher.encrypt(data)
        out["database"] += 1
        n += 1
        if n % batch == 0:
            session.flush()
    for model, column in ((SourceRecord, "raw_ref"), (Submission, "raw_path"), (ReportRun, "path")):
        for (ref,) in session.execute(select(getattr(model, column)).where(getattr(model, column).is_not(None))):
            if is_db_ref(ref) or not Path(ref).is_file():
                continue
            try:
                raw = Path(ref).read_bytes()
                data = cipher.decrypt(raw)
                write_protected(ref, data, cipher)
                out["file"] += 1
            except (OSError, DataProtectionError):
                out["unreadable"].append({"ref": ref})
    session.flush()
    return out


def _relative_key(ref: str, prefix: str) -> str:
    """A stable key from a file path: the part after the store's folder name when present, else the file name."""
    parts = Path(ref).parts
    for anchor in (prefix, "raw", "reports", "phishing"):
        if anchor in parts:
            return "/".join(parts[len(parts) - parts[::-1].index(anchor):])
    return Path(ref).name


def check_references(session: Session, settings: Settings | None = None, *, sample: int | None = None) -> dict[str, Any]:
    """Every stored reference resolves (on this host). Used by ``blobs check`` and before a switch of backend."""
    from soc_platform.core.models import SourceRecord
    from soc_platform.domains.phishing.models import Submission
    from soc_platform.domains.vulnerability.models import ReportRun

    store = BlobStore(session, settings)
    out: dict[str, Any] = {"checked": 0, "database": 0, "file": 0, "unreadable": []}
    for model, column in ((SourceRecord, "raw_ref"), (Submission, "raw_path"), (ReportRun, "path")):
        q = select(model.id, getattr(model, column)).where(getattr(model, column).is_not(None)).order_by(model.id)
        if sample:
            q = q.limit(sample)
        for rid, ref in session.execute(q):
            out["checked"] += 1
            out["database" if is_db_ref(ref) else "file"] += 1
            if not store.exists(ref):
                out["unreadable"].append({"table": model.__tablename__, "id": rid, "ref": ref})
    return out
