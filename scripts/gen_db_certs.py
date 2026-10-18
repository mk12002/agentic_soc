"""TLS for the single-host (Docker Compose) PostgreSQL: a private CA and a server certificate for ``postgres``.

    python scripts/gen_db_certs.py OUT_DIR [--host postgres] [--days 825]

Writes ``ca.crt`` (world-readable: clients verify the server with it, ``sslmode=verify-full``), ``server.crt`` and
``server.key`` (0600: PostgreSQL refuses a key others can read). Idempotent: existing files are kept, so the CA
clients trust does not change on every start; delete the folder to issue new ones. Compose runs this once in the
``db-certs`` service as the PostgreSQL user. A managed or Kubernetes database brings its own certificates.
"""

from __future__ import annotations

import argparse
import datetime as dt
import os
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


def _write(path: Path, data: bytes, mode: int) -> None:
    path.write_bytes(data)
    os.chmod(path, mode)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("out")
    ap.add_argument("--host", default="postgres")
    ap.add_argument("--days", type=int, default=825)
    a = ap.parse_args(argv)
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    if all((out / f).is_file() for f in ("ca.crt", "server.crt", "server.key")):
        print(f"certificates already in {out}")
        return 0
    now = dt.datetime.now(dt.UTC)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "SOC platform database CA")])
    ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name).public_key(ca_key.public_key())
          .serial_number(x509.random_serial_number()).not_valid_before(now - dt.timedelta(minutes=5))
          .not_valid_after(now + dt.timedelta(days=a.days))
          .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
          .add_extension(x509.KeyUsage(digital_signature=False, content_commitment=False, key_encipherment=False,
                                       data_encipherment=False, key_agreement=False, key_cert_sign=True,
                                       crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
          .sign(ca_key, hashes.SHA256()))
    key = ec.generate_private_key(ec.SECP256R1())
    cert = (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, a.host)])).issuer_name(ca_name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(minutes=5)).not_valid_after(now + dt.timedelta(days=a.days))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(a.host)]), critical=False)
            .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .sign(ca_key, hashes.SHA256()))
    pem = serialization.Encoding.PEM
    _write(out / "ca.crt", ca.public_bytes(pem), 0o644)
    _write(out / "server.crt", cert.public_bytes(pem), 0o644)
    _write(out / "server.key", key.private_bytes(pem, serialization.PrivateFormat.PKCS8,
                                                 serialization.NoEncryption()), 0o600)
    print(f"wrote ca.crt, server.crt, server.key to {out} (valid {a.days} days)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
