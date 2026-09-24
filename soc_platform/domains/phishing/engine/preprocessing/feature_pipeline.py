"""
Feature engineering pipeline for local model training (RTX 4050 workflow).
"""

from __future__ import annotations

import ipaddress
import math
import posixpath
import re
from pathlib import Path
from urllib.parse import SplitResult, urlsplit, urlunsplit

import pandas as pd

URL_REGEX = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
SUSPICIOUS_TOKENS = (
    "login",
    "verify",
    "secure",
    "update",
    "account",
    "signin",
    "auth",
    "password",
    "wallet",
    "invoice",
    "confirm",
    "payment",
    "free",
    "bonus",
    "urgent",
    "token",
)

URL_FEATURE_COLUMNS = [
    "url_length",
    "host_length",
    "path_length",
    "query_length",
    "subdomain_count",
    "dot_count",
    "digit_count",
    "digit_ratio",
    "special_char_count",
    "slash_count",
    "hyphen_count",
    "at_count",
    "question_count",
    "ampersand_count",
    "percent_count",
    "equals_count",
    "path_depth",
    "suspicious_token_count",
    "host_entropy",
    "url_entropy",
    "is_https",
    "has_ip_host",
    "has_port",
    "punycode_flag",
    "tld_length",
]


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    probs = [value.count(char) / len(value) for char in set(value)]
    return float(-sum(prob * math.log(prob, 2) for prob in probs))


def _is_ip_host(host: str) -> bool:
    if not host:
        return False
    candidate = host.strip("[]")
    try:
        ipaddress.ip_address(candidate)
        return True
    except ValueError:
        return False


def normalize_url(raw_url: str) -> str | None:
    """Normalize raw URL strings into a canonical form for stable dedup/features."""
    text = str(raw_url or "").strip().strip('"').strip("'")
    if not text:
        return None
    if " " in text:
        text = text.replace(" ", "")
    if "://" not in text:
        text = f"https://{text}"

    try:
        parsed = urlsplit(text)
    except Exception:
        return None

    scheme = (parsed.scheme or "https").lower()
    if scheme not in {"http", "https"}:
        scheme = "https"

    netloc = parsed.netloc or parsed.path
    path = parsed.path if parsed.netloc else ""

    if "@" in netloc:
        netloc = netloc.rsplit("@", 1)[-1]

    host = netloc
    port = ""
    if ":" in netloc and not netloc.startswith("["):
        host, _, port = netloc.partition(":")

    host = host.strip().strip(".").lower()
    if not host:
        return None

    try:
        host = host.encode("idna").decode("ascii")
    except Exception:
        return None

    if not _is_ip_host(host) and host != "localhost" and "." not in host:
        return None

    norm_path = path or "/"
    if not norm_path.startswith("/"):
        norm_path = f"/{norm_path}"
    try:
        norm_path = posixpath.normpath(norm_path)
    except Exception:
        norm_path = "/"
    if not norm_path.startswith("/"):
        norm_path = f"/{norm_path}"
    if norm_path == ".":
        norm_path = "/"

    netloc_with_port = host
    if port.isdigit():
        netloc_with_port = f"{host}:{port}"

    cleaned = SplitResult(
        scheme=scheme,
        netloc=netloc_with_port,
        path=norm_path,
        query=parsed.query,
        fragment="",
    )
    return urlunsplit(cleaned)


def extract_url_lexical_features(url: str) -> dict[str, float]:
    parsed = urlsplit(url)
    host = (parsed.hostname or "").lower()
    path = parsed.path or ""
    query = parsed.query or ""
    lowered_url = url.lower()

    digit_count = sum(1 for char in url if char.isdigit())
    special_char_count = sum(1 for char in url if not char.isalnum())
    url_len = max(len(url), 1)

    has_ip = 1.0 if _is_ip_host(host) else 0.0
    labels = [segment for segment in host.split(".") if segment]
    tld = labels[-1] if labels else ""
    if has_ip:
        subdomain_count = 0
        tld = ""
    elif len(labels) > 2:
        subdomain_count = len(labels) - 2
    else:
        subdomain_count = 0

    suspicious_token_count = sum(1 for token in SUSPICIOUS_TOKENS if token in lowered_url)
    path_depth = len([segment for segment in path.split("/") if segment])

    return {
        "url_length": float(len(url)),
        "host_length": float(len(host)),
        "path_length": float(len(path)),
        "query_length": float(len(query)),
        "subdomain_count": float(subdomain_count),
        "dot_count": float(url.count(".")),
        "digit_count": float(digit_count),
        "digit_ratio": float(digit_count / url_len),
        "special_char_count": float(special_char_count),
        "slash_count": float(url.count("/")),
        "hyphen_count": float(url.count("-")),
        "at_count": float(url.count("@")),
        "question_count": float(url.count("?")),
        "ampersand_count": float(url.count("&")),
        "percent_count": float(url.count("%")),
        "equals_count": float(url.count("=")),
        "path_depth": float(path_depth),
        "suspicious_token_count": float(suspicious_token_count),
        "host_entropy": float(_entropy(host)),
        "url_entropy": float(_entropy(url)),
        "is_https": float(1 if parsed.scheme.lower() == "https" else 0),
        "has_ip_host": float(has_ip),
        "has_port": float(1 if parsed.port else 0),
        "punycode_flag": float(1 if "xn--" in host else 0),
        "tld_length": float(len(tld)),
    }


def build_url_features(urls: list[str], label: int) -> pd.DataFrame:
    rows = []
    for raw_url in urls:
        normalized = normalize_url(raw_url)
        if not normalized:
            continue

        row = {"url": normalized, **extract_url_lexical_features(normalized), "label": int(label)}
        rows.append(row)

    if not rows:
        return pd.DataFrame(columns=["url", *URL_FEATURE_COLUMNS, "label"])
    return pd.DataFrame(rows)


def build_content_features(email_rows: list[dict]) -> pd.DataFrame:
    rows = []
    for item in email_rows:
        content = (item.get("content") or "").lower()
        rows.append(
            {
                "text": item.get("content") or "",
                "word_count": len(content.split()),
                "urgency_count": sum(1 for term in ["urgent", "verify", "immediately"] if term in content),
                "url_count": len(URL_REGEX.findall(content)),
                "label": int(item.get("label", 0)),
            }
        )
    return pd.DataFrame(rows)


def write_processed_dataset(frame: pd.DataFrame, output_file: str | Path) -> str:
    output_path = Path(output_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    frame.to_csv(output_path, index=False)
    return str(output_path)
