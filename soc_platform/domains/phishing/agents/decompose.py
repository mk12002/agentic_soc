"""Email decomposition (PH-F02): headers, authentication, routing path, bodies, URLs,
attachments (hashes + fuzzy hash), embedded images and QR codes.

Pure-stdlib parsing so it works with or without the ML engine installed; QR decoding
uses pyzbar when available and degrades gracefully (recorded in ``warnings``).
"""

from __future__ import annotations

import hashlib
import html as htmllib
import io
import re
from dataclasses import dataclass, field
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from email.utils import getaddresses, parseaddr, parsedate_to_datetime
from typing import Any

URL_RE = re.compile(r"""https?://[^\s"'<>\)\]]+""", re.IGNORECASE)
HREF_RE = re.compile(r"""href\s*=\s*["']([^"']+)["']""", re.IGNORECASE)
AUTH_RE = re.compile(r"\b(spf|dkim|dmarc|arc|compauth)=(\w+)", re.IGNORECASE)
RECEIVED_FROM_RE = re.compile(r"from\s+([^\s;()]+)(?:\s*\(([^)]*)\))?", re.IGNORECASE)
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
RISKY_EXT = {".exe", ".scr", ".js", ".jse", ".vbs", ".vbe", ".hta", ".wsf", ".ps1", ".bat", ".cmd", ".lnk", ".iso",
             ".img", ".vhd", ".one", ".html", ".htm", ".svg", ".docm", ".xlsm", ".pptm", ".jar", ".msi", ".zip", ".rar", ".7z"}


@dataclass
class Attachment:
    filename: str
    content_type: str
    size: int
    sha256: str
    ssdeep: str | None
    risky_extension: bool
    qr_urls: list[str] = field(default_factory=list)
    has_macros_hint: bool = False


@dataclass
class DecomposedEmail:
    message_id: str
    subject: str
    sender: str
    sender_domain: str
    display_name: str
    reply_to: str | None
    return_path: str | None
    to: list[str]
    cc: list[str]
    date: str | None
    auth: dict[str, str]
    received_path: list[dict[str, Any]]
    origin_ip: str | None
    body_text: str
    body_html: str
    urls: list[str]
    url_domains: list[str]
    hidden_link_mismatch: list[dict[str, str]]
    attachments: list[Attachment]
    headers: dict[str, str]
    raw_sha256: str
    warnings: list[str] = field(default_factory=list)

    @property
    def qr_urls(self) -> list[str]:
        return sorted({u for a in self.attachments for u in a.qr_urls})

    def indicators(self) -> dict[str, list[str]]:
        return {"sender": [self.sender] if self.sender else [], "domain": sorted({self.sender_domain, *self.url_domains} - {""}),
                "url": sorted(set(self.urls) | set(self.qr_urls)), "ip": [self.origin_ip] if self.origin_ip else [],
                "sha256": [a.sha256 for a in self.attachments]}


def _domain(addr: str) -> str:
    return addr.rsplit("@", 1)[-1].lower() if "@" in addr else ""


def _url_domain(u: str) -> str:
    return re.sub(r"^https?://", "", u, flags=re.IGNORECASE).split("/")[0].split("?")[0].split(":")[0].lower()


def _qr_from_image(data: bytes, warnings: list[str]) -> list[str]:
    try:
        from PIL import Image
        from pyzbar.pyzbar import decode
    except Exception:  # pragma: no cover - optional dependency
        warnings.append("QR decoding unavailable (install pyzbar + Pillow)")
        return []
    try:
        img = Image.open(io.BytesIO(data))
        return [d.data.decode("utf-8", "replace") for d in decode(img)]
    except Exception as exc:
        warnings.append(f"QR decode failed: {type(exc).__name__}")
        return []


def _fuzzy(data: bytes) -> str | None:
    try:
        import ppdeep

        return ppdeep.hash(data)
    except Exception:
        return None


def _hdr_all(msg: Any, name: str) -> list[str]:
    """Header values as text, safely: Python's structured header parser raises on some malformed headers (for
    example a raw newline inside an address display name). Hostile mail must not stop the analysis, so fall back to
    the header exactly as received."""
    try:
        return [str(v) for v in (msg.get_all(name, []) or [])]
    except Exception:
        return [str(v) for k, v in msg.raw_items() if k.lower() == name.lower()]


def _hdr(msg: Any, name: str) -> str:
    vals = _hdr_all(msg, name)
    return vals[0] if vals else ""


def _headers(msg: Any) -> dict[str, str]:
    """Every header, decoded where it parses and as received where it does not."""
    out: dict[str, str] = {}
    for k, raw in msg.raw_items():
        try:
            v = str(msg.policy.header_fetch_parse(k, raw))
        except Exception:
            v = str(raw)
        out[k] = v[:500]                                                   # a repeated header keeps its last value
    return out


def _part_meta(part: Any) -> tuple[str, str, str | None]:
    """(content type, disposition, filename) of a MIME part, tolerating malformed headers."""
    try:
        ctype = part.get_content_type()
    except Exception:
        ctype = "application/octet-stream"
    try:
        disp = (part.get_content_disposition() or "").lower()
    except Exception:
        disp = ""
    try:
        fname = part.get_filename()
    except Exception:
        fname = "unnamed.bin"
    return ctype, disp, fname


def decompose(raw: bytes) -> DecomposedEmail:
    msg: EmailMessage = BytesParser(policy=policy.default).parsebytes(raw)  # type: ignore[assignment]
    warnings: list[str] = []
    display, sender = parseaddr(_hdr(msg, "From"))
    sender = sender.lower()
    auth_hdr = " ".join(_hdr_all(msg, "Authentication-Results"))
    auth = {k.lower(): v.lower() for k, v in AUTH_RE.findall(auth_hdr)}
    received = []
    for hop in _hdr_all(msg, "Received"):
        m = RECEIVED_FROM_RE.search(str(hop))
        ips = IP_RE.findall(str(hop))
        received.append({"from": m.group(1) if m else None, "ips": ips, "raw": str(hop)[:300]})
    origin_ip = next((ip for hop in reversed(received) for ip in hop["ips"]
                      if not ip.startswith(("10.", "192.168.", "127.")) and not re.match(r"172\.(1[6-9]|2\d|3[01])\.", ip)),
                     None)

    text_parts, html_parts, attachments = [], [], []
    for part in msg.walk():
        if part.is_multipart():
            continue
        ctype, disp, fname = _part_meta(part)
        try:
            payload = part.get_payload(decode=True) or b""
        except Exception:
            payload = str(part.get_payload()).encode("utf-8", "replace")
        if not isinstance(payload, bytes):
            payload = str(payload).encode("utf-8", "replace")
        if disp == "attachment" or fname or ctype.startswith(("image/", "application/")):
            if ctype in ("text/plain", "text/html") and not fname:
                pass
            else:
                name = fname or f"inline.{ctype.split('/')[-1]}"
                ext = "." + name.rsplit(".", 1)[-1].lower() if "." in name else ""
                att = Attachment(filename=name, content_type=ctype, size=len(payload),
                                 sha256=hashlib.sha256(payload).hexdigest(), ssdeep=_fuzzy(payload),
                                 risky_extension=ext in RISKY_EXT,
                                 has_macros_hint=b"vbaProject" in payload or b"AutoOpen" in payload)
                if ctype.startswith("image/"):
                    att.qr_urls = _qr_from_image(payload, warnings)
                attachments.append(att)
                continue
        try:
            content = part.get_content()
        except Exception:
            content = payload.decode("utf-8", "replace")
        (html_parts if ctype == "text/html" else text_parts).append(str(content))

    body_html = "\n".join(html_parts)
    body_text = "\n".join(text_parts) or re.sub(r"<[^>]+>", " ", htmllib.unescape(body_html))
    hrefs = [htmllib.unescape(h) for h in HREF_RE.findall(body_html)]
    urls = sorted({u.rstrip(".,;") for u in URL_RE.findall(body_text) + URL_RE.findall(body_html) + hrefs
                   if u.lower().startswith("http")})
    # Link text that shows one domain but points to another (classic phishing tell)
    mismatch = []
    for m in re.finditer(r"""<a[^>]+href\s*=\s*["']([^"']+)["'][^>]*>(.*?)</a>""", body_html, re.IGNORECASE | re.DOTALL):
        href, text = m.group(1), re.sub(r"<[^>]+>", "", m.group(2)).strip()
        shown = URL_RE.search(text) or re.search(r"\b[a-z0-9-]+(\.[a-z0-9-]+)+\b", text, re.IGNORECASE)
        if shown and href.startswith("http") and _url_domain(href) not in text.lower():
            mismatch.append({"shown": shown.group(0), "href": href})
    all_urls = sorted(set(urls) | {u for a in attachments for u in a.qr_urls if u.startswith("http")})
    date = None
    try:
        date = parsedate_to_datetime(_hdr(msg, "Date")).isoformat() if _hdr(msg, "Date") else None
    except Exception:
        warnings.append("unparseable Date header")
    return DecomposedEmail(
        message_id=_hdr(msg, "Message-ID").strip(), subject=_hdr(msg, "Subject"), sender=sender,
        sender_domain=_domain(sender), display_name=display, reply_to=parseaddr(_hdr(msg, "Reply-To"))[1] or None,
        return_path=parseaddr(_hdr(msg, "Return-Path"))[1] or None,
        to=[a.lower() for _, a in getaddresses(_hdr_all(msg, "To")) if a],
        cc=[a.lower() for _, a in getaddresses(_hdr_all(msg, "Cc")) if a], date=date, auth=auth,
        received_path=received, origin_ip=origin_ip, body_text=body_text, body_html=body_html, urls=all_urls,
        url_domains=sorted({_url_domain(u) for u in all_urls}), hidden_link_mismatch=mismatch,
        attachments=attachments, headers=_headers(msg),
        raw_sha256=hashlib.sha256(raw).hexdigest(), warnings=warnings)
