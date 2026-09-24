"""
Email parsing service for extracting headers, body, URLs, and attachments.
"""

from __future__ import annotations

import hashlib
import re
import uuid
from email import policy
from email.parser import BytesParser
from email.utils import getaddresses
from pathlib import Path
from typing import Any

from bs4 import BeautifulSoup

try:
    import extract_msg  # type: ignore
except Exception:  # pragma: no cover
    extract_msg = None

from soc_platform.domains.phishing.engine.configs.settings import settings
from soc_platform.domains.phishing.engine.services.logging_service import get_service_logger
from soc_platform.domains.phishing.engine.services.messaging_service import RabbitMQClient
from soc_platform.domains.phishing.engine.services.ocr_service import extract_data_from_attachments

logger = get_service_logger("email_parser")

URL_REGEX = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)


class EmailParserService:
    """Parse raw email files and publish NewEmailEvent messages."""

    def __init__(self):
        import tempfile
        self.attachments_dir = Path(settings.attachment_volume_dir)
        try:
            self.attachments_dir.mkdir(parents=True, exist_ok=True)
        except PermissionError:
            fallback = Path(tempfile.gettempdir()) / "email_security_attachments"
            fallback.mkdir(parents=True, exist_ok=True)
            import logging as _logging
            _logging.getLogger("email_parser").warning(
                "Cannot create attachment dir %s (PermissionError) — falling back to %s",
                self.attachments_dir,
                fallback,
            )
            self.attachments_dir = fallback
        self.messaging = RabbitMQClient()

    def supports_extension(self, extension: str) -> bool:
        ext = (extension or "").lower()
        if ext in {".eml", ".txt"}:
            return True
        if ext == ".msg":
            return extract_msg is not None
        return False

    def supported_extensions(self) -> set[str]:
        exts = {".eml", ".txt"}
        if extract_msg is not None:
            exts.add(".msg")
        return exts

    def parse_file(self, file_path: str | Path) -> dict[str, Any]:
        source_path = Path(file_path)
        extension = source_path.suffix.lower()
        analysis_id = str(uuid.uuid4())

        if extension == ".msg":
            if extract_msg is None:
                raise ValueError(
                    "Outlook .msg parsing requires optional dependency 'extract-msg'."
                )
            headers, body_plain, body_html, attachments = self._parse_msg(source_path, analysis_id)
        else:
            with open(source_path, "rb") as source:
                raw_bytes = source.read()
            message = BytesParser(policy=policy.default).parsebytes(raw_bytes)
            headers = self._extract_headers(message)
            body_plain, body_html = self._extract_body_parts(message)
            attachments = self._extract_attachments(message, analysis_id)

        urls = self._extract_urls(body_plain, body_html)

        # OCR: extract hidden URLs and text from image/PDF attachments
        ocr_urls: list[str] = []
        ocr_text: str = ""
        try:
            ocr_urls, ocr_text = extract_data_from_attachments(attachments)
            
            if ocr_urls:
                logger.info(
                    "OCR discovered hidden URLs in attachments",
                    analysis_id=analysis_id,
                    ocr_url_count=len(ocr_urls),
                )
                urls = sorted(set(urls + ocr_urls))
                
            if ocr_text:
                logger.info(
                    "OCR extracted text from attachments",
                    analysis_id=analysis_id,
                    text_length=len(ocr_text),
                )
                # Append to body_plain so content_agent can analyze it
                body_plain += "\n\n" + ocr_text
                
        except Exception as exc:
            logger.warning("OCR extraction failed gracefully", error=str(exc))

        # Extract Graph identity fields for the action layer
        internet_message_id = (headers.get("message_id") or "").strip()
        recipients = headers.get("to", [])
        user_principal_name = recipients[0] if recipients else ""

        payload = {
            "event_type": "NewEmailEvent",
            "analysis_id": analysis_id,
            "source_file": str(file_path),
            "internet_message_id": internet_message_id,
            "user_principal_name": user_principal_name,
            "headers": headers,
            "body": {
                "plain": body_plain,
                "html": body_html,
            },
            "urls": urls,
            "ocr_extracted_urls": ocr_urls,
            "attachments": attachments,
            "iocs": {
                "domains": self._extract_domains(urls),
                "ips": self._extract_ips(body_plain + "\n" + body_html),
                "hashes": [item["sha256"] for item in attachments],
            },
        }
        return payload

    def _parse_msg(
        self,
        source_path: Path,
        analysis_id: str,
    ) -> tuple[dict[str, Any], str, str, list[dict[str, Any]]]:
        msg = extract_msg.Message(str(source_path))  # type: ignore[union-attr]
        sender_raw = str(getattr(msg, "sender", "") or "")
        to_raw = str(getattr(msg, "to", "") or "")
        cc_raw = str(getattr(msg, "cc", "") or "")
        subject = str(getattr(msg, "subject", "") or "")
        message_id = str(getattr(msg, "messageId", "") or "")

        body_plain = str(getattr(msg, "body", "") or "")
        html_body = getattr(msg, "htmlBody", "")
        if isinstance(html_body, bytes):
            body_html = html_body.decode("utf-8", errors="replace")
        else:
            body_html = str(html_body or "")

        raw_header = str(getattr(msg, "header", "") or "")
        auth_results = ""
        received: list[str] = []
        raw_headers: dict[str, str] = {}
        # ARC headers repeat per instance, so collect them as lists (a flat dict
        # would keep only the last instance and break chain validation).
        arc: dict[str, list[str]] = {"seal": [], "message_signature": [], "authentication_results": []}
        if raw_header:
            for line in raw_header.splitlines():
                if ":" not in line:
                    continue
                key, value = line.split(":", 1)
                cleaned_key = key.strip()
                cleaned_value = value.strip()
                if cleaned_key:
                    raw_headers[cleaned_key] = cleaned_value
                key_lower = cleaned_key.lower()
                if key_lower == "authentication-results":
                    auth_results = cleaned_value
                if key_lower == "received":
                    received.append(cleaned_value)
                elif key_lower == "arc-seal":
                    arc["seal"].append(cleaned_value)
                elif key_lower == "arc-message-signature":
                    arc["message_signature"].append(cleaned_value)
                elif key_lower == "arc-authentication-results":
                    arc["authentication_results"].append(cleaned_value)

        sender_addr = getaddresses([sender_raw])
        recipient_addrs = getaddresses([to_raw, cc_raw])

        headers = {
            "from": sender_raw,
            "sender": sender_addr[0][1] if sender_addr else "",
            "reply_to": raw_headers.get("Reply-To"),
            "to": [entry[1] for entry in recipient_addrs if entry[1]],
            "subject": subject,
            "message_id": message_id or raw_headers.get("Message-ID"),
            "received": received,
            "authentication_results": auth_results,
            "arc": arc,
            "raw": raw_headers,
        }

        attachments: list[dict[str, Any]] = []
        for item in getattr(msg, "attachments", []) or []:
            payload = getattr(item, "data", None)
            if callable(payload):
                payload = payload()
            if payload is None:
                continue
            if isinstance(payload, str):
                payload = payload.encode("utf-8", errors="ignore")
            if not isinstance(payload, (bytes, bytearray)):
                continue

            attachment_uuid = str(uuid.uuid4())
            filename = (
                getattr(item, "longFilename", None)
                or getattr(item, "filename", None)
                or f"attachment-{attachment_uuid}.bin"
            )
            safe_name = re.sub(r"[^A-Za-z0-9._-]", "_", str(filename))
            target_name = f"{analysis_id}_{attachment_uuid}_{safe_name}"
            target_path = self.attachments_dir / target_name
            with open(target_path, "wb") as output:
                output.write(bytes(payload))

            sha256 = hashlib.sha256(bytes(payload)).hexdigest()
            attachments.append(
                {
                    "attachment_id": attachment_uuid,
                    "filename": str(filename),
                    "content_type": getattr(item, "mimetype", None) or "application/octet-stream",
                    "size_bytes": len(payload),
                    "sha256": sha256,
                    "path": str(target_path),
                }
            )

        return headers, body_plain, body_html, attachments

    def parse_and_publish(self, file_path: str | Path) -> dict[str, Any]:
        payload = self.parse_file(file_path)
        try:
            self.messaging.connect()
            self.messaging.publish_new_email(payload)
            self.messaging.close()
            logger.info("Published NewEmailEvent", analysis_id=payload["analysis_id"])
        except Exception as msg_exc:
            # If messaging fails (e.g., RabbitMQ not available), log but don't fail the parse
            logger.warning(f"Failed to publish to message queue: {msg_exc} - Email parsing still succeeded")
        return payload

    def _extract_headers(self, message) -> dict[str, Any]:
        sender_raw = message.get("From", "")
        recipients_raw = message.get_all("To", []) + message.get_all("Cc", [])
        sender_addr = getaddresses([sender_raw])
        recipient_addrs = getaddresses(recipients_raw)

        return {
            "from": sender_raw,
            "sender": sender_addr[0][1] if sender_addr else "",
            "reply_to": message.get("Reply-To"),
            "to": [entry[1] for entry in recipient_addrs if entry[1]],
            "subject": message.get("Subject", ""),
            "message_id": message.get("Message-ID"),
            "received": message.get_all("Received", []),
            "authentication_results": message.get("Authentication-Results", ""),
            # ARC headers repeat per instance; preserve all of them as lists for
            # chain validation (the flat ``raw`` dict below keeps only the last).
            "arc": {
                "seal": [str(v) for v in message.get_all("ARC-Seal", [])],
                "message_signature": [str(v) for v in message.get_all("ARC-Message-Signature", [])],
                "authentication_results": [str(v) for v in message.get_all("ARC-Authentication-Results", [])],
            },
            "raw": {key: value for key, value in message.items()},
        }

    def _extract_body_parts(self, message) -> tuple[str, str]:
        plain_chunks: list[str] = []
        html_chunks: list[str] = []

        if message.is_multipart():
            for part in message.walk():
                content_disposition = (part.get_content_disposition() or "").lower()
                if content_disposition == "attachment":
                    continue
                content_type = part.get_content_type().lower()
                payload = self._safe_decode_part(part)
                if not payload:
                    continue
                if content_type == "text/plain":
                    plain_chunks.append(payload)
                elif content_type == "text/html":
                    html_chunks.append(payload)
        else:
            payload = self._safe_decode_part(message)
            content_type = message.get_content_type().lower()
            if content_type == "text/html":
                html_chunks.append(payload)
            else:
                plain_chunks.append(payload)

        return "\n".join(plain_chunks).strip(), "\n".join(html_chunks).strip()

    def _safe_decode_part(self, part) -> str:
        content = part.get_payload(decode=True)
        if content is None:
            try:
                return str(part.get_payload())
            except Exception:
                return ""
        charset = part.get_content_charset() or "utf-8"
        try:
            return content.decode(charset, errors="replace")
        except Exception:
            return content.decode("utf-8", errors="replace")

    def _extract_urls(self, plain: str, html: str) -> list[str]:
        extracted = set(URL_REGEX.findall(plain or ""))
        extracted.update(URL_REGEX.findall(html or ""))

        if html:
            soup = BeautifulSoup(html, "html.parser")
            for anchor in soup.find_all(["a", "button"]):
                href = anchor.get("href") or anchor.get("data-href") or anchor.get("onclick")
                if href:
                    extracted.update(URL_REGEX.findall(href))

        return sorted(extracted)

    def _extract_attachments(self, message, analysis_id: str) -> list[dict[str, Any]]:
        saved: list[dict[str, Any]] = []
        for part in message.walk():
            if part.get_content_disposition() != "attachment":
                continue
            payload = part.get_payload(decode=True)
            if not payload:
                continue

            attachment_uuid = str(uuid.uuid4())
            filename = part.get_filename() or f"attachment-{attachment_uuid}.bin"
            safe_name = re.sub(r"[^A-Za-z0-9._-]", "_", filename)
            target_name = f"{analysis_id}_{attachment_uuid}_{safe_name}"
            target_path = self.attachments_dir / target_name
            with open(target_path, "wb") as output:
                output.write(payload)

            sha256 = hashlib.sha256(payload).hexdigest()
            saved.append(
                {
                    "attachment_id": attachment_uuid,
                    "filename": filename,
                    "content_type": part.get_content_type(),
                    "size_bytes": len(payload),
                    "sha256": sha256,
                    "path": str(target_path),
                }
            )
        return saved

    def _extract_domains(self, urls: list[str]) -> list[str]:
        domains = set()
        for url in urls:
            match = re.match(r"https?://([^/:?#]+)", url, flags=re.IGNORECASE)
            if match:
                domains.add(match.group(1).lower())
        return sorted(domains)

    def _extract_ips(self, content: str) -> list[str]:
        return sorted(set(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", content)))
