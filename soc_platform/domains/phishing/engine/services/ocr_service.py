"""OCR extraction service for image and PDF attachments.

Uses Azure AI Vision API to extract text from image/PDF email attachments,
and pyzbar for local QR code/barcode payload extraction.
Scans extracted text for hidden URLs that bypass traditional content scanners.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

try:
    from PIL import Image, ImageFile
    ImageFile.LOAD_TRUNCATED_IMAGES = True
    from pyzbar.pyzbar import decode
except ImportError:
    Image = None
    decode = None

from soc_platform.domains.phishing.engine.configs.settings import settings
from soc_platform.domains.phishing.engine.services.logging_service import get_service_logger

logger = get_service_logger("ocr_service")

# Extensions eligible for OCR processing
OCR_IMAGE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".bmp", ".tiff", ".tif", ".gif", ".webp"}
OCR_DOCUMENT_EXTENSIONS = {".pdf"}
OCR_ELIGIBLE_EXTENSIONS = OCR_IMAGE_EXTENSIONS | OCR_DOCUMENT_EXTENSIONS

URL_PATTERN = re.compile(
    r"https?://[^\s\"'<>\]\)]+",
    re.IGNORECASE,
)


def is_ocr_eligible(filename: str) -> bool:
    """Check if a file extension is eligible for OCR processing."""
    return Path(filename).suffix.lower() in OCR_ELIGIBLE_EXTENSIONS


def _extract_barcodes_local(file_path: Path) -> list[str]:
    """Extract barcode and QR code payloads locally using pyzbar.
    Only works for images, not PDFs.
    """
    if decode is None or Image is None:
        return []
    
    if file_path.suffix.lower() not in OCR_IMAGE_EXTENSIONS:
        return []

    try:
        image = Image.open(str(file_path))
        decoded_objects = decode(image)
        return [obj.data.decode("utf-8") for obj in decoded_objects if obj.data]
    except Exception as exc:
        logger.warning("Local barcode extraction failed", file=str(file_path), error=str(exc))
        return []


def extract_text_from_file(file_path: Path) -> dict[str, Any]:
    """Extract text from an image or PDF file using Azure AI Vision API
    and local pyzbar for QR/Barcodes.

    Returns a dict with keys:
        - success: bool
        - extracted_text: str (raw text from OCR)
        - discovered_urls: list[str] (URLs found in extracted text + QR codes)
        - error: str | None
    """
    result: dict[str, Any] = {
        "success": False,
        "extracted_text": "",
        "discovered_urls": [],
        "error": None,
    }

    if not settings.enable_ocr_extraction:
        result["error"] = "OCR extraction is disabled"
        return result

    if not file_path.exists() or not file_path.is_file():
        result["error"] = f"File not found: {file_path}"
        return result

    file_size_mb = file_path.stat().st_size / (1024 * 1024)
    if file_size_mb > settings.ocr_max_file_size_mb:
        result["error"] = f"File too large ({file_size_mb:.1f}MB > {settings.ocr_max_file_size_mb}MB limit)"
        return result

    extracted_text = ""
    discovered_urls: list[str] = []

    # 1. Local Barcode/QR Extraction
    barcode_payloads = _extract_barcodes_local(file_path)
    if barcode_payloads:
        extracted_text += "\n[BARCODE_DATA]:\n" + "\n".join(barcode_payloads) + "\n"
        for payload in barcode_payloads:
            discovered_urls.extend(URL_PATTERN.findall(payload))

    # 2. Azure AI Vision OCR
    endpoint = settings.azure_ocr_endpoint
    api_key = settings.azure_ocr_key

    if not endpoint or not api_key:
        result["error"] = "Azure OCR credentials not configured. Proceeded with local barcode extraction only."
    else:
        try:
            from azure.ai.vision.imageanalysis import ImageAnalysisClient
            from azure.ai.vision.imageanalysis.models import VisualFeatures
            from azure.core.credentials import AzureKeyCredential
            from azure.core.exceptions import AzureError
            
            raw_bytes = file_path.read_bytes()
            
            client = ImageAnalysisClient(
                endpoint=endpoint,
                credential=AzureKeyCredential(api_key)
            )

            logger.info("Sending file to Azure OCR via SDK", file=str(file_path), size_mb=f"{file_size_mb:.2f}")

            response = client.analyze(
                image_data=raw_bytes,
                visual_features=[VisualFeatures.READ]
            )

            if response.read is not None:
                for block in response.read.blocks:
                    for line in block.lines:
                        extracted_text += "\n" + line.text

        except ImportError:
            result["error"] = "Azure AI Vision SDK not installed. Please install azure-ai-vision-imageanalysis."
            logger.error("Azure SDK missing", file=str(file_path))
        except Exception as exc:
            err_str = str(exc)
            result["error"] = f"Azure OCR processing failed: {exc}"
            # 401 / auth errors are expected in dev or misconfigured environments.
            # Log at WARNING (no stack trace) to avoid alarming false-crash output.
            if any(token in err_str for token in ("401", "Access denied", "invalid subscription", "PermissionDenied")):
                logger.warning(
                    "Azure OCR auth/config error — check AZURE_OCR_ENDPOINT and AZURE_OCR_KEY",
                    file=str(file_path),
                    error=err_str[:200],
                )
            else:
                logger.exception("Unexpected Azure OCR error", file=str(file_path))

    # 3. Final URL Extraction & Deduplication
    if extracted_text.strip():
        result["success"] = True
        result["extracted_text"] = extracted_text.strip()
        
        all_urls = URL_PATTERN.findall(extracted_text) + discovered_urls
        seen: set[str] = set()
        unique_urls: list[str] = []
        for url in all_urls:
            url = url.rstrip(".,;:!?)")
            if url not in seen:
                seen.add(url)
                unique_urls.append(url)

        result["discovered_urls"] = unique_urls

        logger.info(
            "OCR extraction completed",
            file=str(file_path),
            text_length=len(extracted_text),
            urls_found=len(unique_urls),
        )

    return result


def extract_data_from_attachments(attachments: list[dict[str, Any]]) -> tuple[list[str], str]:
    """Scan eligible attachments for hidden URLs and text via OCR and Barcode readers.

    Args:
        attachments: List of attachment dicts with 'path' and 'filename' keys.

    Returns:
        A tuple of (discovered_urls, combined_extracted_text)
    """
    if not settings.enable_ocr_extraction:
        return [], ""

    all_urls: list[str] = []
    all_text: list[str] = []

    for attachment in attachments:
        filename = attachment.get("filename", "")
        path_str = attachment.get("path", "")

        if not is_ocr_eligible(filename):
            continue

        file_path = Path(path_str)
        if not file_path.exists():
            logger.debug("Skipping OCR for missing file", filename=filename, path=path_str)
            continue

        result = extract_text_from_file(file_path)

        if result["success"]:
            if result["discovered_urls"]:
                logger.info(
                    "OCR discovered hidden URLs in attachment",
                    filename=filename,
                    url_count=len(result["discovered_urls"]),
                )
                all_urls.extend(result["discovered_urls"])
            if result["extracted_text"]:
                all_text.append(f"--- Extracted text from {filename} ---\n{result['extracted_text']}")

        if result.get("error"):
            logger.debug(
                "OCR extraction issue",
                filename=filename,
                error=result["error"],
            )

    return all_urls, "\n\n".join(all_text)

