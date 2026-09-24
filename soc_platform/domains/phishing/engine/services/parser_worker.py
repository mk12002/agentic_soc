"""
Folder-based ingestion worker.

Watches EMAIL_DROP_DIR for incoming .eml/.msg/.txt and publishes NewEmailEvent.
"""

from __future__ import annotations

import shutil
import time
from pathlib import Path

from soc_platform.domains.phishing.engine.configs.settings import settings
from soc_platform.domains.phishing.engine.services.email_parser import EmailParserService
from soc_platform.domains.phishing.engine.services.gdrive_client import get_gdrive_client
from soc_platform.domains.phishing.engine.services.logging_service import setup_logging, get_service_logger

logger = get_service_logger("parser_worker")


def _supported(path: Path, parser: EmailParserService) -> bool:
    return parser.supports_extension(path.suffix.lower())


def run() -> None:
    import signal
    setup_logging(settings.log_dir, settings.app_log_level, settings.log_format)
    parser = EmailParserService()

    drop_dir = Path(settings.email_drop_dir)
    processed_dir = drop_dir / "processed"
    failed_dir = drop_dir / "failed"
    
    if getattr(settings, "local_routing_enabled", False):
        drop_dir = Path(settings.local_ingestion_folder)
        staging_dir = Path(settings.local_staging_folder)
        failed_dir = drop_dir.parent / "Parse_Failed"
        target_approved = Path(settings.local_approved_folder)
        target_quarantine = Path(settings.local_quarantine_folder)
        target_deleted = Path(settings.local_deleted_folder)
        
        for d in [drop_dir, staging_dir, failed_dir, target_approved, target_quarantine, target_deleted]:
            d.mkdir(parents=True, exist_ok=True)
    else:
        drop_dir.mkdir(parents=True, exist_ok=True)
        processed_dir.mkdir(parents=True, exist_ok=True)
        failed_dir.mkdir(parents=True, exist_ok=True)

    is_running = True

    def _handle_shutdown(sig, frame):
        nonlocal is_running
        logger.info("Shutdown signal received", signal=sig)
        is_running = False

    signal.signal(signal.SIGTERM, _handle_shutdown)
    signal.signal(signal.SIGINT, _handle_shutdown)

    logger.info("Parser worker started", drop_dir=str(drop_dir))
    gdrive = get_gdrive_client()
    
    while is_running:
        if gdrive.is_configured():
            # Google Drive Mode
            new_emails = gdrive.list_new_emails()
            for gfile in new_emails:
                if not is_running:
                    break
                try:
                    file_id = gfile['id']
                    file_name = gfile['name']
                    staged_path = staging_dir / file_name
                    
                    # 1. Download
                    if not gdrive.download_file(file_id, str(staged_path)):
                        continue
                        
                    # 2. Move in GDrive from Ingestion to Staging
                    gdrive.move_file(file_id, gdrive.ingestion_folder_id, gdrive.staging_folder_id)
                    
                    # 3. Parse and publish
                    event = parser.parse_file(staged_path)
                    event["local_routing_path"] = str(staged_path)
                    event["gdrive_file_id"] = file_id  # Pass for response engine
                    
                    parser.messaging.connect()
                    parser.messaging.publish_new_email(event)
                    parser.messaging.close()
                    
                    logger.info(
                        "Parsed and published (GDrive mode)",
                        file_id=file_id,
                        analysis_id=event["analysis_id"],
                    )
                except Exception as exc:
                    logger.exception("Failed to parse GDrive email", file_id=gfile.get('id'), error=str(exc))
        else:
            # Local Mode fallback
            candidates = [
                path for path in drop_dir.iterdir() if path.is_file() and _supported(path, parser)
            ]
            for file_path in candidates:
                if not is_running:
                    break
                try:
                    if getattr(settings, "local_routing_enabled", False):
                        staged_path = staging_dir / file_path.name
                        shutil.move(str(file_path), str(staged_path))
                        
                        event = parser.parse_file(staged_path)
                        event["local_routing_path"] = str(staged_path)
                        
                        parser.messaging.connect()
                        parser.messaging.publish_new_email(event)
                        parser.messaging.close()
                        
                        logger.info(
                            "Parsed and published (local routing mode)",
                            source_file=str(staged_path),
                            analysis_id=event["analysis_id"],
                        )
                    else:
                        event = parser.parse_and_publish(file_path)
                        logger.info(
                            "Parsed and published",
                            source_file=str(file_path),
                            analysis_id=event["analysis_id"],
                        )
                        shutil.move(str(file_path), str(processed_dir / file_path.name))
                except Exception as exc:
                    logger.exception("Failed to parse email", file=str(file_path), error=str(exc))
                    shutil.move(str(file_path), str(failed_dir / file_path.name))

        if is_running:
            time.sleep(max(1, settings.parser_poll_seconds))
    
    # Ensure messaging client is closed
    try:
        parser.messaging.shutdown()
    except Exception:
        pass
    logger.info("Parser worker stopped")


if __name__ == "__main__":
    run()
