"""
Google Drive Integration Client.

Handles interaction with Google Drive API for email ingestion,
downloading, and moving files between folders (Ingestion, Staging, Approved, etc.)
"""
import io
import os
from pathlib import Path
from typing import Any, ClassVar

from google.oauth2 import service_account
from googleapiclient.discovery import build
from googleapiclient.http import MediaFileUpload, MediaIoBaseDownload

from soc_platform.domains.phishing.engine.configs.settings import settings
from soc_platform.domains.phishing.engine.services.logging_service import get_service_logger

logger = get_service_logger("gdrive_client")


class GDriveClient:
    SCOPES: ClassVar[list[str]] = ['https://www.googleapis.com/auth/drive']

    def __init__(self):
        self.credentials_path = getattr(settings, "gdrive_credentials_path", "/app/email_security/gdrive_credentials.json")
        self.ingestion_folder_id = getattr(settings, "gdrive_ingestion_folder_id", None)
        self.staging_folder_id = getattr(settings, "gdrive_staging_folder_id", None)
        self.approved_folder_id = getattr(settings, "gdrive_approved_folder_id", None)
        self.quarantine_folder_id = getattr(settings, "gdrive_quarantine_folder_id", None)
        self.deleted_folder_id = getattr(settings, "gdrive_deleted_folder_id", None)
        
        self.service = self._build_service()

    def _build_service(self):
        """Authenticate and return the Google Drive v3 API service."""
        if not os.path.exists(self.credentials_path):
            logger.warning("GDrive credentials not found", path=self.credentials_path)
            return None

        try:
            creds = service_account.Credentials.from_service_account_file(
                self.credentials_path, scopes=self.SCOPES
            )
            return build('drive', 'v3', credentials=creds, cache_discovery=False)
        except Exception as e:
            logger.error("Failed to build GDrive service", error=str(e))
            return None

    def is_configured(self) -> bool:
        return self.service is not None

    def list_new_emails(self) -> list[dict[str, Any]]:
        """
        List all .eml files in the Ingestion folder.
        """
        if not self.is_configured() or not self.ingestion_folder_id:
            return []

        try:
            query = f"'{self.ingestion_folder_id}' in parents and name contains '.eml' and trashed = false"
            results = self.service.files().list(
                q=query,
                spaces='drive',
                fields='files(id, name, parents)',
                pageSize=50
            ).execute()
            items = results.get('files', [])
            return items
        except Exception as e:
            logger.error("Failed to list GDrive files", error=str(e))
            return []

    def download_file(self, file_id: str, dest_path: str) -> bool:
        """Download a file from GDrive to local disk."""
        if not self.is_configured():
            return False

        try:
            request = self.service.files().get_media(fileId=file_id)
            with io.FileIO(dest_path, 'wb') as fh:
                downloader = MediaIoBaseDownload(fh, request)
                done = False
                while done is False:
                    _status, done = downloader.next_chunk()
            logger.debug("Downloaded GDrive file", file_id=file_id, dest=dest_path)
            return True
        except Exception as e:
            logger.error("Failed to download GDrive file", file_id=file_id, error=str(e))
            return False

    def move_file(self, file_id: str, current_parent_id: str, new_parent_id: str) -> bool:
        """Move a file between GDrive folders."""
        if not self.is_configured() or not new_parent_id:
            return False

        try:
            # Move the file to the new folder
            self.service.files().update(
                fileId=file_id,
                addParents=new_parent_id,
                removeParents=current_parent_id,
                fields='id, parents'
            ).execute()
            logger.info("Moved GDrive file", file_id=file_id, new_parent=new_parent_id)
            return True
        except Exception as e:
            logger.error("Failed to move GDrive file", file_id=file_id, error=str(e))
            return False

    def upload_file(self, file_path: str, folder_id: str) -> str | None:
        """Upload a local file to a specific GDrive folder."""
        if not self.is_configured() or not folder_id:
            return None

        try:
            path = Path(file_path)
            file_metadata = {
                'name': path.name,
                'parents': [folder_id]
            }
            media = MediaFileUpload(str(path), mimetype='message/rfc822', resumable=True)
            file = self.service.files().create(
                body=file_metadata,
                media_body=media,
                fields='id'
            ).execute()
            logger.info("Uploaded to GDrive", local_path=str(path), file_id=file.get('id'), folder_id=folder_id)
            return file.get('id')
        except Exception as e:
            logger.error("Failed to upload to GDrive", path=file_path, error=str(e))
            return None


_GDRIVE_CLIENT: GDriveClient | None = None

def get_gdrive_client() -> GDriveClient:
    global _GDRIVE_CLIENT
    if _GDRIVE_CLIENT is None:
        _GDRIVE_CLIENT = GDriveClient()
    return _GDRIVE_CLIENT
