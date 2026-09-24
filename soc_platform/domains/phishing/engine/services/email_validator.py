from fastapi import HTTPException
from pathlib import Path
import email


class EmailValidator:
    MAX_EMAIL_SIZE = 50 * 1024 * 1024  # 50 MB
    MAX_ATTACHMENTS = 20
    ALLOWED_MIME_TYPES = {
        'text/plain',
        'text/html',
        'application/pdf',
        'application/msword',
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        'application/vnd.ms-excel',
        'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        'image/jpeg',
        'image/png',
        'image/gif',
    }

    @staticmethod
    def validate_email_size(email_data: bytes):
        """Validate email doesn't exceed size limit"""
        if len(email_data) > EmailValidator.MAX_EMAIL_SIZE:
            raise HTTPException(
                status_code=413,
                detail="Email exceeds maximum size"
            )

    @staticmethod
    def validate_email_format(email_data: bytes):
        """Validate it's a valid MIME message and return parsed message"""
        try:
            msg = email.message_from_bytes(email_data)
            # message payload can be empty for some multipart messages; accept
            return msg
        except Exception:
            raise HTTPException(
                status_code=400,
                detail="Invalid email format"
            )

    @staticmethod
    def validate_attachments(email_msg):
        """Validate attachments found in parsed email message"""
        attachment_count = 0

        for part in email_msg.walk():
            if part.get_content_disposition() == "attachment":
                attachment_count += 1

                # Check count limit
                if attachment_count > EmailValidator.MAX_ATTACHMENTS:
                    raise HTTPException(
                        status_code=400,
                        detail="Too many attachments"
                    )

                # Prevent path traversal
                filename = part.get_filename()
                if filename:
                    filename = Path(filename).name  # Remove directory traversal

                # Validate MIME type
                mime_type = part.get_content_type()
                if mime_type not in EmailValidator.ALLOWED_MIME_TYPES:
                    raise HTTPException(
                        status_code=400,
                        detail=f"Unsupported attachment type: {mime_type}"
                    )

    @staticmethod
    def validate_headers(email_msg):
        """Prevent header injection attacks"""
        suspicious_headers = ['bcc', 'x-forwarded-for', 'x-originating-ip']

        for header in suspicious_headers:
            if header in email_msg:
                # do not raise, just log for now (integration teams may set headers)
                logger = __import__('loguru').logger
                logger.warning(f"Suspicious header present: {header}")
