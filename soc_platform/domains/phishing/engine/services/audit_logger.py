from loguru import logger
from datetime import datetime, timezone
import json


class AuditLogger:
    @staticmethod
    def log_api_call(
        endpoint: str,
        client_ip: str,
        status_code: int,
        request_size: int,
        response_time_ms: float,
        user_agent: str,
    ):
        logger.bind(event="api_call").info(
            json.dumps({
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "endpoint": endpoint,
                "client_ip": client_ip,
                "status_code": status_code,
                "request_size": request_size,
                "response_time_ms": response_time_ms,
                "user_agent": user_agent,
            })
        )

    @staticmethod
    def log_validation_error(client_ip: str, error_type: str, error_detail: str):
        logger.bind(event="validation_error").warning(
            json.dumps({
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "client_ip": client_ip,
                "error_type": error_type,
                "error_detail": error_detail,
            })
        )

    @staticmethod
    def log_rate_limit_exceeded(client_ip: str):
        logger.bind(event="rate_limit_exceeded").warning(
            json.dumps({
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "client_ip": client_ip,
            })
        )

    @staticmethod
    def log_malicious_input(client_ip: str, issue: str, input_type: str):
        logger.bind(event="malicious_input").warning(
            json.dumps({
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "client_ip": client_ip,
                "issue": issue,
                "input_type": input_type,
            })
        )
