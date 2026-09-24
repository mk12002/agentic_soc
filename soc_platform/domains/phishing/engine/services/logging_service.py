"""
Centralized logging framework for the Agentic Email Security System.

Uses Loguru for structured JSON logging with file rotation, console output,
and agent-specific context binding.
"""

import sys
from pathlib import Path
from typing import Optional

from loguru import logger


def setup_logging(
    log_dir: str = "logs",
    log_level: str = "INFO",
    log_format: str = "json",
    rotation: str = "10 MB",
    retention: str = "30 days",
) -> None:
    """
    Initialize the centralized logging system.

    Args:
        log_dir: Directory for log file output.
        log_level: Minimum log level (DEBUG, INFO, WARNING, ERROR, CRITICAL).
        log_format: Log format – 'json' for structured or 'text' for human-readable.
        rotation: Log rotation threshold (e.g. '10 MB', '1 day').
        retention: How long to keep old log files (e.g. '30 days').
    """
    # Remove default Loguru handler
    logger.remove()

    log_path = Path(log_dir)
    log_path.mkdir(parents=True, exist_ok=True)

    # --- Console handler (human-readable) ---
    console_format = (
        "<green>{time:YYYY-MM-DD HH:mm:ss.SSS}</green> | "
        "<level>{level: <8}</level> | "
        "<cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> | "
        "<level>{message}</level> | <cyan>{extra}</cyan>"
    )

    logger.add(
        sys.stderr,
        format=console_format,
        level=log_level,
        colorize=True,
        backtrace=True,
        diagnose=True,
    )

    # --- File handler (structured JSON) ---
    if log_format == "json":
        logger.add(
            str(log_path / "app_{time:YYYY-MM-DD}.log"),
            format="{message}",
            level=log_level,
            rotation=rotation,
            retention=retention,
            compression="gz",
            serialize=True,  # JSON structured output
            backtrace=True,
            diagnose=False,
        )
    else:
        logger.add(
            str(log_path / "app_{time:YYYY-MM-DD}.log"),
            format=(
                "{time:YYYY-MM-DD HH:mm:ss.SSS} | {level: <8} | "
                "{name}:{function}:{line} | {message}"
            ),
            level=log_level,
            rotation=rotation,
            retention=retention,
            compression="gz",
            backtrace=True,
            diagnose=True,
        )

    # --- Error-only log file ---
    logger.add(
        str(log_path / "errors_{time:YYYY-MM-DD}.log"),
        format="{message}",
        level="ERROR",
        rotation=rotation,
        retention=retention,
        compression="gz",
        serialize=True,
        backtrace=True,
        diagnose=True,
    )

    logger.info("Logging system initialized", log_dir=str(log_path), level=log_level)


def get_agent_logger(agent_name: str) -> "logger":
    """
    Create a contextualized logger for a specific agent.

    Args:
        agent_name: Name of the agent (e.g. 'header_agent').

    Returns:
        A Loguru logger instance bound with agent context.
    """
    return logger.bind(agent=agent_name)


def get_service_logger(service_name: str) -> "logger":
    """
    Create a contextualized logger for a specific service.

    Args:
        service_name: Name of the service (e.g. 'api', 'orchestrator').

    Returns:
        A Loguru logger instance bound with service context.
    """
    return logger.bind(service=service_name)
