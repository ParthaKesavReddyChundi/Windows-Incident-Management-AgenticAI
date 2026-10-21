"""
Logging configuration for the application.

Call `setup_logging()` once at startup. All modules should use:
    import logging
    logger = logging.getLogger(__name__)
"""
from __future__ import annotations

import logging
import logging.handlers
from pathlib import Path


def setup_logging(log_level: str = "INFO", logs_dir: Path | None = None) -> None:
    """Configure root logger with console and rotating file handlers."""

    numeric_level = getattr(logging, log_level.upper(), logging.INFO)

    fmt = logging.Formatter(
        fmt="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )

    root = logging.getLogger()
    root.setLevel(numeric_level)

    # Console handler
    console = logging.StreamHandler()
    console.setLevel(numeric_level)
    console.setFormatter(fmt)
    root.addHandler(console)

    # Rotating file handler (if logs_dir is provided)
    if logs_dir is not None:
        logs_dir.mkdir(parents=True, exist_ok=True)
        file_handler = logging.handlers.RotatingFileHandler(
            filename=logs_dir / "app.log",
            maxBytes=10 * 1024 * 1024,  # 10 MB
            backupCount=5,
            encoding="utf-8",
        )
        file_handler.setLevel(numeric_level)
        file_handler.setFormatter(fmt)
        root.addHandler(file_handler)

        # Separate audit log — append-only, never truncated
        audit_handler = logging.FileHandler(
            filename=logs_dir / "audit.log",
            mode="a",
            encoding="utf-8",
        )
        audit_handler.setLevel(logging.INFO)
        audit_handler.setFormatter(fmt)
        audit_logger = logging.getLogger("audit")
        audit_logger.addHandler(audit_handler)
        audit_logger.propagate = False

    # Suppress noisy third-party loggers
    for noisy in ("uvicorn.access", "httpx", "httpcore"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
