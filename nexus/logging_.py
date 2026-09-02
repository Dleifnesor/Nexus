"""Structured logging and audit trail for Nexus.

Two channels:
- application log (human + structured JSON lines) for debugging.
- audit log (append-only JSON lines) for security-relevant actions: every install,
  intrusive action, scope decision, and mode change is recorded here.
"""
from __future__ import annotations

import json
import logging
import sys
import time
from pathlib import Path
from typing import Any

_AUDIT_LOGGER_NAME = "nexus.audit"
_APP_LOGGER_NAME = "nexus"


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": time.time(),
            "time": self.formatTime(record, "%Y-%m-%dT%H:%M:%S"),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        extra = getattr(record, "extra_fields", None)
        if extra:
            payload.update(extra)
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


def setup_logging(log_dir: Path | None = None, level: int = logging.INFO) -> None:
    """Configure application + audit loggers. Idempotent."""
    app = logging.getLogger(_APP_LOGGER_NAME)
    if getattr(app, "_nexus_configured", False):
        return
    app.setLevel(level)
    app.propagate = False

    console = logging.StreamHandler(sys.stderr)
    console.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    app.addHandler(console)

    if log_dir is not None:
        log_dir.mkdir(parents=True, exist_ok=True)
        app_file = logging.FileHandler(log_dir / "nexus.log.jsonl", encoding="utf-8")
        app_file.setFormatter(JsonFormatter())
        app.addHandler(app_file)

        audit = logging.getLogger(_AUDIT_LOGGER_NAME)
        audit.setLevel(logging.INFO)
        audit.propagate = False
        audit_file = logging.FileHandler(log_dir / "audit.log.jsonl", encoding="utf-8")
        audit_file.setFormatter(JsonFormatter())
        audit.addHandler(audit_file)

    app._nexus_configured = True  # type: ignore[attr-defined]


def get_logger(name: str = _APP_LOGGER_NAME) -> logging.Logger:
    return logging.getLogger(name)


def log_event(logger: logging.Logger, level: int, msg: str, **fields: Any) -> None:
    logger.log(level, msg, extra={"extra_fields": fields})


def audit(msg: str, **fields: Any) -> None:
    """Record a security-relevant event to the append-only audit log."""
    logger = logging.getLogger(_AUDIT_LOGGER_NAME)
    logger.info(msg, extra={"extra_fields": fields})
