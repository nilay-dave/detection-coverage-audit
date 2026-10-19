"""Structured JSON logging.

Every log line is one JSON object so the audit's own output can be ingested by
the same SIEM it is auditing. A run_id ties every line of a single audit run
together, which matters when the audit is scheduled rather than run by hand.
"""

from __future__ import annotations

import json
import logging
import os
import sys
import uuid
from typing import Any

RUN_ID = os.environ.get("DCA_RUN_ID") or uuid.uuid4().hex[:12]


class JsonFormatter(logging.Formatter):
    """Render a LogRecord as a single-line JSON object."""

    RESERVED = {
        "args", "asctime", "created", "exc_info", "exc_text", "filename",
        "funcName", "levelname", "levelno", "lineno", "module", "msecs",
        "message", "msg", "name", "pathname", "process", "processName",
        "relativeCreated", "stack_info", "thread", "threadName", "taskName",
    }

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S"),
            "level": record.levelname.lower(),
            "logger": record.name,
            "run_id": RUN_ID,
            "message": record.getMessage(),
        }
        for key, value in record.__dict__.items():
            if key not in self.RESERVED and not key.startswith("_"):
                payload[key] = value
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


def configure(level: str | int = "INFO") -> None:
    """Install the JSON formatter on the root logger, once."""
    root = logging.getLogger()
    if any(isinstance(h.formatter, JsonFormatter) for h in root.handlers):
        return
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(JsonFormatter())
    root.handlers = [handler]
    root.setLevel(level)


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)
