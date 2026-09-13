"""Structured JSON logging in Elastic Common Schema (ECS) format.

We emit ECS-shaped JSON directly from the application rather than writing
plain text and reconstructing fields in Logstash. Parsing a line you already
control is wasted work, and grok on free-form text is the single most common
source of pipeline breakage when a log format drifts.

The unparsed-text path still exists on purpose: the nginx sidecar writes a
classic combined access log, which Logstash *does* grok. That gives the
platform one of each, which is what a real estate looks like.
"""

import json
import logging
import os
import socket
import sys
import time
import uuid
from contextvars import ContextVar

# Correlation id for the in-flight request, so every log line emitted while
# handling a request can be tied back to it (and to the nginx access log entry).
trace_id_var: ContextVar[str] = ContextVar("trace_id", default="-")

SERVICE_NAME = os.getenv("SERVICE_NAME", "payments-api")
SERVICE_VERSION = os.getenv("SERVICE_VERSION", "1.4.2")
SERVICE_ENV = os.getenv("SERVICE_ENV", "production")

# ECS reserves a set of top-level keys. Anything we invent goes under
# `labels.*` so we never collide with a future ECS field name.
_RESERVED = {"message", "log", "ecs", "service", "host", "event", "trace"}


class EcsJsonFormatter(logging.Formatter):
    """Render a LogRecord as a single line of ECS JSON."""

    def __init__(self) -> None:
        super().__init__()
        self.hostname = socket.gethostname()

    def format(self, record: logging.LogRecord) -> str:
        doc = {
            "@timestamp": time.strftime(
                "%Y-%m-%dT%H:%M:%S", time.gmtime(record.created)
            )
            + f".{int(record.msecs):03d}Z",
            "message": record.getMessage(),
            "log": {
                "level": record.levelname.lower(),
                "logger": record.name,
                "origin": {
                    "file": {"name": record.filename, "line": record.lineno},
                    "function": record.funcName,
                },
            },
            "ecs": {"version": "8.11.0"},
            "service": {
                "name": SERVICE_NAME,
                "version": SERVICE_VERSION,
                "environment": SERVICE_ENV,
            },
            "host": {"hostname": self.hostname},
            "process": {"pid": record.process},
        }

        trace_id = trace_id_var.get()
        if trace_id != "-":
            doc["trace"] = {"id": trace_id}

        # Structured fields passed as logger.info("msg", extra={"ecs": {...}})
        # are merged in, deeply, so callers can set event.action, user.name,
        # source.ip and friends without knowing anything about this formatter.
        extra = getattr(record, "ecs", None)
        if isinstance(extra, dict):
            _deep_merge(doc, extra)

        if record.exc_info:
            exc_type, exc_value, _ = record.exc_info
            doc["error"] = {
                "type": exc_type.__name__ if exc_type else "UnknownError",
                "message": str(exc_value),
                "stack_trace": self.formatException(record.exc_info),
            }

        return json.dumps(doc, separators=(",", ":"), default=str)


def _deep_merge(base: dict, overlay: dict) -> dict:
    """Merge overlay into base in place, recursing into nested dicts."""
    for key, value in overlay.items():
        if isinstance(value, dict) and isinstance(base.get(key), dict):
            _deep_merge(base[key], value)
        else:
            base[key] = value
    return base


def configure_logging() -> logging.Logger:
    """Install the ECS formatter on stdout and return the app logger.

    Container logs go to stdout and nowhere else. The collector owns the
    file-on-disk problem (rotation, retention, shipping); the app does not.
    """
    level = os.getenv("LOG_LEVEL", "INFO").upper()

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(EcsJsonFormatter())

    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(level)

    # Werkzeug's own request log is noisy and redundant: nginx already records
    # every request in the access log, in a format we parse.
    logging.getLogger("werkzeug").setLevel(logging.ERROR)

    return logging.getLogger(SERVICE_NAME)


def new_trace_id() -> str:
    return uuid.uuid4().hex[:16]
