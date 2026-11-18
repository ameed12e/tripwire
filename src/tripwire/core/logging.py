"""Structured logging setup based on structlog."""

from __future__ import annotations

import logging
import re
import sys

import structlog

# HTTP client libraries log full request URLs at INFO/DEBUG. Some APIs (Telegram)
# carry credentials in the URL path, so these loggers are never allowed below WARNING.
_QUIET_LOGGERS = ("httpx", "httpcore", "hpack")
_SECRET_PATTERNS = (
    re.compile(r"(/bot)\d+:[A-Za-z0-9_-]+"),  # Telegram bot tokens in API URLs
)


def redact(text: str) -> str:
    for pattern in _SECRET_PATTERNS:
        text = pattern.sub(r"\1<redacted>", text)
    return text


class RedactingFilter(logging.Filter):
    """Defense in depth: scrub known secret patterns from stdlib log records."""

    def filter(self, record: logging.LogRecord) -> bool:
        message = record.getMessage()
        cleaned = redact(message)
        if cleaned != message:
            record.msg, record.args = cleaned, None
        return True


def _redact_processor(
    _logger: object, _name: str, event_dict: structlog.typing.EventDict
) -> structlog.typing.EventDict:
    for key, value in event_dict.items():
        if isinstance(value, str):
            event_dict[key] = redact(value)
    return event_dict


class _StderrProxy:
    """Resolve ``sys.stderr`` at write time (it may be swapped, e.g. by test runners)."""

    def write(self, data: str) -> int:
        return sys.stderr.write(data)

    def flush(self) -> None:
        sys.stderr.flush()


def configure_logging(level: str = "INFO", json_output: bool = False) -> None:
    """Configure structlog (and stdlib logging) once for the whole process."""
    log_level = getattr(logging, level.upper(), logging.INFO)
    logging.basicConfig(format="%(message)s", stream=sys.stderr, level=log_level)
    for name in _QUIET_LOGGERS:
        logging.getLogger(name).setLevel(max(log_level, logging.WARNING))
    for handler in logging.getLogger().handlers:
        if not any(isinstance(f, RedactingFilter) for f in handler.filters):
            handler.addFilter(RedactingFilter())

    processors: list[structlog.typing.Processor] = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        _redact_processor,
    ]
    renderer: structlog.typing.Processor = (
        structlog.processors.JSONRenderer()
        if json_output
        else structlog.dev.ConsoleRenderer(colors=sys.stderr.isatty())
    )
    structlog.configure(
        processors=[*processors, renderer],
        wrapper_class=structlog.make_filtering_bound_logger(log_level),
        logger_factory=structlog.PrintLoggerFactory(file=_StderrProxy()),  # type: ignore[arg-type]
        cache_logger_on_first_use=False,
    )


def get_logger(name: str | None = None) -> structlog.typing.FilteringBoundLogger:
    logger: structlog.typing.FilteringBoundLogger = structlog.get_logger(name)
    return logger
