from __future__ import annotations

import asyncio
import logging

import httpx
import pytest
import respx

from tripwire.core.logging import RedactingFilter, configure_logging, redact

TOKEN = "123456789:AAFakeTokenValue_for-tests"
URL = f"https://api.telegram.org/bot{TOKEN}/sendMessage"


def test_redact() -> None:
    assert TOKEN not in redact(f"POST {URL} 200")
    assert "/bot<redacted>/sendMessage" in redact(URL)
    assert redact("nothing secret here") == "nothing secret here"


@pytest.mark.parametrize("level", ["DEBUG", "INFO"])
def test_http_client_loggers_are_quiet(level: str) -> None:
    configure_logging(level)
    for name in ("httpx", "httpcore"):
        assert logging.getLogger(name).getEffectiveLevel() >= logging.WARNING


@respx.mock
def test_telegram_request_does_not_log_token(caplog: pytest.LogCaptureFixture) -> None:
    configure_logging("DEBUG")
    respx.post(URL).mock(return_value=httpx.Response(200, json={"ok": True}))
    caplog.set_level(logging.DEBUG)  # even if someone forces DEBUG on everything

    async def go() -> None:
        async with httpx.AsyncClient() as client:
            await client.post(URL, json={})

    logging.getLogger("httpx").setLevel(logging.WARNING)
    asyncio.run(go())
    assert TOKEN not in caplog.text


def test_filter_scrubs_records() -> None:
    record = logging.LogRecord("httpx", logging.INFO, __file__, 1, "HTTP Request: %s", (URL,), None)
    RedactingFilter().filter(record)
    assert TOKEN not in record.getMessage()
