from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import smtplib
from typing import Any

import httpx
import pytest
import respx

from tripwire.alerts.base import AlertError, AlertMessage
from tripwire.alerts.email import EmailChannel, EmailOptions
from tripwire.alerts.telegram import TelegramChannel, TelegramOptions
from tripwire.alerts.webhook import WebhookChannel, WebhookOptions
from tripwire.core.config import TripwireConfig
from tripwire.core.events import Event, EventKind, Incident, Severity
from tripwire.core.plugin import PluginContext

REPORT = "https://tw.example.test/r/abc?exp=1&sig=x"


def _msg(summary: str = "Decoy accessed: passwords.txt", url: str | None = REPORT) -> AlertMessage:
    ev = Event(
        kind=EventKind.FILE_ACCESSED,
        source="fs",
        summary=summary,
        severity=Severity.HIGH,
        host="laptop",
        details={"secret_detail": "only-in-full-report"},
    )
    return AlertMessage(incident=Incident(event=ev), report_url=url)


def test_message_is_short_and_mobile_friendly() -> None:
    m = _msg("x" * 1000)
    assert m.title.startswith("🟠 Tripwire: file accessed")
    assert len(m.text) < 400
    assert "only-in-full-report" not in m.text
    assert "Report: " + REPORT in m.body
    assert "Incident:" in _msg(url=None).body


# ------------------------------------------------------------------ telegram
def _telegram(config: TripwireConfig) -> TelegramChannel:
    opts = TelegramOptions(bot_token="123:SECRET", chat_id="42")  # type: ignore[arg-type]
    return TelegramChannel("tg", opts, PluginContext(config))


@respx.mock
def test_telegram_send(config: TripwireConfig) -> None:
    route = respx.post("https://api.telegram.org/bot123:SECRET/sendMessage").mock(
        return_value=httpx.Response(200, json={"ok": True})
    )
    ch = _telegram(config)
    asyncio.run(ch.send(_msg()))
    body = json.loads(route.calls[0].request.content)
    assert body["chat_id"] == "42"
    assert body["reply_markup"]["inline_keyboard"][0][0]["url"] == REPORT
    asyncio.run(ch.close())


def test_telegram_no_button_for_http(config: TripwireConfig) -> None:
    assert "reply_markup" not in _telegram(config).build_payload(_msg(url="http://127.0.0.1/r/x"))


@respx.mock
def test_telegram_error_hides_token(config: TripwireConfig) -> None:
    respx.post(url__regex=r".*/sendMessage").mock(side_effect=httpx.ConnectError("down"))
    with pytest.raises(AlertError) as exc:
        asyncio.run(_telegram(config).send(_msg()))
    assert "SECRET" not in str(exc.value)


@respx.mock
def test_telegram_api_error(config: TripwireConfig) -> None:
    respx.post(url__regex=r".*/sendMessage").mock(
        return_value=httpx.Response(400, json={"ok": False, "description": "chat not found"})
    )
    with pytest.raises(AlertError, match="400"):
        asyncio.run(_telegram(config).send(_msg()))


# ------------------------------------------------------------------- webhook
@respx.mock
def test_webhook_signed(config: TripwireConfig) -> None:
    route = respx.post("https://hooks.example.test/x").mock(return_value=httpx.Response(204))
    opts = WebhookOptions(url="https://hooks.example.test/x", secret="s3cret", headers={"X-A": "1"})  # type: ignore[arg-type]
    asyncio.run(WebhookChannel("wh", opts, PluginContext(config)).send(_msg()))
    req = route.calls[0].request
    expected = hmac.new(b"s3cret", req.content, hashlib.sha256).hexdigest()
    assert req.headers["X-Tripwire-Signature"] == f"sha256={expected}"
    assert req.headers["X-A"] == "1"
    body = json.loads(req.content)
    assert body["kind"] == "file_accessed" and body["report_url"] == REPORT
    assert "report" not in body


@respx.mock
def test_webhook_full_report_and_failure(config: TripwireConfig) -> None:
    route = respx.post("https://hooks.example.test/x").mock(return_value=httpx.Response(500))
    opts = WebhookOptions(url="https://hooks.example.test/x", include_report=True)  # type: ignore[arg-type]
    with pytest.raises(AlertError, match="500"):
        asyncio.run(WebhookChannel("wh", opts, PluginContext(config)).send(_msg()))
    body = json.loads(route.calls[0].request.content)
    assert body["report"]["event"]["details"]["secret_detail"] == "only-in-full-report"


# --------------------------------------------------------------------- email
class FakeSMTP:
    instances: list[FakeSMTP] = []

    def __init__(self, host: str, port: int, timeout: float = 0, **_: Any) -> None:
        self.host, self.port = host, port
        self.calls: list[str] = []
        self.sent: list[Any] = []
        FakeSMTP.instances.append(self)

    def __enter__(self) -> FakeSMTP:
        return self

    def __exit__(self, *a: object) -> None:
        self.calls.append("quit")

    def starttls(self, context: Any = None) -> None:
        self.calls.append("starttls")

    def login(self, user: str, pw: str) -> None:
        self.calls.append(f"login:{user}:{pw}")

    def send_message(self, msg: Any) -> None:
        self.sent.append(msg)


def test_email_send(config: TripwireConfig, monkeypatch: pytest.MonkeyPatch) -> None:
    FakeSMTP.instances.clear()
    monkeypatch.setattr(smtplib, "SMTP", FakeSMTP)
    opts = EmailOptions(
        smtp_host="smtp.example.test",
        username="u",
        password="p",  # type: ignore[arg-type]
        sender="tw@example.test",
        recipients=["me@example.test"],
    )
    asyncio.run(EmailChannel("mail", opts, PluginContext(config)).send(_msg()))
    [smtp] = FakeSMTP.instances
    assert smtp.calls[:2] == ["starttls", "login:u:p"]
    [msg] = smtp.sent
    assert msg["To"] == "me@example.test"
    assert "Tripwire" in msg["Subject"]
    assert REPORT in msg.get_content()


def test_email_failure(config: TripwireConfig, monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*a: object, **k: object) -> None:
        raise ConnectionRefusedError("nope")

    monkeypatch.setattr(smtplib, "SMTP", boom)
    opts = EmailOptions(smtp_host="h", sender="a@b.c", recipients=["d@e.f"])
    with pytest.raises(AlertError, match="smtp"):
        asyncio.run(EmailChannel("mail", opts, PluginContext(config)).send(_msg()))
