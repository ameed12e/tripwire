"""E-mail alerts via SMTP (stdlib ``smtplib``, run in a worker thread)."""

from __future__ import annotations

import asyncio
import smtplib
import ssl
from email.message import EmailMessage
from typing import Literal

from pydantic import Field, SecretStr

from tripwire.alerts.base import AlertChannel, AlertError, AlertMessage
from tripwire.core.plugin import PluginOptions


class EmailOptions(PluginOptions):
    smtp_host: str
    smtp_port: int = Field(default=587, ge=1, le=65535)
    security: Literal["starttls", "ssl", "none"] = "starttls"
    username: str | None = None
    password: SecretStr | None = None
    sender: str
    recipients: list[str] = Field(min_length=1)
    timeout_seconds: float = 15


class EmailChannel(AlertChannel[EmailOptions]):
    Options = EmailOptions

    def build_message(self, message: AlertMessage) -> EmailMessage:
        msg = EmailMessage()
        msg["Subject"] = message.title
        msg["From"] = self.options.sender
        msg["To"] = ", ".join(self.options.recipients)
        msg.set_content(message.body + "\n\n-- \nTripwire\n")
        return msg

    def _send_sync(self, msg: EmailMessage) -> None:
        o = self.options
        context = ssl.create_default_context()
        smtp: smtplib.SMTP
        if o.security == "ssl":
            smtp = smtplib.SMTP_SSL(o.smtp_host, o.smtp_port, timeout=o.timeout_seconds, context=context)
        else:
            smtp = smtplib.SMTP(o.smtp_host, o.smtp_port, timeout=o.timeout_seconds)
        with smtp:
            if o.security == "starttls":
                smtp.starttls(context=context)
            if o.username and o.password:
                smtp.login(o.username, o.password.get_secret_value())
            smtp.send_message(msg)

    async def send(self, message: AlertMessage) -> None:
        try:
            await asyncio.to_thread(self._send_sync, self.build_message(message))
        except (smtplib.SMTPException, OSError) as exc:
            raise AlertError(f"smtp delivery failed: {exc}") from exc
