"""Telegram bot alerts (plain text, phone-sized, with an 'Open report' button)."""

from __future__ import annotations

from typing import Any

import httpx
from pydantic import Field, SecretStr

from tripwire.alerts.base import AlertChannel, AlertError, AlertMessage
from tripwire.core.plugin import PluginOptions

API_BASE = "https://api.telegram.org"


class TelegramOptions(PluginOptions):
    bot_token: SecretStr = Field(description="Use ${TRIPWIRE_TELEGRAM_TOKEN}; never inline it")
    chat_id: str
    api_base: str = API_BASE
    silent: bool = False


class TelegramChannel(AlertChannel[TelegramOptions]):
    Options = TelegramOptions

    def __init__(self, *args: object, **kwargs: object) -> None:
        super().__init__(*args, **kwargs)  # type: ignore[arg-type]
        self._client: httpx.AsyncClient | None = None

    def build_payload(self, message: AlertMessage) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "chat_id": self.options.chat_id,
            "text": message.text[:4096],
            "disable_web_page_preview": True,
            "disable_notification": self.options.silent,
        }
        # Telegram only accepts public http(s) URLs for buttons.
        if message.report_url and message.report_url.startswith("https://"):
            payload["reply_markup"] = {
                "inline_keyboard": [[{"text": "Open report", "url": message.report_url}]]
            }
        return payload

    async def send(self, message: AlertMessage) -> None:
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=15)
        token = self.options.bot_token.get_secret_value()
        url = f"{self.options.api_base}/bot{token}/sendMessage"
        try:
            resp = await self._client.post(url, json=self.build_payload(message))
        except httpx.HTTPError as exc:
            # Never include the URL (it contains the bot token) in the error.
            raise AlertError(f"telegram request failed: {type(exc).__name__}") from None
        if resp.status_code != 200 or not resp.json().get("ok", False):
            raise AlertError(f"telegram API error {resp.status_code}: {resp.text[:200]}")

    async def close(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None


def _api_error(resp: httpx.Response, token: str) -> str:
    """Extract Telegram's error description, never echoing the token."""
    try:
        description = str(resp.json().get("description", ""))
    except ValueError:
        description = resp.text[:200]
    return description.replace(token, "<redacted>") or f"HTTP {resp.status_code}"


def verify_telegram(
    token: str,
    chat_id: str,
    *,
    api_base: str = API_BASE,
    client: httpx.Client | None = None,
) -> str:
    """Check the bot token (``getMe``) and chat ID (a test ``sendMessage``).

    Returns the bot's @username. Raises :class:`AlertError` with a message that
    never contains the token or the request URL.
    """
    own = client is None
    http = client or httpx.Client(timeout=15)
    base = f"{api_base}/bot{token}"
    try:
        try:
            me = http.get(f"{base}/getMe")
        except httpx.HTTPError as exc:
            raise AlertError(f"cannot reach Telegram: {type(exc).__name__}") from None
        if me.status_code != 200 or not me.json().get("ok", False):
            raise AlertError(f"bot token rejected by Telegram: {_api_error(me, token)}")
        username = str(me.json().get("result", {}).get("username", "?"))
        try:
            sent = http.post(
                f"{base}/sendMessage",
                json={
                    "chat_id": chat_id,
                    "text": "✅ Tripwire is connected. Alerts will arrive in this chat.",
                },
            )
        except httpx.HTTPError as exc:
            raise AlertError(f"cannot reach Telegram: {type(exc).__name__}") from None
        if sent.status_code != 200 or not sent.json().get("ok", False):
            raise AlertError(
                f"cannot send to chat {chat_id}: {_api_error(sent, token)} "
                f"(open a chat with @{username} and press Start first)"
            )
        return username
    finally:
        if own:
            http.close()
