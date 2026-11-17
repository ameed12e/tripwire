"""Generic JSON webhook (ntfy, Slack-compatible relays, Home Assistant, your own API...).

Payload::

    {"title": "...", "text": "...", "report_url": "...", "incident_id": "...",
     "kind": "file_accessed", "severity": "high", "host": "...", "timestamp": "..."}

With ``include_report: true`` the full incident report is added under
``"report"``. If ``secret`` is set, the body is signed with HMAC-SHA256 in the
``X-Tripwire-Signature: sha256=<hex>`` header.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any

import httpx
from pydantic import Field, HttpUrl, SecretStr

from tripwire.alerts.base import AlertChannel, AlertError, AlertMessage
from tripwire.core.plugin import PluginOptions


class WebhookOptions(PluginOptions):
    url: HttpUrl
    headers: dict[str, str] = Field(default_factory=dict)
    secret: SecretStr | None = None
    include_report: bool = False


class WebhookChannel(AlertChannel[WebhookOptions]):
    Options = WebhookOptions

    def __init__(self, *args: object, **kwargs: object) -> None:
        super().__init__(*args, **kwargs)  # type: ignore[arg-type]
        self._client: httpx.AsyncClient | None = None

    def build_payload(self, message: AlertMessage) -> dict[str, Any]:
        ev = message.incident.event
        payload: dict[str, Any] = {
            "title": message.title,
            "text": message.body,
            "report_url": message.report_url,
            "incident_id": message.incident.id,
            "kind": ev.kind.value,
            "severity": ev.severity.value,
            "host": ev.host,
            "timestamp": ev.timestamp.isoformat(),
        }
        if self.options.include_report:
            payload["report"] = message.incident.report()
        return payload

    async def send(self, message: AlertMessage) -> None:
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=15)
        body = json.dumps(self.build_payload(message), separators=(",", ":")).encode()
        headers = {"Content-Type": "application/json", **self.options.headers}
        if self.options.secret is not None:
            sig = hmac.new(
                self.options.secret.get_secret_value().encode(), body, hashlib.sha256
            ).hexdigest()
            headers["X-Tripwire-Signature"] = f"sha256={sig}"
        try:
            resp = await self._client.post(str(self.options.url), content=body, headers=headers)
        except httpx.HTTPError as exc:
            raise AlertError(f"webhook request failed: {type(exc).__name__}") from None
        if resp.status_code >= 300:
            raise AlertError(f"webhook returned HTTP {resp.status_code}")

    async def close(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None
