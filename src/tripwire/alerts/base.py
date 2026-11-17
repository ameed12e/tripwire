"""Alert channel interface and the mobile-friendly message formatter."""

from __future__ import annotations

import abc
from dataclasses import dataclass
from typing import TypeVar

from tripwire.core.events import Incident, Severity
from tripwire.core.plugin import Plugin, PluginOptions

O = TypeVar("O", bound=PluginOptions)

_SEVERITY_ICON = {
    Severity.LOW: "🔵",
    Severity.MEDIUM: "🟡",
    Severity.HIGH: "🟠",
    Severity.CRITICAL: "🔴",
}

MAX_SUMMARY_CHARS = 160


@dataclass(frozen=True)
class AlertMessage:
    """What every channel receives. ``title``/``body`` are short, phone-sized text."""

    incident: Incident
    report_url: str | None

    @property
    def title(self) -> str:
        ev = self.incident.event
        icon = _SEVERITY_ICON.get(ev.severity, "⚠️")
        return f"{icon} Tripwire: {ev.kind.value.replace('_', ' ')}"

    @property
    def body(self) -> str:
        ev = self.incident.event
        summary = ev.summary
        if len(summary) > MAX_SUMMARY_CHARS:
            summary = summary[: MAX_SUMMARY_CHARS - 1] + "…"
        lines = [
            summary,
            f"Host: {ev.host or 'unknown'}",
            f"When: {ev.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}",
        ]
        if self.report_url:
            lines.append(f"Report: {self.report_url}")
        else:
            lines.append(f"Incident: {self.incident.id}")
        return "\n".join(lines)

    @property
    def text(self) -> str:
        return f"{self.title}\n{self.body}"


class AlertError(Exception):
    """Raised by a channel when delivery fails."""


class AlertChannel(Plugin[O], abc.ABC):
    @abc.abstractmethod
    async def send(self, message: AlertMessage) -> None:
        """Deliver the alert. Raise :class:`AlertError` on failure."""

    async def close(self) -> None:  # noqa: B027 - optional hook
        """Release resources."""
