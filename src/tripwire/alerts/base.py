"""Alert channel interface and the mobile-friendly message formatter."""

from __future__ import annotations

import abc
import ipaddress
from dataclasses import dataclass
from typing import Any, TypeVar
from urllib.parse import urlsplit

from tripwire.core.events import Incident, Severity
from tripwire.core.plugin import Plugin, PluginOptions

OptionsT = TypeVar("OptionsT", bound=PluginOptions)

_SEVERITY_ICON = {
    Severity.LOW: "🔵",
    Severity.MEDIUM: "🟡",
    Severity.HIGH: "🟠",
    Severity.CRITICAL: "🔴",
}

MAX_SUMMARY_CHARS = 160
MAX_LINES = 15
MAX_LIST_ITEMS = 3


def _phone_openable(url: str) -> bool:
    """A loopback report link is useless on a phone, so don't waste a line on it."""
    host = urlsplit(url).hostname or ""
    if host == "localhost":
        return False
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        return True
    return not (addr.is_loopback or addr.is_unspecified)


def _context_lines(ctx: dict[str, Any]) -> list[str]:
    """Render the 'who touched it' snapshot from :mod:`tripwire.core.context`."""
    lines = [f"User: {ctx.get('local_user', 'unknown')}"]

    procs = ctx.get("processes")
    if isinstance(procs, list) and procs:
        shown = ", ".join(
            f"{p.get('name', '?')} (PID {p.get('pid', '?')}, {p.get('user', '?')})"
            for p in procs[:2]
        )
        lines.append(f"Process: {shown}")
    elif isinstance(procs, list):
        lines.append("Process: unknown (file already closed)")
    else:
        lines.append("Process: unknown (no permission)")

    sessions = ctx.get("sessions")
    if isinstance(sessions, list):
        remote = [s for s in sessions if s.get("host")]
        local = len(sessions) - len(remote)
        extra = f", {local} local" if local else ""
        if remote:
            lines.append(f"Remote sessions ({len(remote)}{extra}):")
            lines += [
                f"  {s.get('user', '?')} from {s['host']} {s.get('terminal', '')}".rstrip()
                for s in remote[:MAX_LIST_ITEMS]
            ]
        else:
            lines.append(f"Remote sessions: none{extra}")
    else:
        lines.append("Remote sessions: unavailable")

    conns = ctx.get("connections")
    if isinstance(conns, list) and conns:
        lines.append("Outbound:")
        for c in conns[:MAX_LIST_ITEMS]:
            who = c.get("process", "?")
            if c.get("pid") is not None:
                who += f" ({c['pid']})"
            lines.append(f"  {c.get('ip', '?')}:{c.get('port', '?')} {who}")
    elif isinstance(conns, list):
        lines.append("Outbound: none")
    else:
        lines.append("Outbound: unavailable")
    return lines


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
        ctx = ev.details.get("context")
        if isinstance(ctx, dict):
            lines += _context_lines(ctx)
        # Title takes one line of the phone-sized budget; the last line is the link/id.
        lines = lines[: MAX_LINES - 2]
        if self.report_url and _phone_openable(self.report_url):
            lines.append(f"Report: {self.report_url}")
        else:
            lines.append(f"Incident: {self.incident.id[:12]}")
        return "\n".join(lines)

    @property
    def text(self) -> str:
        return f"{self.title}\n{self.body}"


class AlertError(Exception):
    """Raised by a channel when delivery fails."""


class AlertChannel(Plugin[OptionsT], abc.ABC):
    @abc.abstractmethod
    async def send(self, message: AlertMessage) -> None:
        """Deliver the alert. Raise :class:`AlertError` on failure."""

    async def close(self) -> None:
        """Release resources."""


AnyAlertChannel = AlertChannel[Any]
