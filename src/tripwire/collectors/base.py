"""Collector interface.

A collector watches something (files, a USB bus, a log...) and calls ``emit``
with :class:`~tripwire.core.events.Event` objects. ``emit`` is thread-safe, so
collectors built on threaded libraries (like watchdog) can call it directly.
"""

from __future__ import annotations

import abc
from collections.abc import Callable
from typing import TypeVar

from tripwire.core.events import Event
from tripwire.core.plugin import Plugin, PluginOptions

Emit = Callable[[Event], None]

O = TypeVar("O", bound=PluginOptions)


class Collector(Plugin[O], abc.ABC):
    @abc.abstractmethod
    async def run(self, emit: Emit) -> None:
        """Run until cancelled or :meth:`stop` is called. Must not busy-loop."""

    async def stop(self) -> None:  # noqa: B027 - optional hook
        """Release resources. Called once on shutdown."""
