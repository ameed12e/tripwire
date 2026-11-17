"""Test doubles shared across test modules."""

from __future__ import annotations

import asyncio

from tripwire.alerts.base import AlertChannel, AlertError, AlertMessage
from tripwire.collectors.base import Collector, Emit
from tripwire.core.events import Event, EventKind
from tripwire.core.plugin import PluginOptions


class RecordingOptions(PluginOptions):
    fail: bool = False


class RecordingChannel(AlertChannel[RecordingOptions]):
    Options = RecordingOptions

    def __init__(self, *args: object, **kwargs: object) -> None:
        super().__init__(*args, **kwargs)  # type: ignore[arg-type]
        self.messages: list[AlertMessage] = []

    async def send(self, message: AlertMessage) -> None:
        if self.options.fail:
            raise AlertError("boom")
        self.messages.append(message)


class OneShotCollector(Collector[PluginOptions]):
    """Emits a single event, then idles until cancelled."""

    async def run(self, emit: Emit) -> None:
        emit(Event(kind=EventKind.CUSTOM, source=self.name, summary="one-shot"))
        await asyncio.Event().wait()
