"""The engine wires collectors -> de-duplication -> storage -> alert channels.

Collectors call :meth:`Engine.emit` (thread-safe). Events are queued and
processed by a single async worker, so storage writes and alert fan-out never
block a collector. Identical events within ``dedupe_window_seconds`` are
collapsed (e.g. an editor reading a decoy ten times in a second).
"""

from __future__ import annotations

import asyncio
import contextlib
import time
from collections.abc import Sequence

from tripwire.alerts.base import AlertMessage, AnyAlertChannel
from tripwire.collectors.base import AnyCollector
from tripwire.core.config import TripwireConfig
from tripwire.core.events import Event, Incident
from tripwire.core.logging import get_logger
from tripwire.server.security import report_url
from tripwire.storage.db import Database

log = get_logger(__name__)

ALERT_TIMEOUT_SECONDS = 20.0


class Engine:
    def __init__(
        self,
        config: TripwireConfig,
        db: Database,
        channels: Sequence[AnyAlertChannel] = (),
        collectors: Sequence[AnyCollector] = (),
    ) -> None:
        self.config = config
        self.db = db
        self.channels = list(channels)
        self.collectors = list(collectors)
        self._queue: asyncio.Queue[Event] | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._last_seen: dict[str, float] = {}
        self._tasks: list[asyncio.Task[None]] = []
        self._signing_key = config.signing_key().get_secret_value()
        self.stats = {"received": 0, "suppressed": 0, "incidents": 0, "alert_failures": 0}

    # ------------------------------------------------------------ ingestion
    def emit(self, event: Event) -> None:
        """Queue an event. Safe to call from any thread once the engine started."""
        if self._loop is None or self._queue is None:
            raise RuntimeError("engine not started")
        if event.host is None:
            event = event.model_copy(update={"host": self.config.host_name})
        self._loop.call_soon_threadsafe(self._enqueue, event)

    def _enqueue(self, event: Event) -> None:
        assert self._queue is not None
        try:
            self._queue.put_nowait(event)
        except asyncio.QueueFull:
            log.warning("event_dropped_queue_full", kind=event.kind, source=event.source)

    def _is_duplicate(self, event: Event) -> bool:
        window = self.config.engine.dedupe_window_seconds
        if window <= 0:
            return False
        now = time.monotonic()
        key = event.dedupe_key()
        last = self._last_seen.get(key)
        self._last_seen[key] = now
        if len(self._last_seen) > 5000:
            cutoff = now - window
            self._last_seen = {k: v for k, v in self._last_seen.items() if v >= cutoff}
        return last is not None and now - last < window

    # ----------------------------------------------------------- processing
    async def process(self, event: Event) -> Incident | None:
        """Persist and alert on one event. Returns ``None`` if suppressed."""
        self.stats["received"] += 1
        if event.host is None:
            event = event.model_copy(update={"host": self.config.host_name})
        if self._is_duplicate(event):
            self.stats["suppressed"] += 1
            log.debug("event_suppressed", key=event.dedupe_key())
            return None
        incident = Incident(event=event)
        await asyncio.to_thread(self.db.add_incident, incident)
        self.stats["incidents"] += 1
        log.warning("incident", id=incident.id, kind=event.kind.value, summary=event.summary)
        await self._dispatch(incident)
        return incident

    def report_link(self, incident: Incident) -> str:
        srv = self.config.server
        return report_url(
            str(srv.public_url), self._signing_key, incident.id, srv.report_link_ttl_hours
        )

    async def _dispatch(self, incident: Incident) -> None:
        if not self.channels:
            return
        message = AlertMessage(incident=incident, report_url=self.report_link(incident))

        async def deliver(channel: AnyAlertChannel) -> None:
            try:
                await asyncio.wait_for(channel.send(message), ALERT_TIMEOUT_SECONDS)
                log.info("alert_sent", channel=channel.name, incident=incident.id)
            except Exception as exc:
                self.stats["alert_failures"] += 1
                log.error("alert_failed", channel=channel.name, error=str(exc))

        await asyncio.gather(*(deliver(c) for c in self.channels))

    async def _worker(self) -> None:
        assert self._queue is not None
        while True:
            event = await self._queue.get()
            try:
                await self.process(event)
            except Exception:
                log.exception("event_processing_failed", kind=event.kind)
            finally:
                self._queue.task_done()

    async def _run_collector(self, collector: AnyCollector) -> None:
        try:
            await collector.run(self.emit)
        except asyncio.CancelledError:
            raise
        except Exception:
            log.exception("collector_crashed", collector=collector.name)

    # ------------------------------------------------------------ lifecycle
    async def start(self) -> None:
        self._loop = asyncio.get_running_loop()
        self._queue = asyncio.Queue(maxsize=self.config.engine.queue_size)
        self._tasks.append(asyncio.create_task(self._worker(), name="tripwire-worker"))
        for collector in self.collectors:
            self._tasks.append(
                asyncio.create_task(self._run_collector(collector), name=collector.name)
            )
        log.info(
            "engine_started",
            collectors=[c.name for c in self.collectors],
            channels=[c.name for c in self.channels],
        )

    async def drain(self) -> None:
        """Wait until every queued event has been processed."""
        if self._queue is not None:
            await self._queue.join()

    async def stop(self) -> None:
        for collector in self.collectors:
            with contextlib.suppress(Exception):
                await collector.stop()
        if self._queue is not None:
            with contextlib.suppress(Exception):
                await asyncio.wait_for(self._queue.join(), 5)
        for task in self._tasks:
            task.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        self._tasks.clear()
        for channel in self.channels:
            with contextlib.suppress(Exception):
                await channel.close()
        log.info("engine_stopped", **self.stats)
