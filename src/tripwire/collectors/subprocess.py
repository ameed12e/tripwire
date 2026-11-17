"""External collector adapter: run any executable that speaks the JSON-lines contract.

This is how collectors written in Go, Rust, C, shell... plug in. The child
process writes one JSON object per line on stdout (see docs/PLUGINS.md)::

    {"v": 1, "kind": "custom", "summary": "USB storage inserted", "severity": "medium",
     "path": null, "decoy_id": null, "details": {"vendor": "0781"}}

Lines with ``"type": "heartbeat"`` are ignored. stderr is forwarded to the log.
The process is restarted with exponential backoff if it exits.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
from typing import Any

from pydantic import Field, ValidationError

from tripwire.collectors.base import Collector, Emit
from tripwire.core.events import Event, EventKind, Severity
from tripwire.core.logging import get_logger
from tripwire.core.plugin import PluginOptions

log = get_logger(__name__)

CONTRACT_VERSION = 1
MAX_LINE_BYTES = 64 * 1024


class SubprocessOptions(PluginOptions):
    command: list[str] = Field(min_length=1, description="argv; executed without a shell")
    env: dict[str, str] = Field(default_factory=dict)
    restart: bool = True
    max_backoff_seconds: float = Field(default=300, gt=0)


def parse_line(line: str, source: str) -> Event | None:
    """Parse one contract line into an Event. Returns None for heartbeats/blank lines."""
    line = line.strip()
    if not line:
        return None
    data: Any = json.loads(line)
    if not isinstance(data, dict):
        raise ValueError("line must be a JSON object")
    if data.get("type") == "heartbeat":
        return None
    version = data.get("v", CONTRACT_VERSION)
    if version != CONTRACT_VERSION:
        raise ValueError(f"unsupported contract version {version}")
    kind_raw = data.get("kind", EventKind.CUSTOM.value)
    try:
        kind = EventKind(kind_raw)
    except ValueError:
        kind = EventKind.CUSTOM
    return Event(
        kind=kind,
        source=source,
        summary=str(data["summary"]),
        severity=Severity(data.get("severity", Severity.MEDIUM.value)),
        path=data.get("path"),
        decoy_id=data.get("decoy_id"),
        details=dict(data.get("details") or {}),
    )


class SubprocessCollector(Collector[SubprocessOptions]):
    Options = SubprocessOptions

    def __init__(self, *args: object, **kwargs: object) -> None:
        super().__init__(*args, **kwargs)  # type: ignore[arg-type]
        self._proc: asyncio.subprocess.Process | None = None
        self._stopping = False

    async def _pump_stderr(self, stream: asyncio.StreamReader) -> None:
        async for raw in stream:
            log.info(
                "collector_stderr", collector=self.name, line=raw.decode(errors="replace")[:500]
            )

    async def _run_once(self, emit: Emit) -> int:
        env = {**os.environ, **self.options.env}
        proc = await asyncio.create_subprocess_exec(
            *self.options.command,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env,
            limit=MAX_LINE_BYTES,
        )
        self._proc = proc
        assert proc.stdout is not None and proc.stderr is not None
        stderr_task = asyncio.create_task(self._pump_stderr(proc.stderr))
        try:
            while True:
                try:
                    raw = await proc.stdout.readline()
                except ValueError:  # line longer than limit
                    log.warning("collector_line_too_long", collector=self.name)
                    continue
                if not raw:
                    break
                try:
                    event = parse_line(raw.decode("utf-8", errors="replace"), self.name)
                except (ValueError, KeyError, ValidationError) as exc:
                    log.warning("collector_bad_line", collector=self.name, error=str(exc))
                    continue
                if event is not None:
                    emit(event)
            return await proc.wait()
        finally:
            stderr_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await stderr_task
            self._proc = None

    async def run(self, emit: Emit) -> None:
        backoff = 1.0
        while not self._stopping:
            try:
                code = await self._run_once(emit)
                log.warning("collector_exited", collector=self.name, code=code)
            except FileNotFoundError:
                log.error("collector_not_found", collector=self.name, cmd=self.options.command[0])
                return
            except OSError as exc:
                log.error("collector_spawn_failed", collector=self.name, error=str(exc))
            if not self.options.restart or self._stopping:
                return
            await asyncio.sleep(backoff)
            backoff = min(backoff * 2, self.options.max_backoff_seconds)

    async def stop(self) -> None:
        self._stopping = True
        proc = self._proc
        if proc is not None and proc.returncode is None:
            with contextlib.suppress(ProcessLookupError):
                proc.terminate()
            try:
                await asyncio.wait_for(proc.wait(), 5)
            except TimeoutError:
                with contextlib.suppress(ProcessLookupError):
                    proc.kill()
