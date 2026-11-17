"""Filesystem collector: alerts when planted decoy files are touched.

Event sources, best first:

* **Linux (inotify):** watchdog reports ``opened`` events, so plain *reads* of a
  decoy are detected immediately.
* **macOS / Windows:** watchdog reports modify/move/delete only. Reads can be
  caught with the optional low-frequency access-time check
  (``atime_poll_seconds``), when the filesystem updates atime.

Everything is event-driven; the only periodic work is the optional atime
check, which ``stat``s a handful of files every N seconds (negligible CPU).
"""

from __future__ import annotations

import asyncio
import os
import threading
from pathlib import Path

from pydantic import Field
from watchdog.events import (
    FileSystemEvent,
    FileSystemEventHandler,
)
from watchdog.observers import Observer

from tripwire.collectors.base import Collector, Emit
from tripwire.core.events import Event, EventKind, Severity
from tripwire.core.logging import get_logger
from tripwire.core.plugin import PluginOptions
from tripwire.decoys.base import load_manifest

log = get_logger(__name__)

_KIND_MAP = {
    "opened": EventKind.FILE_ACCESSED,
    "modified": EventKind.FILE_MODIFIED,
    "closed": EventKind.FILE_MODIFIED,  # closed after write
    "deleted": EventKind.FILE_DELETED,
    "moved": EventKind.FILE_MOVED,
    "created": EventKind.FILE_CREATED,
}

_SEVERITY = {
    EventKind.FILE_ACCESSED: Severity.HIGH,
    EventKind.FILE_MODIFIED: Severity.CRITICAL,
    EventKind.FILE_DELETED: Severity.CRITICAL,
    EventKind.FILE_MOVED: Severity.CRITICAL,
    EventKind.FILE_CREATED: Severity.MEDIUM,
}


class FilesystemOptions(PluginOptions):
    paths: list[str] = Field(default_factory=list, description="Extra files/dirs to watch")
    use_manifest: bool = Field(default=True, description="Also watch every planted decoy")
    atime_poll_seconds: float = Field(default=0, ge=0, description="0 disables the atime check")


class _Handler(FileSystemEventHandler):
    def __init__(self, collector: FilesystemCollector) -> None:
        self.collector = collector

    def on_any_event(self, event: FileSystemEvent) -> None:
        self.collector.handle_fs_event(
            event.event_type,
            os.fsdecode(event.src_path),
            os.fsdecode(event.dest_path) if getattr(event, "dest_path", "") else None,
            event.is_directory,
        )


class FilesystemCollector(Collector[FilesystemOptions]):
    Options = FilesystemOptions

    def __init__(self, *args: object, **kwargs: object) -> None:
        super().__init__(*args, **kwargs)  # type: ignore[arg-type]
        self._emit: Emit | None = None
        self._observer: Observer | None = None
        self._stopped = threading.Event()
        self._targets: dict[str, str | None] = {}  # resolved path -> decoy id
        self._dir_targets: dict[str, str | None] = {}
        self._labels: dict[str, str] = {}
        self._atimes: dict[str, float] = {}

    # ------------------------------------------------------------- targets
    def load_targets(self) -> None:
        targets: dict[str, str | None] = {}
        labels: dict[str, str] = {}
        if self.options.use_manifest:
            for rec in load_manifest(self.ctx.config.manifest_path).decoys:
                resolved = str(Path(rec.path).expanduser().resolve())
                targets[resolved] = rec.id
                labels[resolved] = rec.label
        for raw in self.options.paths:
            targets.setdefault(str(Path(raw).expanduser().resolve()), None)
        self._targets = {p: i for p, i in targets.items() if not Path(p).is_dir()}
        self._dir_targets = {p: i for p, i in targets.items() if Path(p).is_dir()}
        self._labels = labels
        self._atimes = {}
        for p in self._targets:
            try:
                self._atimes[p] = os.stat(p).st_atime
            except OSError:
                log.warning("decoy_missing", path=p)

    def _match(self, path: str) -> tuple[bool, str | None]:
        try:
            resolved = str(Path(path).resolve())
        except OSError:
            resolved = path
        if resolved in self._targets:
            return True, self._targets[resolved]
        for d, decoy_id in self._dir_targets.items():
            if resolved == d or resolved.startswith(d + os.sep):
                return True, decoy_id
        return False, None

    # -------------------------------------------------------------- events
    def handle_fs_event(
        self, event_type: str, src: str, dest: str | None, is_directory: bool
    ) -> None:
        kind = _KIND_MAP.get(event_type)
        if kind is None or self._emit is None:
            return  # closed_no_write and other noise
        if is_directory and event_type in ("modified", "opened"):
            return  # directory listing updates caused by our own watchers
        matched, decoy_id = self._match(src)
        if not matched:
            return
        self._emit_event(kind, src, decoy_id, dest=dest, via=f"watchdog:{event_type}")

    def _emit_event(
        self, kind: EventKind, path: str, decoy_id: str | None, dest: str | None, via: str
    ) -> None:
        assert self._emit is not None
        resolved = str(Path(path).resolve()) if os.path.exists(path) else path
        label = self._labels.get(resolved, Path(path).name)
        verb = kind.value.removeprefix("file_")
        summary = f"Decoy {verb}: {label} ({path})"
        if dest:
            summary += f" -> {dest}"
        details: dict[str, object] = {"detected_by": via}
        if dest:
            details["dest_path"] = dest
        try:
            st = os.stat(path)
            details.update(uid=st.st_uid, size=st.st_size, atime=st.st_atime, mtime=st.st_mtime)
        except OSError:
            pass
        self._emit(
            Event(
                kind=kind,
                source=self.name,
                summary=summary,
                severity=_SEVERITY.get(kind, Severity.HIGH),
                decoy_id=decoy_id,
                path=path,
                details=details,
            )
        )

    def check_atimes(self) -> None:
        """Emit FILE_ACCESSED for decoys whose atime advanced since last check."""
        for path, decoy_id in self._targets.items():
            try:
                atime = os.stat(path).st_atime
            except OSError:
                continue
            previous = self._atimes.get(path)
            self._atimes[path] = atime
            if previous is not None and atime > previous:
                self._emit_event(EventKind.FILE_ACCESSED, path, decoy_id, None, via="atime")

    # ----------------------------------------------------------- lifecycle
    def _watch_dirs(self) -> dict[str, bool]:
        dirs: dict[str, bool] = {}
        for p in self._targets:
            parent = str(Path(p).parent)
            if Path(parent).is_dir():
                dirs.setdefault(parent, False)
        for d in self._dir_targets:
            dirs[d] = True
        return dirs

    async def run(self, emit: Emit) -> None:
        self._emit = emit
        self._stopped.clear()
        self.load_targets()
        observer = Observer()
        for directory, recursive in self._watch_dirs().items():
            observer.schedule(_Handler(self), directory, recursive=recursive)
        observer.daemon = True
        observer.start()
        self._observer = observer
        log.info(
            "filesystem_collector_started",
            files=len(self._targets),
            dirs=len(self._dir_targets),
            atime_poll=self.options.atime_poll_seconds,
        )
        try:
            while not self._stopped.is_set():
                interval = self.options.atime_poll_seconds
                await asyncio.sleep(interval if interval > 0 else 3600)
                if interval > 0:
                    await asyncio.to_thread(self.check_atimes)
        finally:
            await self.stop()

    async def stop(self) -> None:
        self._stopped.set()
        observer, self._observer = self._observer, None
        if observer is not None:
            observer.stop()
            await asyncio.to_thread(observer.join, 5)
