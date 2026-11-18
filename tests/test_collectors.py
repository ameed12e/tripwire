from __future__ import annotations

import asyncio
import json
import os
import sys
import time
from collections.abc import Callable
from pathlib import Path

import pytest

from tripwire.collectors.filesystem import FilesystemCollector, FilesystemOptions
from tripwire.collectors.subprocess import SubprocessCollector, SubprocessOptions, parse_line
from tripwire.core.config import TripwireConfig
from tripwire.core.events import Event, EventKind
from tripwire.core.plugin import PluginContext
from tripwire.decoys.base import DecoyRecord, add_to_manifest


def _has(kind: EventKind) -> Callable[[list[Event]], bool]:
    return lambda events: any(e.kind == kind for e in events)


def _fs(config: TripwireConfig, **opts: object) -> FilesystemCollector:
    return FilesystemCollector("fs", FilesystemOptions(**opts), PluginContext(config))  # type: ignore[arg-type]


async def _collect(
    collector: FilesystemCollector | SubprocessCollector,
    action: object,
    until: Callable[[list[Event]], bool] = bool,
    timeout: float = 5.0,
) -> list[Event]:
    """Run the collector, perform ``action``, and wait until ``until(events)`` holds."""
    events: list[Event] = []
    task = asyncio.create_task(collector.run(events.append))
    await asyncio.sleep(0.3)  # let the observer start
    if callable(action):
        await asyncio.to_thread(action)
    deadline = time.monotonic() + timeout
    while not until(events) and time.monotonic() < deadline:
        await asyncio.sleep(0.05)
    await collector.stop()
    task.cancel()
    await asyncio.gather(task, return_exceptions=True)
    return events


# ---------------------------------------------------------------- filesystem
def test_detects_modification_of_manifest_decoy(config: TripwireConfig, tmp_path: Path) -> None:
    decoy = tmp_path / "passwords.txt"
    decoy.write_text("admin:hunter2\n")
    add_to_manifest(
        config.manifest_path,
        DecoyRecord(id="d1", kind="test", path=str(decoy), label="passwords"),
    )

    def touch() -> None:
        with decoy.open("a") as fh:
            fh.write("x")

    events = asyncio.run(_collect(_fs(config), touch, until=_has(EventKind.FILE_MODIFIED)))
    assert events, "no event emitted"
    assert all(e.decoy_id == "d1" for e in events)
    assert any(e.kind in (EventKind.FILE_MODIFIED, EventKind.FILE_ACCESSED) for e in events)
    assert "passwords" in events[0].summary


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="inotify open events")
def test_detects_plain_read_on_linux(config: TripwireConfig, tmp_path: Path) -> None:
    decoy = tmp_path / "id_rsa"
    decoy.write_text("not a key")
    events = asyncio.run(
        _collect(_fs(config, paths=[str(decoy)], use_manifest=False), decoy.read_text)
    )
    if not events:
        pytest.skip("filesystem does not report open events (e.g. proot/overlay)")
    assert events[0].kind == EventKind.FILE_ACCESSED
    assert events[0].path == str(decoy)


def test_ignores_unrelated_files(config: TripwireConfig, tmp_path: Path) -> None:
    decoy = tmp_path / "decoy.txt"
    decoy.write_text("x")
    other = tmp_path / "other.txt"
    events = asyncio.run(
        _collect(
            _fs(config, paths=[str(decoy)], use_manifest=False),
            lambda: other.write_text("y"),
            timeout=1.0,
        )
    )
    assert events == []


def test_detects_delete_inside_watched_dir(config: TripwireConfig, tmp_path: Path) -> None:
    folder = tmp_path / "Finance"
    folder.mkdir()
    victim = folder / "q3.xlsx"
    victim.write_text("x")
    events = asyncio.run(
        _collect(
            _fs(config, paths=[str(folder)], use_manifest=False),
            victim.unlink,
            until=_has(EventKind.FILE_DELETED),
        )
    )
    assert any(e.kind == EventKind.FILE_DELETED for e in events)


def test_events_from_before_start_are_ignored(config: TripwireConfig, tmp_path: Path) -> None:
    """macOS FSEvents may replay the decoy's own creation after the watcher starts."""
    decoy = tmp_path / "decoy.txt"
    decoy.write_text("x")
    collector = _fs(config, paths=[str(decoy)], use_manifest=False)
    events: list[Event] = []
    collector._emit = events.append
    collector.load_targets()
    collector._started_at = time.time() + 1  # decoy was written before "start"
    collector.handle_fs_event("created", str(decoy), None, False)
    collector.handle_fs_event("modified", str(decoy), None, False)
    assert events == []
    collector.handle_fs_event("deleted", str(decoy), None, False)  # never filtered
    assert [e.kind for e in events] == [EventKind.FILE_DELETED]
    # A real change after start is reported.
    events.clear()
    collector._started_at = time.time() - 1
    decoy.write_text("tampered")
    collector.handle_fs_event("modified", str(decoy), None, False)
    assert [e.kind for e in events] == [EventKind.FILE_MODIFIED]


def test_atime_check(config: TripwireConfig, tmp_path: Path) -> None:
    decoy = tmp_path / "wallet.dat"
    decoy.write_text("x")
    old = time.time() - 86400 * 30
    os.utime(decoy, (old, old))
    collector = _fs(config, paths=[str(decoy)], use_manifest=False)
    events: list[Event] = []
    collector._emit = events.append
    collector.load_targets()
    collector.check_atimes()
    assert events == []
    os.utime(decoy, (time.time(), old))  # simulate a read updating atime
    collector.check_atimes()
    assert [e.kind for e in events] == [EventKind.FILE_ACCESSED]
    assert events[0].details["detected_by"] == "atime"


# ---------------------------------------------------------------- subprocess
def test_parse_line_contract() -> None:
    line = json.dumps(
        {
            "v": 1,
            "kind": "custom",
            "summary": "USB inserted",
            "severity": "low",
            "details": {"a": 1},
        }
    )
    ev = parse_line(line, "usb")
    assert ev is not None and ev.summary == "USB inserted" and ev.details == {"a": 1}
    assert parse_line('{"type": "heartbeat"}', "usb") is None
    assert parse_line("   ", "usb") is None
    assert parse_line('{"kind": "weird", "summary": "s"}', "x").kind == EventKind.CUSTOM  # type: ignore[union-attr]
    with pytest.raises(ValueError):
        parse_line('{"v": 99, "summary": "s"}', "x")
    with pytest.raises(KeyError):
        parse_line('{"kind": "custom"}', "x")


def test_subprocess_collector_end_to_end(config: TripwireConfig) -> None:
    script = (
        "import json, sys\n"
        "print('garbage', flush=True)\n"
        "print(json.dumps({'type': 'heartbeat'}), flush=True)\n"
        "print(json.dumps({'v': 1, 'kind': 'custom', 'summary': 'external hello',"
        " 'severity': 'medium'}), flush=True)\n"
        "print('to stderr', file=sys.stderr)\n"
    )
    collector = SubprocessCollector(
        "ext",
        SubprocessOptions(command=[sys.executable, "-c", script], restart=False),
        PluginContext(config),
    )
    events = asyncio.run(_collect(collector, None))
    assert [e.summary for e in events] == ["external hello"]
    assert events[0].source == "ext"


def test_subprocess_missing_binary(config: TripwireConfig) -> None:
    collector = SubprocessCollector(
        "ext",
        SubprocessOptions(command=["/definitely/not/here"], restart=True),
        PluginContext(config),
    )
    asyncio.run(asyncio.wait_for(collector.run(lambda e: None), 5))  # returns, no hang
