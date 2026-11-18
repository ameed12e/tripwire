from __future__ import annotations

import asyncio
import os
from collections import namedtuple
from pathlib import Path
from typing import Any

import psutil
import pytest

from helpers import RecordingChannel, RecordingOptions
from tripwire.alerts.base import AlertMessage
from tripwire.core import context
from tripwire.core.config import TripwireConfig
from tripwire.core.engine import Engine
from tripwire.core.events import Event, EventKind, Incident
from tripwire.core.plugin import PluginContext
from tripwire.storage import Cipher, Database

FULL_CTX: dict[str, Any] = {
    "local_user": "alice",
    "processes": [{"pid": 4242, "name": "cat", "user": "mallory"}],
    "sessions": [
        {"user": "mallory", "terminal": "pts/1", "host": "203.0.113.7"},
        {"user": "eve", "terminal": "pts/2", "host": "198.51.100.2"},
        {"user": "x", "terminal": "pts/3", "host": "192.0.2.1"},
        {"user": "y", "terminal": "pts/4", "host": "192.0.2.2"},
        {"user": "alice", "terminal": "tty1", "host": ""},
    ],
    "connections": [
        {"ip": "203.0.113.9", "port": 443, "pid": 4242, "process": "curl"},
        {"ip": "198.51.100.3", "port": 22, "pid": None, "process": "?"},
        {"ip": "192.0.2.5", "port": 8080, "pid": 7, "process": "nc"},
    ],
}


def _msg(ctx: dict[str, Any] | None, url: str | None = "https://tw.example.test/r/1") -> str:
    details = {"context": ctx} if ctx is not None else {}
    ev = Event(
        kind=EventKind.FILE_ACCESSED,
        source="fs",
        summary="Decoy accessed: passwords.txt (/home/alice/passwords.txt)",
        host="laptop",
        details=details,
    )
    return AlertMessage(incident=Incident(event=ev), report_url=url).text


def test_full_context_fits_phone_budget() -> None:
    text = _msg(FULL_CTX)
    lines = text.splitlines()
    assert len(lines) <= 15
    assert "User: alice" in text
    assert "Process: cat (PID 4242, mallory)" in text
    assert "Remote sessions (4, 1 local):" in text
    assert "  mallory from 203.0.113.7 pts/1" in text
    assert "192.0.2.2" not in text  # only top 3 remote sessions
    assert "  203.0.113.9:443 curl (4242)" in text
    assert "  198.51.100.3:22 ?" in text
    assert lines[-1].startswith("Report: https://")


def test_unavailable_and_empty_context() -> None:
    text = _msg(
        {
            "local_user": "u0_a123",
            "processes": "unavailable",
            "sessions": "unavailable",
            "connections": "unavailable",
        }
    )
    assert "Process: unknown (no permission)" in text
    assert "Remote sessions: unavailable" in text
    assert "Outbound: unavailable" in text
    text = _msg({"local_user": "a", "processes": [], "sessions": [], "connections": []})
    assert "Process: unknown (file already closed)" in text
    assert "Remote sessions: none" in text
    assert "Outbound: none" in text


def test_loopback_report_link_replaced_by_incident_id() -> None:
    text = _msg(None, url="http://127.0.0.1:8765/r/abc?sig=x")
    assert "127.0.0.1" not in text
    assert "Incident: " in text.splitlines()[-1]


def test_snapshot_finds_own_open_file_from_child(tmp_path: Path) -> None:
    decoy = tmp_path / "decoy.txt"
    decoy.write_text("x")
    with decoy.open():
        # Our own PID is excluded, so nothing (or 'unavailable' if sandboxed).
        assert context._openers(str(decoy)) in ([], context.UNAVAILABLE)
    ctx = context.snapshot(str(decoy))
    assert set(ctx) == {"local_user", "processes", "sessions", "connections"}


def test_snapshot_never_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*_a: object, **_k: object) -> None:
        raise psutil.AccessDenied()

    monkeypatch.setattr(psutil, "users", boom)
    monkeypatch.setattr(psutil, "net_connections", boom)
    monkeypatch.setattr(psutil, "process_iter", boom)
    ctx = context.snapshot("/nope")
    assert ctx["sessions"] == ctx["connections"] == ctx["processes"] == "unavailable"


def test_connections_filtered_and_ranked(monkeypatch: pytest.MonkeyPatch) -> None:
    Addr = namedtuple("Addr", "ip port")
    Conn = namedtuple("Conn", "status raddr pid")
    est = psutil.CONN_ESTABLISHED
    conns = [
        Conn(est, Addr("127.0.0.1", 80), 1),
        Conn("LISTEN", Addr("8.8.8.8", 53), 1),
        Conn(est, (), 1),
        Conn(est, Addr("203.0.113.1", 443), None),
        Conn(est, Addr("203.0.113.2", 443), None),
        Conn(est, Addr("203.0.113.2", 443), None),
    ]
    monkeypatch.setattr(psutil, "net_connections", lambda kind: conns)
    out = context._connections()
    assert isinstance(out, list)
    assert [c["ip"] for c in out] == ["203.0.113.2", "203.0.113.1"]


def test_engine_attaches_context_to_file_events(config: TripwireConfig) -> None:
    db = Database(config.db_path, Cipher(config.fernet_key().get_secret_value()))
    ch = RecordingChannel("rec", RecordingOptions(), PluginContext(config))
    engine = Engine(config, db, channels=[ch])
    file_ev = Event(kind=EventKind.FILE_ACCESSED, source="t", summary="r", path=os.devnull)
    incident = asyncio.run(engine.process(file_ev))
    assert incident is not None
    assert "local_user" in incident.event.details["context"]
    assert "User: " in ch.messages[0].text

    beacon = Event(kind=EventKind.BEACON_HIT, source="t", summary="b")
    incident = asyncio.run(engine.process(beacon))
    assert incident is not None and "context" not in incident.event.details


def test_engine_context_can_be_disabled(config: TripwireConfig) -> None:
    config.engine.collect_context = False
    db = Database(config.db_path, Cipher(config.fernet_key().get_secret_value()))
    engine = Engine(config, db)
    ev = Event(kind=EventKind.FILE_ACCESSED, source="t", summary="r", path=os.devnull)
    incident = asyncio.run(engine.process(ev))
    assert incident is not None and "context" not in incident.event.details
