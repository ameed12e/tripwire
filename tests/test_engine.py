from __future__ import annotations

import asyncio
import threading
from urllib.parse import parse_qs, urlparse

import pytest

from helpers import OneShotCollector, RecordingChannel, RecordingOptions
from tripwire.core import registry
from tripwire.core.config import ConfigError, PluginConfig, TripwireConfig
from tripwire.core.engine import Engine
from tripwire.core.events import Event, EventKind
from tripwire.core.plugin import PluginContext, PluginOptions
from tripwire.server.security import verify_report
from tripwire.storage import Cipher, Database


def _db(config: TripwireConfig) -> Database:
    return Database(config.db_path, Cipher(config.fernet_key().get_secret_value()))


def _event(path: str = "/decoy") -> Event:
    return Event(kind=EventKind.FILE_ACCESSED, source="test", summary="read", path=path)


def _channel(config: TripwireConfig, fail: bool = False) -> RecordingChannel:
    return RecordingChannel("rec", RecordingOptions(fail=fail), PluginContext(config))


def test_process_stores_and_alerts(config: TripwireConfig, keys: tuple[str, str]) -> None:
    db = _db(config)
    ch = _channel(config)
    engine = Engine(config, db, channels=[ch])
    incident = asyncio.run(engine.process(_event()))
    assert incident is not None
    assert db.get_incident(incident.id) == incident
    assert incident.event.host == "test-host"
    [msg] = ch.messages
    assert msg.report_url is not None
    url = urlparse(msg.report_url)
    assert url.netloc == "tw.example.test"
    q = parse_qs(url.query)
    assert verify_report(keys[1], incident.id, int(q["exp"][0]), q["sig"][0])
    assert "Report:" in msg.text and len(msg.text) < 500


def test_dedupe_window(config: TripwireConfig) -> None:
    engine = Engine(config, _db(config))

    async def go() -> list[object]:
        return [await engine.process(_event()) for _ in range(5)] + [
            await engine.process(_event("/other"))
        ]

    results = asyncio.run(go())
    assert sum(r is not None for r in results) == 2
    assert engine.stats["suppressed"] == 4


def test_failing_channel_does_not_block_others(config: TripwireConfig) -> None:
    good, bad = _channel(config), _channel(config, fail=True)
    engine = Engine(config, _db(config), channels=[bad, good])
    asyncio.run(engine.process(_event()))
    assert len(good.messages) == 1
    assert engine.stats["alert_failures"] == 1


def test_emit_from_thread_and_collector(config: TripwireConfig) -> None:
    db = _db(config)
    collector = OneShotCollector("oneshot", PluginOptions(), PluginContext(config))
    engine = Engine(config, db, collectors=[collector])

    async def go() -> None:
        await engine.start()
        t = threading.Thread(target=engine.emit, args=(_event("/from-thread"),))
        t.start()
        t.join()
        for _ in range(100):
            await asyncio.sleep(0.01)
            if db.count_incidents() >= 2:
                break
        await engine.stop()

    asyncio.run(go())
    kinds = sorted(i.event.kind.value for i in db.list_incidents())
    assert kinds == ["custom", "file_accessed"]


def test_emit_before_start_raises(config: TripwireConfig) -> None:
    with pytest.raises(RuntimeError):
        Engine(config, _db(config)).emit(_event())


def test_registry_builtins_and_custom(config: TripwireConfig) -> None:
    assert {"filesystem", "subprocess"} <= set(registry.collectors.names())
    assert {"telegram", "email", "webhook"} <= set(registry.alerts.names())
    registry.alerts.register("recording", RecordingChannel)
    ch = registry.build_alert(
        PluginConfig(type="recording", name="r1", options={"fail": True}), PluginContext(config)
    )
    assert isinstance(ch, RecordingChannel) and ch.name == "r1" and ch.options.fail


def test_registry_errors(config: TripwireConfig) -> None:
    ctx = PluginContext(config)
    with pytest.raises(ConfigError, match="unknown"):
        registry.build_alert(PluginConfig(type="carrier-pigeon"), ctx)
    registry.alerts.register("recording", RecordingChannel)
    with pytest.raises(ConfigError, match="invalid options"):
        registry.build_alert(PluginConfig(type="recording", options={"nope": 1}), ctx)
