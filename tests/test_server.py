from __future__ import annotations

import time
from datetime import UTC, datetime
from urllib.parse import urlparse

import pytest
from fastapi.testclient import TestClient
from helpers import RecordingChannel, RecordingOptions

from tripwire.core.config import TripwireConfig
from tripwire.core.engine import Engine
from tripwire.core.events import EventKind
from tripwire.core.plugin import PluginContext
from tripwire.server.app import PIXEL_GIF, create_app
from tripwire.server.security import (
    RateLimiter,
    make_beacon_token,
    new_decoy_id,
    verify_beacon_token,
)
from tripwire.storage import Cipher, Database


@pytest.fixture
def setup(config: TripwireConfig) -> tuple[Engine, RecordingChannel]:
    db = Database(config.db_path, Cipher(config.fernet_key().get_secret_value()))
    ch = RecordingChannel("rec", RecordingOptions(), PluginContext(config))
    return Engine(config, db, channels=[ch]), ch


def _wait_for(pred: object, timeout: float = 3.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if pred():  # type: ignore[operator]
            return
        time.sleep(0.02)
    raise AssertionError("condition not met")


def test_token_roundtrip() -> None:
    did = new_decoy_id()
    tok = make_beacon_token("k", did)
    assert verify_beacon_token("k", tok) == did
    assert verify_beacon_token("k", tok.upper()) == did
    assert verify_beacon_token("other", tok) is None
    assert verify_beacon_token("k", tok[:-1] + ("0" if tok[-1] != "0" else "1")) is None
    assert verify_beacon_token("k", "../../etc/passwd") is None


def test_beacon_hit_creates_incident_and_alert(
    setup: tuple[Engine, RecordingChannel], keys: tuple[str, str]
) -> None:
    engine, ch = setup
    did = new_decoy_id()
    engine.db.register_beacon(did, "Salaries.docx on laptop", datetime.now(UTC))
    token = make_beacon_token(keys[1], did)
    with TestClient(create_app(engine)) as client:
        resp = client.get(f"/t/{token}.png", headers={"User-Agent": "Word/16.0"})
        assert resp.status_code == 200
        assert resp.content == PIXEL_GIF
        assert resp.headers["cache-control"].startswith("no-store")
        _wait_for(lambda: ch.messages)

        [msg] = ch.messages
        ev = msg.incident.event
        assert ev.kind == EventKind.BEACON_HIT
        assert ev.decoy_id == did
        assert "Salaries.docx" in ev.summary and "Word/16.0" in ev.summary
        assert ev.details["client_ip"] == "testclient"

        # The signed report link from the alert works ...
        assert msg.report_url is not None
        url = urlparse(msg.report_url)
        report = client.get(f"{url.path}?{url.query}")
        assert report.status_code == 200
        assert report.json()["id"] == msg.incident.id
        assert report.json()["event"]["details"]["headers"]["user-agent"] == "Word/16.0"
        # ... but tampering with it does not.
        bad = client.get(f"{url.path}?{url.query.replace('sig=', 'sig=00')}")
        assert bad.status_code == 404


def test_invalid_token_returns_pixel_without_incident(
    setup: tuple[Engine, RecordingChannel],
) -> None:
    engine, ch = setup
    with TestClient(create_app(engine)) as client:
        for path in ("/t/deadbeef", "/t/" + "0" * 32, "/t/whatever.png"):
            resp = client.get(path)
            assert resp.status_code == 200 and resp.content == PIXEL_GIF
        time.sleep(0.2)
    assert ch.messages == []
    assert engine.db.count_incidents() == 0


def test_expired_report_link(setup: tuple[Engine, RecordingChannel], keys: tuple[str, str]) -> None:
    from tripwire.server.security import sign_report

    engine, _ = setup
    past = int(time.time()) - 10
    with TestClient(create_app(engine)) as client:
        resp = client.get(f"/r/abc?exp={past}&sig={sign_report(keys[1], 'abc', past)}")
        assert resp.status_code == 404
        assert client.get("/healthz").json() == {"status": "ok"}


def test_repeated_hits_same_ip_deduped(
    setup: tuple[Engine, RecordingChannel], keys: tuple[str, str]
) -> None:
    engine, ch = setup
    token = make_beacon_token(keys[1], new_decoy_id())
    with TestClient(create_app(engine)) as client:
        for _ in range(5):
            client.get(f"/t/{token}")
        _wait_for(lambda: engine.stats["received"] >= 5)
    assert len(ch.messages) == 1


def test_rate_limiter() -> None:
    rl = RateLimiter(max_hits=2, window_seconds=60)
    assert rl.allow("a", now=0) and rl.allow("a", now=1)
    assert not rl.allow("a", now=2)
    assert rl.allow("b", now=2)
    assert rl.allow("a", now=62)
