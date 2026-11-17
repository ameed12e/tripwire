from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest
from cryptography.fernet import Fernet

from tripwire.core.config import ENV_FERNET_KEY, ENV_SIGNING_KEY, TripwireConfig, parse_config


@pytest.fixture
def keys(monkeypatch: pytest.MonkeyPatch) -> Iterator[tuple[str, str]]:
    fernet = Fernet.generate_key().decode()
    signing = "test-signing-key-0123456789abcdef"
    monkeypatch.setenv(ENV_FERNET_KEY, fernet)
    monkeypatch.setenv(ENV_SIGNING_KEY, signing)
    yield fernet, signing


@pytest.fixture
def config(tmp_path: Path, keys: tuple[str, str]) -> TripwireConfig:
    return parse_config(
        {
            "host_name": "test-host",
            "data_dir": str(tmp_path / "data"),
            "engine": {"dedupe_window_seconds": 60},
            "server": {"public_url": "https://tw.example.test"},
        }
    )
