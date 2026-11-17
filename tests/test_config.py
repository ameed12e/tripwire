from __future__ import annotations

from pathlib import Path

import pytest

from tripwire.core.config import (
    ENV_FERNET_KEY,
    ConfigError,
    expand_env,
    load_config,
    parse_config,
    read_env_file,
)
from tripwire.core.events import Event, EventKind, Incident


def test_defaults() -> None:
    cfg = parse_config({})
    assert cfg.server.bind_port == 8080
    assert cfg.collectors == []
    assert cfg.engine.dedupe_window_seconds == 60


def test_env_expansion(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TW_TOKEN", "abc")
    assert expand_env({"a": ["${TW_TOKEN}", "x-${MISSING:-def}"]}) == {"a": ["abc", "x-def"]}


def test_missing_env_reference_is_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("TW_NOPE", raising=False)
    with pytest.raises(ConfigError, match="TW_NOPE"):
        expand_env("${TW_NOPE}")


def test_unknown_key_rejected() -> None:
    with pytest.raises(ConfigError):
        parse_config({"bogus": 1})


def test_invalid_port_rejected() -> None:
    with pytest.raises(ConfigError):
        parse_config({"server": {"bind_port": 70000}})


def test_load_yaml_with_plugins(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TW_CHAT", "42")
    cfg_file = tmp_path / "config.yaml"
    cfg_file.write_text(
        f"""
data_dir: {tmp_path / "data"}
collectors:
  - type: filesystem
    options: {{paths: [/tmp/x]}}
alerts:
  - type: telegram
    name: phone
    options: {{chat_id: "${{TW_CHAT}}", bot_token: "${{TW_BOT:-t}}"}}
""",
        encoding="utf-8",
    )
    cfg = load_config(cfg_file)
    assert cfg.collectors[0].instance_name == "filesystem"
    assert cfg.alerts[0].instance_name == "phone"
    assert cfg.alerts[0].options["chat_id"] == "42"


def test_missing_config_file(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="not found"):
        load_config(tmp_path / "nope.yaml")


def test_secret_from_env_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(ENV_FERNET_KEY, raising=False)
    data = tmp_path / "data"
    data.mkdir()
    (data / ".env").write_text(f"# comment\n{ENV_FERNET_KEY}='k123'\n", encoding="utf-8")
    assert read_env_file(data / ".env") == {ENV_FERNET_KEY: "k123"}
    cfg = parse_config({"data_dir": str(data)})
    assert cfg.fernet_key().get_secret_value() == "k123"


def test_missing_secret(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(ENV_FERNET_KEY, raising=False)
    cfg = parse_config({"data_dir": str(tmp_path)})
    with pytest.raises(ConfigError, match=ENV_FERNET_KEY):
        cfg.fernet_key()


def test_incident_roundtrip() -> None:
    ev = Event(kind=EventKind.FILE_ACCESSED, source="fs", summary="read", path="/x")
    inc = Incident(event=ev)
    again = Incident.model_validate(inc.report())
    assert again == inc
    assert ev.dedupe_key() == "file_accessed:/x"
