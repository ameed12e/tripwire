from __future__ import annotations

import stat
import sys
from pathlib import Path

import httpx
import pytest
import respx
import yaml
from typer.testing import CliRunner

from tripwire.alerts.base import AlertError
from tripwire.alerts.telegram import verify_telegram
from tripwire.cli import app
from tripwire.core.config import (
    ENV_FERNET_KEY,
    ENV_SIGNING_KEY,
    ENV_TELEGRAM_CHAT_ID,
    ENV_TELEGRAM_TOKEN,
    load_config,
    read_env_file,
    write_env_values,
)

runner = CliRunner()
TOKEN = "123456789:AAHsecretSECRETsecretSECRETsecret_x"
CHAT = "987654321"
API = f"https://api.telegram.org/bot{TOKEN}"


@pytest.fixture
def env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    # setenv-then-delenv so monkeypatch also removes values load_env_file adds later.
    for name in (ENV_FERNET_KEY, ENV_SIGNING_KEY, ENV_TELEGRAM_TOKEN, ENV_TELEGRAM_CHAT_ID):
        monkeypatch.setenv(name, "x")
        monkeypatch.delenv(name)
    monkeypatch.setenv("TRIPWIRE_CONFIG", str(tmp_path / "cfg" / "config.yaml"))
    result = runner.invoke(app, ["init", "--data-dir", str(tmp_path / "data")])
    assert result.exit_code == 0, result.output
    return tmp_path


def _telegram_alert(tmp: Path) -> dict[str, object]:
    doc = yaml.safe_load((tmp / "cfg" / "config.yaml").read_text())
    return next(a for a in doc["alerts"] if a["type"] == "telegram")


@respx.mock
def test_setup_telegram_success(env: Path) -> None:
    respx.get(f"{API}/getMe").mock(
        return_value=httpx.Response(200, json={"ok": True, "result": {"username": "tw_bot"}})
    )
    send = respx.post(f"{API}/sendMessage").mock(
        return_value=httpx.Response(200, json={"ok": True, "result": {}})
    )
    result = runner.invoke(app, ["setup-telegram"], input=f"{TOKEN}\n{CHAT}\n")
    assert result.exit_code == 0, result.output
    assert TOKEN not in result.output and "AAHsecret" not in result.output
    assert "@tw_bot" in result.output
    assert send.called and b'"chat_id":"987654321"' in send.calls[0].request.content

    env_file = env / "data" / ".env"
    values = read_env_file(env_file)
    assert values[ENV_TELEGRAM_TOKEN] == TOKEN and values[ENV_TELEGRAM_CHAT_ID] == CHAT
    assert values[ENV_FERNET_KEY] and values[ENV_SIGNING_KEY]  # keys kept
    if sys.platform != "win32":
        assert stat.S_IMODE(env_file.stat().st_mode) == 0o600

    cfg_text = (env / "cfg" / "config.yaml").read_text()
    assert TOKEN not in cfg_text and cfg_text.startswith("# Tripwire configuration")
    alert = _telegram_alert(env)
    assert alert["enabled"] is True
    assert alert["options"] == {
        "bot_token": "${TRIPWIRE_TELEGRAM_TOKEN}",
        "chat_id": "${TRIPWIRE_TELEGRAM_CHAT_ID}",
    }
    cfg = load_config()
    tg = next(a for a in cfg.alerts if a.type == "telegram")
    assert tg.enabled and tg.options["bot_token"] == TOKEN and tg.options["chat_id"] == CHAT

    # Running it again replaces values in place instead of duplicating lines.
    result = runner.invoke(app, ["setup-telegram", "--chat-id", CHAT], input=f"{TOKEN}\n")
    assert result.exit_code == 0, result.output
    assert env_file.read_text().count(ENV_TELEGRAM_TOKEN) == 1


@respx.mock
def test_setup_telegram_bad_token_writes_nothing(env: Path) -> None:
    respx.get(f"{API}/getMe").mock(
        return_value=httpx.Response(401, json={"ok": False, "description": "Unauthorized"})
    )
    before = (env / "data" / ".env").read_text()
    result = runner.invoke(app, ["setup-telegram", "--chat-id", CHAT], input=f"{TOKEN}\n")
    assert result.exit_code == 1
    assert "Unauthorized" in result.output and TOKEN not in result.output
    assert (env / "data" / ".env").read_text() == before
    assert _telegram_alert(env)["enabled"] is False


@respx.mock
def test_setup_telegram_bad_chat(env: Path) -> None:
    respx.get(f"{API}/getMe").mock(
        return_value=httpx.Response(200, json={"ok": True, "result": {"username": "tw_bot"}})
    )
    respx.post(f"{API}/sendMessage").mock(
        return_value=httpx.Response(
            400, json={"ok": False, "description": "Bad Request: chat not found"}
        )
    )
    result = runner.invoke(app, ["setup-telegram"], input=f"{TOKEN}\n{CHAT}\n")
    assert result.exit_code == 1
    assert "chat not found" in result.output and "press Start" in result.output
    assert TOKEN not in result.output
    assert ENV_TELEGRAM_TOKEN not in (env / "data" / ".env").read_text()


def test_setup_telegram_rejects_malformed_input(env: Path) -> None:
    result = runner.invoke(app, ["setup-telegram"], input="not-a-token-SECRETVALUE\n")
    assert result.exit_code == 1 and "SECRETVALUE" not in result.output
    result = runner.invoke(app, ["setup-telegram", "--chat-id", "abc"], input=f"{TOKEN}\n")
    assert result.exit_code == 1 and "chat ID" in result.output


def test_setup_telegram_needs_init(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TRIPWIRE_CONFIG", str(tmp_path / "missing.yaml"))
    result = runner.invoke(app, ["setup-telegram"], input=f"{TOKEN}\n{CHAT}\n")
    assert result.exit_code == 1 and "tripwire init" in result.output


@respx.mock
def test_verify_telegram_network_error_hides_token() -> None:
    respx.get(url__regex=r".*/getMe").mock(side_effect=httpx.ConnectError(f"boom {API}"))
    with pytest.raises(AlertError) as exc_info:
        verify_telegram(TOKEN, CHAT)
    assert TOKEN not in str(exc_info.value) and "ConnectError" in str(exc_info.value)


def test_write_env_values_preserves_other_lines(tmp_path: Path) -> None:
    path = tmp_path / ".env"
    path.write_text("# comment\nA=1\nTRIPWIRE_TELEGRAM_CHAT_ID=old\nB=2\n")
    write_env_values(path, {ENV_TELEGRAM_CHAT_ID: "new", ENV_TELEGRAM_TOKEN: "t"})
    assert path.read_text() == (
        "# comment\nA=1\nTRIPWIRE_TELEGRAM_CHAT_ID=new\nB=2\nTRIPWIRE_TELEGRAM_TOKEN=t\n"
    )
    with pytest.raises(Exception, match="invalid value"):
        write_env_values(path, {"X": "a\nEVIL=1"})
