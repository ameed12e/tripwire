from __future__ import annotations

import stat
import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

from tripwire.cli import app
from tripwire.core.config import ENV_FERNET_KEY, ENV_SIGNING_KEY

runner = CliRunner()


@pytest.fixture
def env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.delenv(ENV_FERNET_KEY, raising=False)
    monkeypatch.delenv(ENV_SIGNING_KEY, raising=False)
    cfg = tmp_path / "cfg" / "config.yaml"
    monkeypatch.setenv("TRIPWIRE_CONFIG", str(cfg))
    return tmp_path


def _init(tmp: Path) -> None:
    result = runner.invoke(
        app, ["init", "--data-dir", str(tmp / "data"), "--public-url", "https://tw.example.test"]
    )
    assert result.exit_code == 0, result.output


def test_version() -> None:
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0 and "tripwire" in result.output


def test_init_creates_files(env: Path) -> None:
    _init(env)
    assert (env / "cfg" / "config.yaml").is_file()
    env_file = env / "data" / ".env"
    content = env_file.read_text()
    assert ENV_FERNET_KEY in content and ENV_SIGNING_KEY in content
    if sys.platform != "win32":
        assert stat.S_IMODE(env_file.stat().st_mode) == 0o600
    assert "TRIPWIRE_FERNET_KEY" not in (env / "cfg" / "config.yaml").read_text()
    again = runner.invoke(app, ["init", "--data-dir", str(env / "data")])
    assert again.exit_code == 1 and "already exists" in again.output


def test_plant_status_remove(env: Path) -> None:
    _init(env)
    target = env / "home"
    target.mkdir()
    listed = runner.invoke(app, ["plant", "--list"])
    assert "beacon-docx" in listed.output and "aws-credentials" in listed.output

    result = runner.invoke(app, ["plant", "passwords", str(target), "--yes", "--label", "desk"])
    assert result.exit_code == 0, result.output
    assert (target / "passwords.txt").is_file()

    result = runner.invoke(app, ["plant", "beacon-html", str(target), "--yes"])
    assert result.exit_code == 0, result.output
    assert "https://tw.example.test/t/" in next(target.glob("*.html")).read_text()

    status = runner.invoke(app, ["status"], env={"COLUMNS": "250"})
    assert status.exit_code == 0, status.output
    assert "passwords" in status.output and "Incidents: 0" in status.output

    removed = runner.invoke(app, ["plant", "--remove-all"])
    assert removed.exit_code == 0, removed.output
    assert list(target.iterdir()) == []


def test_plant_requires_confirmation(env: Path) -> None:
    _init(env)
    result = runner.invoke(app, ["plant", "ssh-key", str(env)], input="n\n")
    assert result.exit_code != 0
    assert not (env / "id_ed25519_backup").exists()


def test_incidents_empty_and_show_missing(env: Path) -> None:
    _init(env)
    result = runner.invoke(app, ["incidents"])
    assert result.exit_code == 0 and "0 incident" in result.output
    assert runner.invoke(app, ["incidents", "--json"]).output.strip() == "[]"
    assert runner.invoke(app, ["incidents", "--show", "nope"]).exit_code == 1


def test_missing_config_is_friendly(env: Path) -> None:
    result = runner.invoke(app, ["status"])
    assert result.exit_code == 1 and "tripwire init" in result.output


def test_bad_plugin_reports_error(env: Path) -> None:
    _init(env)
    cfg = env / "cfg" / "config.yaml"
    cfg.write_text(cfg.read_text() + "\n", encoding="utf-8")
    text = cfg.read_text().replace("type: filesystem", "type: does-not-exist")
    cfg.write_text(text, encoding="utf-8")
    result = runner.invoke(app, ["watch"])
    assert result.exit_code == 1 and "unknown" in result.output
