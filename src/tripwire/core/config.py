"""YAML configuration with pydantic validation.

Secrets never live in the YAML file. Any string value may reference an
environment variable with ``${VAR}`` (or ``${VAR:-default}``); references are
expanded at load time. Required keys (Fernet key, signing key) are read from
``TRIPWIRE_FERNET_KEY`` / ``TRIPWIRE_SIGNING_KEY``, optionally pre-populated
from a ``.env`` file in the data directory that ``tripwire init`` creates with
``0600`` permissions.
"""

from __future__ import annotations

import contextlib
import os
import re
import socket
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, HttpUrl, SecretStr, ValidationError

ENV_FERNET_KEY = "TRIPWIRE_FERNET_KEY"
ENV_SIGNING_KEY = "TRIPWIRE_SIGNING_KEY"
ENV_CONFIG_PATH = "TRIPWIRE_CONFIG"
ENV_TELEGRAM_TOKEN = "TRIPWIRE_TELEGRAM_TOKEN"  # noqa: S105 - variable name, not a secret
ENV_TELEGRAM_CHAT_ID = "TRIPWIRE_TELEGRAM_CHAT_ID"

DEFAULT_CONFIG_PATH = Path("~/.config/tripwire/config.yaml")
DEFAULT_DATA_DIR = Path("~/.local/share/tripwire")

_ENV_REF = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}")


class ConfigError(Exception):
    """Raised for missing or invalid configuration."""


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class PluginConfig(_Strict):
    """A collector or alert channel instance. ``options`` is validated by the plugin."""

    type: str = Field(description="Registered plugin name, e.g. 'filesystem' or 'telegram'")
    name: str | None = Field(default=None, description="Instance name; defaults to type")
    enabled: bool = True
    options: dict[str, Any] = Field(default_factory=dict)

    @property
    def instance_name(self) -> str:
        return self.name or self.type


class ServerConfig(_Strict):
    public_url: HttpUrl = Field(
        default=HttpUrl("http://127.0.0.1:8080"),
        description="Externally reachable base URL used in beacons and report links",
    )
    bind_host: str = "127.0.0.1"
    bind_port: int = Field(default=8080, ge=1, le=65535)
    report_link_ttl_hours: int = Field(default=72, ge=1)
    max_hits_per_minute_per_ip: int = Field(default=30, ge=1)
    trust_forwarded_for: bool = Field(
        default=False, description="Use X-Forwarded-For (only behind a trusted reverse proxy)"
    )


class EngineConfig(_Strict):
    dedupe_window_seconds: float = Field(default=60.0, ge=0)
    queue_size: int = Field(default=1000, ge=1)
    collect_context: bool = Field(
        default=True,
        description="Snapshot process/user/sessions/connections when a decoy file fires",
    )
    context_timeout_seconds: float = Field(default=3.0, gt=0)


class LoggingConfig(_Strict):
    level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    json_output: bool = False


class TripwireConfig(_Strict):
    host_name: str = Field(default_factory=socket.gethostname)
    data_dir: Path = DEFAULT_DATA_DIR
    logging: LoggingConfig = Field(default_factory=LoggingConfig)
    engine: EngineConfig = Field(default_factory=EngineConfig)
    server: ServerConfig = Field(default_factory=ServerConfig)
    collectors: list[PluginConfig] = Field(default_factory=list)
    alerts: list[PluginConfig] = Field(default_factory=list)

    @property
    def resolved_data_dir(self) -> Path:
        return self.data_dir.expanduser()

    @property
    def db_path(self) -> Path:
        return self.resolved_data_dir / "tripwire.db"

    @property
    def manifest_path(self) -> Path:
        return self.resolved_data_dir / "manifest.json"

    @property
    def env_file(self) -> Path:
        return self.resolved_data_dir / ".env"

    def fernet_key(self) -> SecretStr:
        return _require_secret(ENV_FERNET_KEY, self.env_file)

    def signing_key(self) -> SecretStr:
        return _require_secret(ENV_SIGNING_KEY, self.env_file)


def expand_env(value: Any) -> Any:
    """Recursively expand ``${VAR}`` / ``${VAR:-default}`` references in strings."""
    if isinstance(value, str):

        def repl(match: re.Match[str]) -> str:
            name, default = match.group(1), match.group(2)
            env_value = os.environ.get(name)
            if env_value is not None:
                return env_value
            if default is not None:
                return default
            raise ConfigError(f"environment variable {name} is referenced but not set")

        return _ENV_REF.sub(repl, value)
    if isinstance(value, dict):
        return {k: expand_env(v) for k, v in value.items()}
    if isinstance(value, list):
        return [expand_env(v) for v in value]
    return value


def read_env_file(path: Path) -> dict[str, str]:
    """Parse a minimal ``KEY=value`` .env file (comments and blank lines ignored)."""
    values: dict[str, str] = {}
    if not path.is_file():
        return values
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        values[key.strip()] = val.strip().strip('"').strip("'")
    return values


def write_env_values(path: Path, values: dict[str, str]) -> None:
    """Set ``KEY=value`` lines in a .env file, keeping every other line.

    Existing keys are replaced in place, new keys are appended. The file is
    written atomically and created with ``0600`` permissions (best effort on
    Windows, where the user profile directory is already private).
    """
    for key, val in values.items():
        if "\n" in val or "\r" in val or "\n" in key or "=" in key:
            raise ConfigError(f"invalid value for {key}")
    remaining = dict(values)
    lines: list[str] = []
    if path.is_file():
        for raw in path.read_text(encoding="utf-8").splitlines():
            key = raw.partition("=")[0].strip()
            if "=" in raw and not raw.lstrip().startswith("#") and key in remaining:
                lines.append(f"{key}={remaining.pop(key)}")
            else:
                lines.append(raw)
    else:
        lines.append("# Tripwire secrets - never commit or share this file.")
    lines.extend(f"{key}={val}" for key, val in remaining.items())

    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join(lines) + "\n")
    os.replace(tmp, path)
    with contextlib.suppress(OSError):
        path.chmod(0o600)


def load_env_file(path: Path) -> None:
    """Populate ``os.environ`` from a .env file without overriding existing vars."""
    for key, val in read_env_file(path).items():
        os.environ.setdefault(key, val)


def _require_secret(name: str, env_file: Path) -> SecretStr:
    load_env_file(env_file)
    value = os.environ.get(name)
    if not value:
        raise ConfigError(f"{name} is not set; run `tripwire init` or export it")
    return SecretStr(value)


def resolve_config_path(path: Path | str | None = None) -> Path:
    if path is not None:
        return Path(path).expanduser()
    env_path = os.environ.get(ENV_CONFIG_PATH)
    if env_path:
        return Path(env_path).expanduser()
    return DEFAULT_CONFIG_PATH.expanduser()


def _expand_config(data: dict[str, Any]) -> dict[str, Any]:
    """Expand env references, skipping disabled plugins (their secrets may be unset)."""
    out: dict[str, Any] = {}
    for key, value in data.items():
        if key in ("collectors", "alerts") and isinstance(value, list):
            out[key] = [
                p if isinstance(p, dict) and p.get("enabled") is False else expand_env(p)
                for p in value
            ]
        else:
            out[key] = expand_env(value)
    return out


def parse_config(data: dict[str, Any]) -> TripwireConfig:
    try:
        return TripwireConfig.model_validate(_expand_config(data))
    except ValidationError as exc:
        raise ConfigError(f"invalid configuration:\n{exc}") from exc


def load_config(path: Path | str | None = None) -> TripwireConfig:
    cfg_path = resolve_config_path(path)
    if not cfg_path.is_file():
        raise ConfigError(f"config file not found: {cfg_path} (run `tripwire init`)")
    try:
        raw = yaml.safe_load(cfg_path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise ConfigError(f"cannot parse {cfg_path}: {exc}") from exc
    if not isinstance(raw, dict):
        raise ConfigError(f"{cfg_path}: top level must be a mapping")
    # Load the data dir .env before expanding ${VAR} references.
    data_dir = Path(str(raw.get("data_dir", DEFAULT_DATA_DIR))).expanduser()
    load_env_file(data_dir / ".env")
    return parse_config(raw)
