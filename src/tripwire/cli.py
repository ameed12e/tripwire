"""Command line interface: ``tripwire init | plant | watch | status | incidents | serve``."""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import signal
import stat
from pathlib import Path
from typing import Annotated

import typer
import yaml
from rich.console import Console
from rich.table import Table

from tripwire import __version__
from tripwire.core import registry
from tripwire.core.config import (
    ENV_FERNET_KEY,
    ENV_SIGNING_KEY,
    ConfigError,
    TripwireConfig,
    load_config,
    resolve_config_path,
)
from tripwire.core.engine import Engine
from tripwire.core.logging import configure_logging
from tripwire.core.plugin import PluginContext
from tripwire.decoys.base import PlantError, load_manifest
from tripwire.decoys.planter import TEMPLATES
from tripwire.decoys.planter import plant as plant_decoy
from tripwire.decoys.planter import remove as remove_decoy
from tripwire.storage import Cipher, Database, DecryptionError, generate_key

app = typer.Typer(
    name="tripwire",
    help="Defensive tripwires and honeytokens for devices you own.",
    no_args_is_help=True,
    add_completion=False,
)
console = Console()
err = Console(stderr=True)

ConfigOpt = Annotated[
    Path | None,
    typer.Option(
        "--config",
        "-c",
        help="Config file (default: $TRIPWIRE_CONFIG or ~/.config/tripwire/config.yaml)",
    ),
]


def _fail(message: str) -> typer.Exit:
    err.print(f"[bold red]error:[/] {message}")
    return typer.Exit(code=1)


def _load(config_path: Path | None) -> TripwireConfig:
    try:
        cfg = load_config(config_path)
    except ConfigError as exc:
        raise _fail(str(exc)) from None
    configure_logging(cfg.logging.level, cfg.logging.json_output)
    return cfg


def _open_db(cfg: TripwireConfig) -> Database:
    try:
        return Database(cfg.db_path, Cipher(cfg.fernet_key().get_secret_value()))
    except (ConfigError, ValueError) as exc:
        raise _fail(str(exc)) from None


def _build_engine(cfg: TripwireConfig, with_collectors: bool = True) -> Engine:
    ctx = PluginContext(cfg)
    try:
        channels = [registry.build_alert(a, ctx) for a in cfg.alerts if a.enabled]
        collectors = (
            [registry.build_collector(c, ctx) for c in cfg.collectors if c.enabled]
            if with_collectors
            else []
        )
    except ConfigError as exc:
        raise _fail(str(exc)) from None
    return Engine(cfg, _open_db(cfg), channels=channels, collectors=collectors)


def _version(value: bool) -> None:
    if value:
        console.print(f"tripwire {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: Annotated[
        bool, typer.Option("--version", callback=_version, is_eager=True, help="Show version")
    ] = False,
) -> None:
    """Deploy only on systems you own or are explicitly authorized to monitor."""


# ---------------------------------------------------------------------- init
@app.command()
def init(
    config: ConfigOpt = None,
    data_dir: Annotated[Path, typer.Option(help="Where the DB, manifest and .env live")] = Path(
        "~/.local/share/tripwire"
    ),
    public_url: Annotated[str, typer.Option(help="Public base URL of your beacon server")] = (
        "http://127.0.0.1:8080"
    ),
    force: Annotated[bool, typer.Option(help="Overwrite an existing config")] = False,
) -> None:
    """Create a config file, data directory and fresh encryption/signing keys."""
    cfg_path = resolve_config_path(config)
    if cfg_path.exists() and not force:
        raise _fail(f"{cfg_path} already exists (use --force to overwrite)")
    data = data_dir.expanduser()
    data.mkdir(parents=True, exist_ok=True)

    env_file = data / ".env"
    if env_file.exists():
        console.print(f"[yellow]Keeping existing keys in {env_file}[/]")
    else:
        env_file.write_text(
            "# Tripwire secrets - never commit or share this file.\n"
            f"{ENV_FERNET_KEY}={generate_key()}\n"
            f"{ENV_SIGNING_KEY}={os.urandom(32).hex()}\n",
            encoding="utf-8",
        )
        with contextlib.suppress(OSError):  # best effort on Windows
            env_file.chmod(stat.S_IRUSR | stat.S_IWUSR)

    document = {
        "data_dir": str(data_dir),
        "server": {"public_url": public_url, "bind_host": "127.0.0.1", "bind_port": 8080},
        "collectors": [{"type": "filesystem", "name": "decoys", "options": {"paths": []}}],
        "alerts": [
            {
                "type": "telegram",
                "enabled": False,
                "options": {
                    "bot_token": "${TRIPWIRE_TELEGRAM_TOKEN}",
                    "chat_id": "${TRIPWIRE_TELEGRAM_CHAT_ID}",
                },
            },
            {"type": "webhook", "enabled": False, "options": {"url": "${TRIPWIRE_WEBHOOK_URL}"}},
        ],
    }
    cfg_path.parent.mkdir(parents=True, exist_ok=True)
    cfg_path.write_text(
        "# Tripwire configuration. Secrets go in environment variables, not here.\n"
        + yaml.safe_dump(document, sort_keys=False),
        encoding="utf-8",
    )
    cfg = _load(cfg_path)
    _open_db(cfg).close()
    console.print(f"[green]✓[/] Config written to {cfg_path}")
    console.print(f"[green]✓[/] Keys stored in {env_file} (mode 600)")
    console.print("Next: [bold]tripwire plant --list[/], then [bold]tripwire watch[/]")


# --------------------------------------------------------------------- plant
@app.command()
def plant(
    template: Annotated[str | None, typer.Argument(help="Decoy template name")] = None,
    destination: Annotated[Path | None, typer.Argument(help="File or directory")] = None,
    label: Annotated[str | None, typer.Option(help="Human label shown in alerts")] = None,
    list_templates: Annotated[bool, typer.Option("--list", help="List templates")] = False,
    remove: Annotated[str | None, typer.Option("--remove", help="Remove decoy by id")] = None,
    remove_all: Annotated[bool, typer.Option("--remove-all", help="Remove every decoy")] = False,
    force: Annotated[bool, typer.Option(help="Overwrite / delete even if changed")] = False,
    yes: Annotated[bool, typer.Option("--yes", "-y", help="Do not ask for confirmation")] = False,
    config: ConfigOpt = None,
) -> None:
    """Plant a decoy, list templates, or remove planted decoys."""
    if list_templates:
        table = Table(title="Decoy templates")
        table.add_column("Name", style="bold")
        table.add_column("Type")
        table.add_column("Default filename")
        table.add_column("Description")
        for name, cls in sorted(TEMPLATES.items()):
            table.add_row(
                name, "beacon" if cls.beacon else "file", cls.default_filename, cls.description
            )
        console.print(table)
        return

    cfg = _load(config)
    db = _open_db(cfg)
    try:
        if remove or remove_all:
            ids = [remove] if remove else [d.id for d in load_manifest(cfg.manifest_path).decoys]
            for decoy_id in ids:
                if decoy_id is None:
                    continue
                record, deleted = remove_decoy(cfg, decoy_id, db=db, force=force)
                note = "file deleted" if deleted else "file kept (missing or changed; --force)"
                console.print(f"[green]✓[/] Removed {record.id} {record.path} - {note}")
            return

        if not template or not destination:
            raise _fail("usage: tripwire plant TEMPLATE DESTINATION (see --list)")
        if not yes:
            typer.confirm(
                f"Plant '{template}' at {destination}? Only do this on a device you own "
                "or are authorized to monitor.",
                abort=True,
            )
        record = plant_decoy(cfg, template, destination, label=label, db=db, force=force)
    except PlantError as exc:
        raise _fail(str(exc)) from None
    finally:
        db.close()
    console.print(f"[green]✓[/] Planted {record.kind} [bold]{record.id}[/] at {record.path}")
    if record.beacon:
        console.print(
            f"Beacon points to {cfg.server.public_url} - make sure `tripwire serve` is reachable."
        )


# --------------------------------------------------------------------- watch
async def _run_until_signal(engine: Engine) -> None:
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        with contextlib.suppress(NotImplementedError, RuntimeError):  # Windows
            loop.add_signal_handler(sig, stop.set)
    await engine.start()
    try:
        await stop.wait()
    finally:
        await engine.stop()


@app.command()
def watch(config: ConfigOpt = None) -> None:
    """Run the agent: watch decoys and send alerts (Ctrl-C to stop)."""
    cfg = _load(config)
    engine = _build_engine(cfg)
    if not engine.collectors:
        raise _fail("no collectors enabled in config")
    console.print(
        f"[bold]Watching[/] with {len(engine.collectors)} collector(s) and "
        f"{len(engine.channels)} alert channel(s). Ctrl-C to stop."
    )
    with contextlib.suppress(KeyboardInterrupt):
        asyncio.run(_run_until_signal(engine))


# -------------------------------------------------------------------- status
@app.command()
def status(config: ConfigOpt = None) -> None:
    """Show configuration, planted decoys and incident count."""
    cfg = _load(config)
    db = _open_db(cfg)
    console.print(f"[bold]Host:[/] {cfg.host_name}")
    console.print(f"[bold]Data dir:[/] {cfg.resolved_data_dir}")
    console.print(f"[bold]Public URL:[/] {cfg.server.public_url}")
    console.print(f"[bold]Incidents:[/] {db.count_incidents()}")
    for kind, items in (("Collectors", cfg.collectors), ("Alerts", cfg.alerts)):
        names = [f"{p.instance_name}({p.type}){'' if p.enabled else ' [dim]off[/]'}" for p in items]
        console.print(f"[bold]{kind}:[/] {', '.join(names) or '-'}")
    table = Table(title="Planted decoys")
    for col in ("ID", "Template", "Path", "Present", "Label"):
        table.add_column(col)
    for d in load_manifest(cfg.manifest_path).decoys:
        present = "[green]yes[/]" if Path(d.path).exists() else "[red]missing[/]"
        table.add_row(d.id, d.kind, d.path, present, d.label)
    console.print(table)
    db.close()


# ----------------------------------------------------------------- incidents
@app.command()
def incidents(
    limit: Annotated[int, typer.Option(min=1, help="Max rows")] = 20,
    show: Annotated[str | None, typer.Option(help="Print the full report of one incident")] = None,
    as_json: Annotated[bool, typer.Option("--json", help="JSON output")] = False,
    config: ConfigOpt = None,
) -> None:
    """List recent incidents (decrypted locally)."""
    cfg = _load(config)
    db = _open_db(cfg)
    try:
        if show:
            inc = db.get_incident(show)
            if inc is None:
                raise _fail(f"no incident {show}")
            console.print_json(json.dumps(inc.report()))
            return
        items = db.list_incidents(limit=limit)
    except DecryptionError as exc:
        raise _fail(str(exc)) from None
    finally:
        db.close()
    if as_json:
        console.print_json(json.dumps([i.report() for i in items]))
        return
    table = Table(title=f"Last {len(items)} incident(s)")
    for col in ("When (UTC)", "ID", "Kind", "Severity", "Summary"):
        table.add_column(col)
    for i in items:
        table.add_row(
            i.created_at.strftime("%Y-%m-%d %H:%M:%S"),
            i.id[:12],
            i.event.kind.value,
            i.event.severity.value,
            i.event.summary,
        )
    console.print(table)


# --------------------------------------------------------------------- serve
@app.command()
def serve(
    host: Annotated[str | None, typer.Option(help="Bind address (default from config)")] = None,
    port: Annotated[int | None, typer.Option(help="Bind port (default from config)")] = None,
    with_collectors: Annotated[
        bool, typer.Option(help="Also run local collectors in this process")
    ] = False,
    config: ConfigOpt = None,
) -> None:
    """Run the beacon server (token endpoint + signed report links)."""
    import uvicorn

    from tripwire.server.app import create_app

    cfg = _load(config)
    engine = _build_engine(cfg, with_collectors=with_collectors)
    uvicorn.run(
        create_app(engine),
        host=host or cfg.server.bind_host,
        port=port or cfg.server.bind_port,
        proxy_headers=cfg.server.trust_forwarded_for,
        server_header=False,
        log_level=cfg.logging.level.lower(),
    )


if __name__ == "__main__":  # pragma: no cover
    app()
