"""Best-effort "who touched it" snapshot taken when an incident fires.

Everything here is read-only and local: we look at this host's own process
table, login sessions and sockets. Each probe is independent and never raises;
anything the OS refuses (e.g. Android blocks socket listing for apps) is
reported as unavailable instead.
"""

from __future__ import annotations

import getpass
import ipaddress
import os
from collections.abc import Callable
from typing import Any

import psutil

MAX_PROCS_SCANNED = 2000
TOP_CONNECTIONS = 3
UNAVAILABLE = "unavailable"


def _current_user() -> str:
    try:
        return getpass.getuser()
    except Exception:
        return "unknown"


def _openers(path: str | None) -> list[dict[str, Any]] | str:
    """Processes that currently have ``path`` open (excluding ourselves)."""
    if not path:
        return []
    try:
        target = os.path.realpath(path)
    except OSError:
        target = path
    me = os.getpid()
    found: list[dict[str, Any]] = []
    denied = 0
    for i, proc in enumerate(psutil.process_iter(["pid", "name", "username"])):
        if i >= MAX_PROCS_SCANNED or len(found) >= 3:
            break
        if proc.info["pid"] == me:
            continue
        try:
            files = proc.open_files()
        except (psutil.AccessDenied, psutil.ZombieProcess):
            denied += 1
            continue
        except (psutil.NoSuchProcess, OSError):
            continue
        if any(f.path == target for f in files):
            found.append(
                {
                    "pid": proc.info["pid"],
                    "name": proc.info["name"] or "?",
                    "user": proc.info.get("username") or "?",
                }
            )
    if not found and denied:
        return UNAVAILABLE
    return found


def _sessions() -> list[dict[str, Any]] | str:
    try:
        users = psutil.users()
    except Exception:
        return UNAVAILABLE
    return [{"user": u.name, "terminal": u.terminal or "", "host": u.host or ""} for u in users]


def _is_local(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip.split("%", 1)[0])
    except ValueError:
        return False
    return addr.is_loopback or addr.is_unspecified


def _connections() -> list[dict[str, Any]] | str:
    """Established outbound TCP connections, most common remote first."""
    try:
        conns = psutil.net_connections(kind="inet")
    except Exception:
        return UNAVAILABLE
    counts: dict[tuple[str, int, int | None], int] = {}
    for c in conns:
        if c.status != psutil.CONN_ESTABLISHED or not c.raddr:
            continue
        ip, port = c.raddr.ip, c.raddr.port
        if _is_local(ip):
            continue
        key = (ip, port, c.pid)
        counts[key] = counts.get(key, 0) + 1
    names: dict[int, str] = {}
    out: list[dict[str, Any]] = []
    for (ip, port, pid), _ in sorted(counts.items(), key=lambda kv: -kv[1])[:TOP_CONNECTIONS]:
        name = "?"
        if pid is not None:
            if pid not in names:
                try:
                    names[pid] = psutil.Process(pid).name()
                except Exception:
                    names[pid] = "?"
            name = names[pid]
        out.append({"ip": ip, "port": port, "pid": pid, "process": name})
    return out


def snapshot(path: str | None) -> dict[str, Any]:
    """Collect host context for an incident. Never raises."""
    ctx: dict[str, Any] = {"local_user": _current_user()}
    probes: dict[str, Callable[[], object]] = {
        "processes": lambda: _openers(path),
        "sessions": _sessions,
        "connections": _connections,
    }
    for key, probe in probes.items():
        try:
            ctx[key] = probe()
        except Exception:
            ctx[key] = UNAVAILABLE
    return ctx
