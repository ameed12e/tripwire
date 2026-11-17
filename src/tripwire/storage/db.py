"""SQLite storage.

Only the minimum metadata needed for listing and filtering is stored in
plaintext (id, timestamp, kind, severity, decoy id). The full incident report,
including summary, paths, IPs and user agents, is Fernet-encrypted.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from tripwire.core.events import Incident
from tripwire.storage.crypto import Cipher

SCHEMA_VERSION = 1

_MIGRATIONS: dict[int, str] = {
    1: """
    CREATE TABLE incidents (
        id          TEXT PRIMARY KEY,
        created_at  TEXT NOT NULL,
        kind        TEXT NOT NULL,
        severity    TEXT NOT NULL,
        decoy_id    TEXT,
        payload     BLOB NOT NULL
    );
    CREATE INDEX idx_incidents_created ON incidents(created_at);
    CREATE TABLE beacon_tokens (
        decoy_id    TEXT PRIMARY KEY,
        label       BLOB NOT NULL,
        created_at  TEXT NOT NULL
    );
    """,
}


@dataclass(frozen=True)
class IncidentRow:
    id: str
    created_at: datetime
    kind: str
    severity: str
    decoy_id: str | None


class Database:
    def __init__(self, path: Path | str, cipher: Cipher) -> None:
        self.path = Path(path)
        self._cipher = cipher
        self._lock = threading.Lock()
        if str(path) != ":memory:":
            self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(path), check_same_thread=False, isolation_level=None)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA foreign_keys=ON")
            self._migrate()

    # ------------------------------------------------------------------ infra
    @contextmanager
    def _tx(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                yield self._conn
            except BaseException:
                self._conn.execute("ROLLBACK")
                raise
            else:
                self._conn.execute("COMMIT")

    def _migrate(self) -> None:
        current = int(self._conn.execute("PRAGMA user_version").fetchone()[0])
        for version in range(current + 1, SCHEMA_VERSION + 1):
            self._conn.executescript(
                f"BEGIN; {_MIGRATIONS[version]} PRAGMA user_version={version}; COMMIT;"
            )

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    # -------------------------------------------------------------- incidents
    def add_incident(self, incident: Incident) -> None:
        payload = self._cipher.encrypt(json.dumps(incident.report()).encode("utf-8"))
        with self._tx() as conn:
            conn.execute(
                "INSERT INTO incidents (id, created_at, kind, severity, decoy_id, payload)"
                " VALUES (?, ?, ?, ?, ?, ?)",
                (
                    incident.id,
                    incident.created_at.isoformat(),
                    incident.event.kind.value,
                    incident.event.severity.value,
                    incident.event.decoy_id,
                    payload,
                ),
            )

    def get_incident(self, incident_id: str) -> Incident | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT payload FROM incidents WHERE id = ?", (incident_id,)
            ).fetchone()
        if row is None:
            return None
        return Incident.model_validate_json(self._cipher.decrypt(row["payload"]))

    def list_incidents(self, limit: int = 50, offset: int = 0) -> list[Incident]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT payload FROM incidents ORDER BY created_at DESC LIMIT ? OFFSET ?",
                (limit, offset),
            ).fetchall()
        return [Incident.model_validate_json(self._cipher.decrypt(r["payload"])) for r in rows]

    def list_incident_rows(self, limit: int = 50) -> list[IncidentRow]:
        """Plaintext metadata only (no decryption needed)."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT id, created_at, kind, severity, decoy_id FROM incidents"
                " ORDER BY created_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [
            IncidentRow(
                id=r["id"],
                created_at=datetime.fromisoformat(r["created_at"]),
                kind=r["kind"],
                severity=r["severity"],
                decoy_id=r["decoy_id"],
            )
            for r in rows
        ]

    def count_incidents(self) -> int:
        with self._lock:
            return int(self._conn.execute("SELECT COUNT(*) FROM incidents").fetchone()[0])

    def delete_incident(self, incident_id: str) -> bool:
        with self._tx() as conn:
            cur = conn.execute("DELETE FROM incidents WHERE id = ?", (incident_id,))
            return cur.rowcount > 0

    # ---------------------------------------------------------- beacon tokens
    def register_beacon(self, decoy_id: str, label: str, created_at: datetime) -> None:
        enc = self._cipher.encrypt(label.encode("utf-8"))
        with self._tx() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO beacon_tokens (decoy_id, label, created_at)"
                " VALUES (?, ?, ?)",
                (decoy_id, enc, created_at.isoformat()),
            )

    def beacon_label(self, decoy_id: str) -> str | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT label FROM beacon_tokens WHERE decoy_id = ?", (decoy_id,)
            ).fetchone()
        if row is None:
            return None
        return self._cipher.decrypt(row["label"]).decode("utf-8")

    def remove_beacon(self, decoy_id: str) -> None:
        with self._tx() as conn:
            conn.execute("DELETE FROM beacon_tokens WHERE decoy_id = ?", (decoy_id,))
