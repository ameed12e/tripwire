from __future__ import annotations

import sqlite3
from datetime import UTC, datetime
from pathlib import Path

import pytest

from tripwire.core.events import Event, EventKind, Incident, Severity
from tripwire.storage import Cipher, Database, DecryptionError, generate_key


def _incident(path: str = "/home/u/passwords.xlsx") -> Incident:
    return Incident(
        event=Event(
            kind=EventKind.FILE_ACCESSED,
            source="filesystem",
            summary=f"Decoy read: {path}",
            severity=Severity.HIGH,
            decoy_id="d1",
            path=path,
            details={"pid": 1234},
        )
    )


@pytest.fixture
def db(tmp_path: Path) -> Database:
    return Database(tmp_path / "t.db", Cipher(generate_key()))


def test_roundtrip(db: Database) -> None:
    inc = _incident()
    db.add_incident(inc)
    assert db.get_incident(inc.id) == inc
    assert db.count_incidents() == 1
    assert db.list_incidents()[0].id == inc.id
    row = db.list_incident_rows()[0]
    assert (row.kind, row.severity, row.decoy_id) == ("file_accessed", "high", "d1")


def test_payload_is_encrypted_at_rest(tmp_path: Path) -> None:
    db = Database(tmp_path / "t.db", Cipher(generate_key()))
    db.add_incident(_incident("/secret/marker-path-xyz"))
    db.close()
    raw = (tmp_path / "t.db").read_bytes()
    wal = tmp_path / "t.db-wal"
    if wal.exists():
        raw += wal.read_bytes()
    assert b"marker-path-xyz" not in raw
    conn = sqlite3.connect(tmp_path / "t.db")
    payload = conn.execute("SELECT payload FROM incidents").fetchone()[0]
    assert payload.startswith(b"gAAAA")  # Fernet token prefix


def test_wrong_key_fails(tmp_path: Path) -> None:
    db = Database(tmp_path / "t.db", Cipher(generate_key()))
    inc = _incident()
    db.add_incident(inc)
    db.close()
    other = Database(tmp_path / "t.db", Cipher(generate_key()))
    with pytest.raises(DecryptionError):
        other.get_incident(inc.id)


def test_invalid_key() -> None:
    with pytest.raises(ValueError):
        Cipher("not-a-key")


def test_ordering_and_delete(db: Database) -> None:
    first, second = _incident("/a"), _incident("/b")
    db.add_incident(first)
    db.add_incident(second)
    ids = [i.id for i in db.list_incidents()]
    assert ids == [second.id, first.id]
    assert db.delete_incident(first.id)
    assert not db.delete_incident(first.id)
    assert db.get_incident(first.id) is None


def test_beacon_registry(db: Database) -> None:
    db.register_beacon("abc", "Q3 salaries.docx on laptop", datetime.now(UTC))
    assert db.beacon_label("abc") == "Q3 salaries.docx on laptop"
    assert db.beacon_label("zzz") is None
    db.remove_beacon("abc")
    assert db.beacon_label("abc") is None


def test_reopen_keeps_schema(tmp_path: Path) -> None:
    key = generate_key()
    Database(tmp_path / "t.db", Cipher(key)).close()
    db = Database(tmp_path / "t.db", Cipher(key))
    db.add_incident(_incident())
    assert db.count_incidents() == 1
