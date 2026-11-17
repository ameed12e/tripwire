"""Event and incident models shared by collectors, storage, alerts and the server.

An ``Event`` is a raw observation emitted by a collector or the beacon server.
An ``Incident`` is an event that the engine accepted (after de-duplication) and
persisted; it carries an id and is what alert channels receive.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class EventKind(StrEnum):
    FILE_ACCESSED = "file_accessed"
    FILE_MODIFIED = "file_modified"
    FILE_DELETED = "file_deleted"
    FILE_MOVED = "file_moved"
    FILE_CREATED = "file_created"
    BEACON_HIT = "beacon_hit"
    CUSTOM = "custom"


class Severity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


def _utcnow() -> datetime:
    return datetime.now(UTC)


class Event(BaseModel):
    """A single raw observation."""

    kind: EventKind
    source: str = Field(description="Collector or component that produced the event")
    summary: str = Field(description="One-line human readable description")
    severity: Severity = Severity.HIGH
    timestamp: datetime = Field(default_factory=_utcnow)
    host: str | None = None
    decoy_id: str | None = None
    path: str | None = None
    details: dict[str, Any] = Field(default_factory=dict)

    def dedupe_key(self) -> str:
        """Key used to collapse bursts of identical events (e.g. many reads)."""
        base = f"{self.kind}:{self.decoy_id or self.path or self.summary}"
        client = self.details.get("client_ip")
        return f"{base}:{client}" if client else base


class Incident(BaseModel):
    """An accepted, persisted event."""

    id: str = Field(default_factory=lambda: uuid.uuid4().hex)
    event: Event
    created_at: datetime = Field(default_factory=_utcnow)

    def report(self) -> dict[str, Any]:
        """Full JSON-serialisable report."""
        return self.model_dump(mode="json")
