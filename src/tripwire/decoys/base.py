"""Decoy interface and the plant manifest.

Every planted decoy is recorded in a JSON manifest (in the data directory) so
that the filesystem collector knows what to watch and ``tripwire plant
--remove`` can cleanly undo everything. Nothing is ever hidden from the device
owner.
"""

from __future__ import annotations

import abc
import json
import os
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import ClassVar

from pydantic import BaseModel, Field


class DecoyRecord(BaseModel):
    id: str
    kind: str = Field(description="Decoy template name, e.g. 'aws-credentials' or 'beacon-html'")
    path: str
    label: str
    beacon: bool = False
    sha256: str | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class Manifest(BaseModel):
    version: int = 1
    decoys: list[DecoyRecord] = Field(default_factory=list)

    def by_path(self) -> dict[str, DecoyRecord]:
        return {str(Path(d.path).resolve()): d for d in self.decoys}

    def get(self, decoy_id: str) -> DecoyRecord | None:
        return next((d for d in self.decoys if d.id == decoy_id), None)


_manifest_lock = threading.Lock()


def load_manifest(path: Path) -> Manifest:
    if not path.is_file():
        return Manifest()
    return Manifest.model_validate_json(path.read_text(encoding="utf-8"))


def save_manifest(path: Path, manifest: Manifest) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(manifest.model_dump(mode="json"), indent=2), encoding="utf-8")
    os.replace(tmp, path)


def add_to_manifest(path: Path, record: DecoyRecord) -> None:
    with _manifest_lock:
        manifest = load_manifest(path)
        manifest.decoys = [d for d in manifest.decoys if d.path != record.path] + [record]
        save_manifest(path, manifest)


def remove_from_manifest(path: Path, decoy_id: str) -> DecoyRecord | None:
    with _manifest_lock:
        manifest = load_manifest(path)
        record = manifest.get(decoy_id)
        if record is not None:
            manifest.decoys = [d for d in manifest.decoys if d.id != decoy_id]
            save_manifest(path, manifest)
        return record


class PlantError(Exception):
    pass


class DecoyTemplate(abc.ABC):
    """A decoy generator. ``render`` must produce inert data (no macros/scripts)."""

    name: ClassVar[str]
    description: ClassVar[str]
    default_filename: ClassVar[str]
    beacon: ClassVar[bool] = False

    @abc.abstractmethod
    def render(self, beacon_url: str | None) -> bytes:
        """Return the file content. ``beacon_url`` is set for beacon decoys."""
