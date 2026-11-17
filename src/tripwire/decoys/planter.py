"""Plant and remove decoys, keeping the manifest and beacon registry in sync."""

from __future__ import annotations

import hashlib
import os
import secrets
import time
from pathlib import Path

from tripwire.core.config import TripwireConfig
from tripwire.decoys import beacons, files
from tripwire.decoys.base import (
    DecoyRecord,
    DecoyTemplate,
    PlantError,
    add_to_manifest,
    load_manifest,
    remove_from_manifest,
)
from tripwire.server.security import beacon_url, new_decoy_id
from tripwire.storage.db import Database

TEMPLATES: dict[str, type[DecoyTemplate]] = {
    t.name: t for t in [*files.TEMPLATES, *beacons.TEMPLATES]
}


def get_template(name: str) -> DecoyTemplate:
    try:
        return TEMPLATES[name]()
    except KeyError:
        raise PlantError(
            f"unknown decoy template '{name}' (available: {', '.join(sorted(TEMPLATES))})"
        ) from None


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _backdate(path: Path) -> None:
    """Give the decoy a plausible past timestamp.

    atime is set equal to mtime so that, on Linux ``relatime`` mounts, the next
    read updates atime (used by the optional atime check).
    """
    when = time.time() - 86400 * (30 + secrets.randbelow(330))
    os.utime(path, (when, when))


def plant(
    config: TripwireConfig,
    template_name: str,
    destination: Path,
    label: str | None = None,
    db: Database | None = None,
    force: bool = False,
) -> DecoyRecord:
    template = get_template(template_name)
    dest = destination.expanduser()
    if dest.is_dir():
        dest = dest / template.default_filename
    dest = dest.resolve()
    if dest.exists() and not force:
        raise PlantError(f"{dest} already exists; refusing to overwrite (use --force)")
    if not dest.parent.is_dir():
        raise PlantError(f"directory does not exist: {dest.parent}")

    decoy_id = new_decoy_id()
    url: str | None = None
    if template.beacon:
        key = config.signing_key().get_secret_value()
        suffix = getattr(template, "url_suffix", "")
        url = beacon_url(str(config.server.public_url), key, decoy_id, suffix)

    content = template.render(url)
    record = DecoyRecord(
        id=decoy_id,
        kind=template.name,
        path=str(dest),
        label=label or f"{template.name} at {dest}",
        beacon=template.beacon,
        sha256=_sha256(content),
    )
    dest.write_bytes(content)
    _backdate(dest)
    if template.beacon and db is not None:
        db.register_beacon(decoy_id, f"{record.label} [{config.host_name}]", record.created_at)
    add_to_manifest(config.manifest_path, record)
    return record


def remove(
    config: TripwireConfig, decoy_id: str, db: Database | None = None, force: bool = False
) -> tuple[DecoyRecord, bool]:
    """Remove a decoy. Returns (record, file_deleted).

    The file is only deleted if its content is unchanged since planting (so we
    never destroy something the owner replaced), unless ``force`` is set.
    """
    record = load_manifest(config.manifest_path).get(decoy_id)
    if record is None:
        raise PlantError(f"no planted decoy with id {decoy_id}")
    path = Path(record.path)
    deleted = False
    if path.is_file():
        unchanged = record.sha256 is None or _sha256(path.read_bytes()) == record.sha256
        if unchanged or force:
            path.unlink()
            deleted = True
    remove_from_manifest(config.manifest_path, decoy_id)
    if db is not None and record.beacon:
        db.remove_beacon(decoy_id)
    return record, deleted
