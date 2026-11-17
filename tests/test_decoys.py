from __future__ import annotations

import io
import zipfile
from pathlib import Path

import pytest

from tripwire.core.config import TripwireConfig
from tripwire.decoys.base import PlantError, load_manifest
from tripwire.decoys.planter import TEMPLATES, get_template, plant, remove
from tripwire.server.security import verify_beacon_token
from tripwire.storage import Cipher, Database

URL = "https://tw.example.test/t/0123456789abcdef0123456789abcdef.png"


def _db(config: TripwireConfig) -> Database:
    return Database(config.db_path, Cipher(config.fernet_key().get_secret_value()))


@pytest.mark.parametrize("name", sorted(TEMPLATES))
def test_every_template_renders(name: str) -> None:
    t = get_template(name)
    data = t.render(URL if t.beacon else None)
    assert data
    if t.beacon:
        if name == "beacon-docx":
            rels = zipfile.ZipFile(io.BytesIO(data)).read("word/_rels/document.xml.rels")
            assert URL.encode() in rels and b'TargetMode="External"' in rels
        else:
            assert URL.encode() in data


def test_beacons_contain_no_active_content() -> None:
    for name, cls in TEMPLATES.items():
        t = cls()
        data = t.render(URL if t.beacon else None).lower()
        for needle in (b"<script", b"/javascript", b"/js ", b"/launch", b"vbaproject", b"onload="):
            assert needle not in data, f"{name} contains {needle!r}"


def test_docx_has_no_macros() -> None:
    data = get_template("beacon-docx").render(URL)
    names = zipfile.ZipFile(io.BytesIO(data)).namelist()
    assert not any("vba" in n.lower() for n in names)


def test_pdf_structure() -> None:
    data = get_template("beacon-pdf").render(URL)
    assert data.startswith(b"%PDF-1.4") and data.rstrip().endswith(b"%%EOF")
    startxref = int(data.rsplit(b"startxref\n", 1)[1].split(b"\n")[0])
    assert data[startxref:].startswith(b"xref")


def test_beacon_requires_url() -> None:
    with pytest.raises(PlantError):
        get_template("beacon-html").render(None)


def test_unknown_template() -> None:
    with pytest.raises(PlantError, match="available"):
        get_template("nope")


def test_plant_file_decoy_and_remove(config: TripwireConfig, tmp_path: Path) -> None:
    rec = plant(config, "passwords", tmp_path, label="desk passwords")
    path = Path(rec.path)
    assert path.name == "passwords.txt" and path.is_file()
    assert path.stat().st_mtime < path.stat().st_ctime - 86400  # backdated
    assert load_manifest(config.manifest_path).get(rec.id) == rec
    with pytest.raises(PlantError, match="exists"):
        plant(config, "passwords", tmp_path)
    _, deleted = remove(config, rec.id)
    assert deleted and not path.exists()
    assert load_manifest(config.manifest_path).decoys == []


def test_remove_keeps_modified_file(config: TripwireConfig, tmp_path: Path) -> None:
    rec = plant(config, "env-file", tmp_path / ".env.prod")
    Path(rec.path).write_text("owner replaced this")
    _, deleted = remove(config, rec.id)
    assert not deleted and Path(rec.path).exists()


def test_plant_beacon_registers_token(
    config: TripwireConfig, tmp_path: Path, keys: tuple[str, str]
) -> None:
    db = _db(config)
    rec = plant(config, "beacon-html", tmp_path, label="recovery codes", db=db)
    content = Path(rec.path).read_text()
    token = content.split("/t/")[1].split(".png")[0]
    assert verify_beacon_token(keys[1], token) == rec.id
    assert content.count("https://tw.example.test/t/") == 1
    assert db.beacon_label(rec.id) == "recovery codes [test-host]"
    remove(config, rec.id, db=db)
    assert db.beacon_label(rec.id) is None


def test_plant_into_missing_dir(config: TripwireConfig, tmp_path: Path) -> None:
    with pytest.raises(PlantError, match="does not exist"):
        plant(config, "ssh-key", tmp_path / "nope" / "key")
