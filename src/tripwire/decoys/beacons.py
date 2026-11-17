"""Beacon decoys (honeytokens) that "phone home" when opened.

Every beacon only *references* a URL on your Tripwire server; the viewer
application fetches it as an ordinary remote resource (an image, a link). There
are no macros, scripts, exploits or executable content of any kind: nothing
runs on the opener's machine. Many viewers block remote content by default, so
treat beacons as a best-effort signal on top of the filesystem collector.
"""

from __future__ import annotations

import html
import io
from typing import ClassVar

from tripwire.decoys.base import DecoyTemplate, PlantError


def _need(url: str | None) -> str:
    if not url:
        raise PlantError("beacon decoys need a beacon URL")
    return url


class HtmlBeacon(DecoyTemplate):
    name: ClassVar[str] = "beacon-html"
    description: ClassVar[str] = "HTML document that loads a 1x1 remote image when opened"
    default_filename: ClassVar[str] = "Account-Recovery-Codes.html"
    beacon: ClassVar[bool] = True
    url_suffix: ClassVar[str] = ".png"

    def render(self, beacon_url: str | None) -> bytes:
        src = html.escape(_need(beacon_url), quote=True)
        return (
            "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">"
            "<title>Account recovery codes</title></head>\n<body>\n"
            "<h1>Account recovery codes</h1>\n"
            "<p>Store these codes somewhere safe. Each code can be used once.</p>\n"
            "<pre>4821-0937  7710-2284  3390-5512\n9014-6631  2286-7745  5503-1198</pre>\n"
            f'<img src="{src}" width="1" height="1" alt="">\n'
            "</body></html>\n"
        ).encode()


class DocxBeacon(DecoyTemplate):
    name: ClassVar[str] = "beacon-docx"
    description: ClassVar[str] = "Word document with an externally linked 1x1 image"
    default_filename: ClassVar[str] = "Salaries-2026-CONFIDENTIAL.docx"
    beacon: ClassVar[bool] = True
    url_suffix: ClassVar[str] = ".png"

    def render(self, beacon_url: str | None) -> bytes:
        from docx import Document
        from docx.opc.constants import RELATIONSHIP_TYPE as RT
        from docx.oxml import parse_xml
        from docx.oxml.ns import nsdecls

        url = _need(beacon_url)
        doc = Document()
        doc.add_heading("Salary review 2026 - CONFIDENTIAL", level=1)
        doc.add_paragraph("Draft figures for leadership review. Do not forward.")
        table = doc.add_table(rows=1, cols=3)
        for cell, text in zip(table.rows[0].cells, ("Employee", "Current", "Proposed"), strict=True):
            cell.text = text
        r_id = doc.part.relate_to(url, RT.IMAGE, is_external=True)
        px = 9525  # 1 pixel in EMU
        drawing = parse_xml(
            f"<w:drawing {nsdecls('w', 'wp', 'a', 'pic', 'r')}>"
            f'<wp:inline distT="0" distB="0" distL="0" distR="0">'
            f'<wp:extent cx="{px}" cy="{px}"/><wp:docPr id="1001" name="logo"/>'
            '<a:graphic><a:graphicData uri="http://schemas.openxmlformats.org/drawingml/2006/picture">'
            '<pic:pic><pic:nvPicPr><pic:cNvPr id="0" name="logo.png"/><pic:cNvPicPr/></pic:nvPicPr>'
            f'<pic:blipFill><a:blip r:link="{r_id}"/><a:stretch><a:fillRect/></a:stretch></pic:blipFill>'
            f'<pic:spPr><a:xfrm><a:off x="0" y="0"/><a:ext cx="{px}" cy="{px}"/></a:xfrm>'
            '<a:prstGeom prst="rect"><a:avLst/></a:prstGeom></pic:spPr>'
            "</pic:pic></a:graphicData></a:graphic></wp:inline></w:drawing>"
        )
        doc.add_paragraph().add_run()._r.append(drawing)
        buf = io.BytesIO()
        doc.save(buf)
        return buf.getvalue()


class PdfBeacon(DecoyTemplate):
    name: ClassVar[str] = "beacon-pdf"
    description: ClassVar[str] = "PDF whose open action is a plain URI (viewers usually ask first)"
    default_filename: ClassVar[str] = "Bank-Statement-Q3.pdf"
    beacon: ClassVar[bool] = True
    url_suffix: ClassVar[str] = ""

    def render(self, beacon_url: str | None) -> bytes:
        url = _need(beacon_url)
        if any(c in url for c in "()\\\r\n"):
            raise PlantError("beacon URL contains characters not allowed in a PDF string")
        text = b"BT /F1 14 Tf 72 720 Td (Quarterly statement - loading secure content...) Tj ET"
        objects = [
            b"<< /Type /Catalog /Pages 2 0 R /OpenAction 5 0 R >>",
            b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R"
            b" /Resources << /Font << /F1 6 0 R >> >> >>",
            b"<< /Length %d >>\nstream\n%s\nendstream" % (len(text), text),
            b"<< /Type /Action /S /URI /URI (" + url.encode("ascii") + b") >>",
            b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        ]
        out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
        offsets = []
        for i, obj in enumerate(objects, start=1):
            offsets.append(len(out))
            out += b"%d 0 obj\n%s\nendobj\n" % (i, obj)
        xref = len(out)
        out += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objects) + 1)
        for off in offsets:
            out += b"%010d 00000 n \n" % off
        out += b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (
            len(objects) + 1,
            xref,
        )
        return bytes(out)


class UrlShortcutBeacon(DecoyTemplate):
    name: ClassVar[str] = "beacon-url"
    description: ClassVar[str] = "Windows Internet Shortcut (.url) pointing at the beacon"
    default_filename: ClassVar[str] = "VPN Admin Portal.url"
    beacon: ClassVar[bool] = True
    url_suffix: ClassVar[str] = ""

    def render(self, beacon_url: str | None) -> bytes:
        url = _need(beacon_url)
        if "\n" in url or "\r" in url:
            raise PlantError("invalid beacon URL")
        return f"[InternetShortcut]\r\nURL={url}\r\n".encode()


TEMPLATES: list[type[DecoyTemplate]] = [HtmlBeacon, DocxBeacon, PdfBeacon, UrlShortcutBeacon]
