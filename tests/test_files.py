"""Pruebas de módulos de archivos (sin red)."""

from __future__ import annotations

import struct
import tempfile
import unittest
import zlib
from pathlib import Path

from osintkit.config import Config
from osintkit.core import Context
from osintkit.http import HttpClient
from osintkit.modules import files


def make_png(path: Path, text: str = "Autor: Analista") -> None:
    signature = b"\x89PNG\r\n\x1a\n"

    def chunk(kind: bytes, payload: bytes) -> bytes:
        return (
            struct.pack(">I", len(payload))
            + kind
            + payload
            + struct.pack(">I", zlib.crc32(kind + payload) & 0xFFFFFFFF)
        )

    ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
    raw = b"\x00\xff\x00\x00"
    idat = zlib.compress(raw)
    path.write_bytes(
        signature
        + chunk(b"IHDR", ihdr)
        + chunk(b"tEXt", text.encode("latin-1"))
        + chunk(b"IDAT", idat)
        + chunk(b"IEND", b"")
    )


def make_pdf(path: Path) -> None:
    body = b"""%PDF-1.4
1 0 obj << /Type /Catalog /Pages 2 0 R /OpenAction 3 0 R >> endobj
2 0 obj << /Type /Pages /Kids [4 0 R] /Count 1 >> endobj
3 0 obj << /S /JavaScript /JS (app.alert('x')) >> endobj
4 0 obj << /Type /Page /Parent 2 0 R /Annots [5 0 R] >> endobj
5 0 obj << /Type /Annot /Subtype /Link /A << /S /URI /URI (https://example.com/) >> >> endobj
6 0 obj << /Title (Informe de prueba) /Author (Analista OSINT)
 /Subject (Demostracion) /Creator (osintkit) /CreationDate (D:20260101120000Z) >> endobj
%%EOF
"""
    path.write_bytes(body)


class FileModuleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.cfg = Config(self.dir / "config.json")
        self.ctx = lambda target: Context(self.cfg, HttpClient(cache=None), str(target), "file")

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_hashes(self) -> None:
        path = self.dir / "muestra.bin"
        path.write_bytes(b"osintkit")
        findings = files.file_hash(self.ctx(path), None)
        values = {finding.title: finding.value for finding in findings}
        self.assertIn("SHA-256", values)
        self.assertEqual(len(values["SHA-256"]), 64)
        self.assertEqual(values["Tipo (firma)"], "texto")

    def test_png_metadata(self) -> None:
        path = self.dir / "imagen.png"
        make_png(path)
        findings = files.exif_metadata(self.ctx(path), None)
        text = "\n".join(f"{f.title}={f.value}" for f in findings)
        self.assertIn("PNG", text)
        self.assertIn("Autor: Analista", text)

    def test_pdf_info(self) -> None:
        path = self.dir / "documento.pdf"
        make_pdf(path)
        findings = files.pdf_info(self.ctx(path), None)
        values = {finding.title: finding.value for finding in findings}
        self.assertEqual(values.get("Título"), "Informe de prueba")
        self.assertEqual(values.get("Autor"), "Analista OSINT")
        self.assertEqual(values.get("JavaScript embebido"), "sí")
        self.assertEqual(values.get("Páginas"), "1")
        self.assertTrue(any(f.url == "https://example.com/" for f in findings))

    def test_strings_and_secrets(self) -> None:
        path = self.dir / "binario.bin"
        path.write_bytes(
            b"\x00\x01 contacto@example.com https://example.com/ruta "
            b"AKIAABCDEFGHIJKLMNOP -----BEGIN RSA PRIVATE KEY-----"
        )
        findings = files.strings_extract(self.ctx(path), None)
        joined = "\n".join(f"{f.title} {f.value}" for f in findings)
        self.assertIn("contacto@example.com", joined)
        self.assertIn("https://example.com/ruta", joined)
        self.assertIn("token AWS", joined)

    def test_missing_file(self) -> None:
        findings = files.file_hash(self.ctx(self.dir / "no-existe"), None)
        self.assertEqual(findings[0].level, "warn")


if __name__ == "__main__":
    unittest.main()
