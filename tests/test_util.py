"""Pruebas de utilidades de detección, hashes y formato."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from osintkit.util import (
    detect_kind,
    file_hashes,
    is_domain,
    is_email,
    is_hash,
    is_ip,
    is_phone,
    normalize_domain,
    normalize_target,
    slugify,
)


class DetectionTests(unittest.TestCase):
    def test_domains(self) -> None:
        self.assertTrue(is_domain("example.com"))
        self.assertTrue(is_domain("sub.example.co.uk"))
        self.assertFalse(is_domain("1.1.1.1"))
        self.assertFalse(is_domain("sin_punto"))
        self.assertEqual(detect_kind("example.com"), "domain")
        self.assertEqual(detect_kind("https://example.com/ruta"), "url")

    def test_ip_email_hash(self) -> None:
        self.assertTrue(is_ip("8.8.8.8"))
        self.assertTrue(is_ip("2001:4860:4860::8888"))
        self.assertTrue(is_email("analista@example.com"))
        self.assertTrue(is_hash("d41d8cd98f00b204e9800998ecf8427e"))
        self.assertEqual(detect_kind("8.8.8.8"), "ip")
        self.assertEqual(detect_kind("analista@example.com"), "email")

    def test_phone_and_username(self) -> None:
        self.assertTrue(is_phone("+5491123456789"))
        self.assertEqual(detect_kind("+5491123456789"), "phone")
        self.assertEqual(detect_kind("analista_osint"), "username")
        self.assertEqual(detect_kind("texto con espacios"), "keyword")

    def test_normalize(self) -> None:
        self.assertEqual(normalize_domain("HTTPS://Example.COM/ruta"), "example.com")
        self.assertEqual(normalize_target(" Example.COM "), "example.com")
        self.assertEqual(slugify("ñandú / ejemplo"), "nandu-ejemplo")

    def test_file_detection(self) -> None:
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as handle:
            handle.write(b"contenido")
            path = Path(handle.name)
        try:
            self.assertEqual(detect_kind(str(path)), "file")
            hashes = file_hashes(path)
            self.assertEqual(len(hashes["sha256"]), 64)
            self.assertEqual(len(hashes["md5"]), 32)
        finally:
            path.unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()
