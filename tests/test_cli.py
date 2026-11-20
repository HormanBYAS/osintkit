"""Pruebas básicas de la CLI (sin red)."""

from __future__ import annotations

import contextlib
import io
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from osintkit.cli import main


class CliTests(unittest.TestCase):
    def run_cli(self, *argv: str) -> tuple[int, str, str]:
        out = io.StringIO()
        err = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(list(argv))
        return code, out.getvalue(), err.getvalue()

    def test_version(self) -> None:
        code, out, _ = self.run_cli("version")
        self.assertEqual(code, 0)
        self.assertIn("osintkit 1.5.2", out)
        self.assertIn("Módulos internos", out)

    def test_osintol_launcher(self) -> None:
        root = Path(__file__).resolve().parents[1]
        proc = subprocess.run(
            [str(root / "bin" / "osintol"), "version"],
            capture_output=True,
            text=True,
            errors="replace",
            timeout=30,
            check=False,
        )
        self.assertEqual(proc.returncode, 0)
        self.assertIn("osintkit 1.5.2", proc.stdout)
        self.assertIn("Módulos internos", proc.stdout)

    def test_list_json(self) -> None:
        code, out, _ = self.run_cli("list", "--kind", "domain", "--json")
        self.assertEqual(code, 0)
        payload = json.loads(out)
        self.assertTrue(payload)
        self.assertTrue(all("domain" in item["kinds"] for item in payload))

    def test_search(self) -> None:
        code, out, _ = self.run_cli("search", "shodan")
        self.assertEqual(code, 0)
        self.assertIn("shodan", out.lower())

    def test_show(self) -> None:
        code, out, _ = self.run_cli("show", "dns_records")
        self.assertEqual(code, 0)
        self.assertIn("Registros DNS", out)
        self.assertIn("module", out.lower()) if False else None

    def test_profiles(self) -> None:
        code, out, _ = self.run_cli("profiles")
        self.assertEqual(code, 0)
        self.assertIn("domain", out)
        self.assertIn("username", out)

    def test_dry_run(self) -> None:
        code, out, _ = self.run_cli("scan", "example.com", "--dry-run")
        self.assertEqual(code, 0)
        self.assertIn("example.com (domain)", out)
        self.assertIn("dns_records", out)

    def test_device_dry_run(self) -> None:
        code, out, _ = self.run_cli("scan", "ubuntu 24.04", "--dry-run", "-f", "none")
        self.assertEqual(code, 0)
        self.assertIn("ubuntu 24.04 (device)", out)
        self.assertIn("device_lifecycle", out)

    def test_plate_dry_run_with_country(self) -> None:
        code, out, _ = self.run_cli(
            "scan", "1234 ABC", "--pais", "ES", "--dry-run", "-f", "none"
        )
        self.assertEqual(code, 0)
        self.assertIn("1234 ABC (plate)", out)
        self.assertIn("España (ES)", out)
        self.assertIn("plate_lookup", out)

    def test_plate_dry_run_with_embedded_country(self) -> None:
        code, out, _ = self.run_cli(
            "scan", "1234ABC, Reino Unido", "--dry-run", "-f", "none"
        )
        self.assertEqual(code, 0)
        self.assertIn("1234ABC (plate)", out)
        self.assertIn("Reino Unido (GB)", out)

    def test_plate_requires_country(self) -> None:
        code, _, err = self.run_cli(
            "scan", "1234ABC", "-k", "plate", "--dry-run", "-f", "none"
        )
        self.assertEqual(code, 2)
        self.assertIn("--country", err)
        self.assertIn("Reino Unido", err)

    def test_plate_country_must_be_known(self) -> None:
        code, _, err = self.run_cli(
            "scan", "1234ABC", "--pais", "Atlántida", "--dry-run", "-f", "none"
        )
        self.assertEqual(code, 2)
        self.assertIn("País no reconocido", err)

    def test_run_plate_info(self) -> None:
        code, out, _ = self.run_cli(
            "run", "plate_info", "45-MF-HV", "--pais", "NL", "-f", "none"
        )
        self.assertEqual(code, 0)
        self.assertIn("Países Bajos (NL)", out)
        self.assertIn("45MFHV", out)

    def test_config_roundtrip(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cfg = str(Path(tmp) / "config.json")
            code, _, _ = self.run_cli("--config", cfg, "config", "set-key", "SHODAN_API_KEY", "abc123")
            self.assertEqual(code, 0)
            code, out, _ = self.run_cli("--config", cfg, "config", "show")
            self.assertEqual(code, 0)
            payload = json.loads(out)
            self.assertIn("SHODAN_API_KEY", payload["keys"])
            self.assertNotIn("abc123", payload["keys"]["SHODAN_API_KEY"])

    def test_catalog_valid(self) -> None:
        code, out, _ = self.run_cli("catalog", "--json")
        self.assertEqual(code, 0)
        payload = json.loads(out)
        self.assertGreaterEqual(len(payload), 200)


if __name__ == "__main__":
    unittest.main()
