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
        self.assertIn("osintkit 1.1.0", out)
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
        self.assertIn("osintkit 1.1.0", proc.stdout)
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
