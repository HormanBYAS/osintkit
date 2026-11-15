"""Pruebas de los generadores de informes."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from osintkit.core import Finding, ScanResult, ToolResult
from osintkit.report import (
    render_console,
    render_html,
    render_json,
    render_markdown,
    write_reports,
)
from osintkit.util import iso_now


def sample_scan() -> ScanResult:
    ok = ToolResult(tool_id="dns_records", name="Registros DNS", category="dns")
    ok.status = "ok"
    ok.duration = 0.42
    ok.findings = [
        Finding(title="A", value="93.184.216.34", level="good"),
        Finding(title="Enlace", value="ver", level="link", url="https://example.com"),
    ]
    skipped = ToolResult(
        tool_id="shodan_host", name="Shodan", category="ip",
        status="skipped", skipped_reason="falta clave SHODAN_API_KEY",
    )
    failed = ToolResult(
        tool_id="virustotal", name="VirusTotal", category="threat",
        status="error", error="HTTP 429",
    )
    scan = ScanResult(target="example.com", kind="domain", profile="domain")
    scan.finished_at = iso_now()
    scan.duration = 3.5
    scan.results = [ok, skipped, failed]
    return scan


class ReportTests(unittest.TestCase):
    def test_json(self) -> None:
        payload = json.loads(render_json(sample_scan()))
        self.assertEqual(payload["target"], "example.com")
        self.assertEqual(payload["summary"]["tools"], 3)
        self.assertEqual(payload["summary"]["findings"], 2)
        self.assertTrue(payload["final_summary"])
        self.assertTrue(
            any(item["title"] == "Direcciones IP encontradas" for item in payload["final_summary"])
        )
        self.assertTrue(any(item["title"] == "Enlaces destacados" for item in payload["final_summary"]))

    def test_markdown(self) -> None:
        text = render_markdown(sample_scan())
        self.assertIn("# Informe OSINT", text)
        self.assertIn("dns_records", text)
        self.assertIn("93.184.216.34", text)
        self.assertIn("https://example.com", text)
        self.assertIn("SHODAN_API_KEY", text)
        self.assertIn("## Resumen final", text)
        self.assertIn("Direcciones IP encontradas", text)

    def test_html_escapes(self) -> None:
        scan = sample_scan()
        scan.results[0].findings.append(
            Finding(title="<script>alert(1)</script>", value="<b>x</b>")
        )
        text = render_html(scan)
        self.assertNotIn("<script>alert(1)</script>", text)
        self.assertIn("&lt;script&gt;", text)
        self.assertIn("Resumen final", text)

    def test_console(self) -> None:
        text = render_console(sample_scan(), color=False)
        self.assertIn("INFORME · example.com", text)
        self.assertIn("Registros DNS", text)
        self.assertIn("93.184.216.34", text)
        self.assertIn("Perfil: domain", text)
        self.assertIn("RESUMEN FINAL", text)
        self.assertIn("Direcciones IP encontradas", text)
        self.assertIn("Enlaces destacados", text)

    def test_write_reports(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            paths = write_reports(sample_scan(), formats=["json", "md", "html"], directory=tmp)
            self.assertEqual(len(paths), 3)
            for path in paths:
                self.assertTrue(path.exists())
                self.assertGreater(path.stat().st_size, 100)
            self.assertTrue(any(path.suffix == ".json" for path in paths))
            self.assertTrue(all(isinstance(path, Path) for path in paths))


if __name__ == "__main__":
    unittest.main()
