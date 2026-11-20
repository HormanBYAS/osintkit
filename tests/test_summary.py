"""Pruebas del resumen final de IPs, datos técnicos y enlaces."""

from __future__ import annotations

import json
import unittest

from osintkit.core import Finding, ScanResult, ToolResult
from osintkit.report import (
    render_console,
    render_html,
    render_json,
    render_markdown,
)
from osintkit.summary import MAX_LINKS, final_findings


def make_scan(*findings: Finding, target: str = "ejemplo", kind: str = "phone") -> ScanResult:
    result = ToolResult(tool_id="prueba", name="Prueba", category=kind)
    result.status = "ok"
    result.findings = list(findings)
    scan = ScanResult(target=target, kind=kind, profile=kind)
    scan.results = [result]
    return scan


def titles(scan: ScanResult) -> list[str]:
    return [finding.title for finding in final_findings(scan)]


def by_title(scan: ScanResult, title: str) -> Finding:
    for finding in final_findings(scan):
        if finding.title == title:
            return finding
    raise AssertionError(f"no se encontró {title!r}")


class FinalSummaryTests(unittest.TestCase):
    def test_extracts_ipv4_and_ipv6_from_values_urls_and_data(self) -> None:
        scan = make_scan(
            Finding("Dirección", "8.8.8.8 y 10.0.0.1", "info"),
            Finding("Versión", "1.2.3", "info"),
            Finding(
                "Servicio",
                "consulta",
                "link",
                url="https://[2606:4700:4700::1111]/",
            ),
            Finding("Metadatos", "nada", "info", data={"nested": ["192.168.1.10"]}),
        )

        names = titles(scan)
        self.assertIn("IP 8.8.8.8", names)
        self.assertIn("IP 10.0.0.1", names)
        self.assertIn("IP 2606:4700:4700::1111", names)
        self.assertIn("IP 192.168.1.10", names)
        self.assertNotIn("IP 1.2.3", names)

        public_first = [name for name in names if name.startswith("IP ")]
        self.assertEqual(public_first[0], "IP 8.8.8.8")
        self.assertIn("IP 2606:4700:4700::1111", public_first[:3])

        header = by_title(scan, "Direcciones IP encontradas")
        self.assertIn("4 únicas", header.value)
        self.assertEqual(header.data["addresses"][0], "8.8.8.8")

    def test_no_ip_is_reported_explicitly(self) -> None:
        scan = make_scan(Finding("ASN", "AS64500", "info"))
        header = by_title(scan, "Direcciones IP encontradas")
        self.assertEqual(header.value, "ninguna en los resultados")
        self.assertNotIn("IP 0.0.0.0", titles(scan))
        text = render_console(scan, color=False)
        self.assertIn("RESUMEN FINAL", text)
        self.assertIn("ninguna en los resultados", text)

    def test_technical_details_are_unique(self) -> None:
        scan = make_scan(
            Finding("ASN", "AS64500 Ejemplo", "info"),
            Finding("ASN", "AS64500 Ejemplo", "info"),
            Finding("Operador", "Ejemplo Móvil", "info"),
            Finding("País", "España", "info"),
            Finding("Tipo de línea", "móvil", "info"),
        )
        final = final_findings(scan)
        self.assertEqual(sum(1 for item in final if item.title == "ASN"), 1)
        self.assertEqual(sum(1 for item in final if item.title == "Operador"), 1)
        self.assertEqual(sum(1 for item in final if item.title == "País"), 1)

    def test_links_rank_direct_profiles_and_dedupe(self) -> None:
        scan = make_scan(
            Finding(
                "Búsqueda manual",
                "DuckDuckGo",
                "link",
                url="https://duckduckgo.com/?q=ejemplo",
            ),
            Finding(
                "Enlace",
                "ficha",
                "link",
                url="https://example.com/ficha",
            ),
            Finding(
                "WhatsApp",
                "perfil directo",
                "good",
                url="https://wa.me/34600123456",
                data={"direct_profile": True},
            ),
            Finding(
                "WhatsApp duplicado",
                "otra fuente",
                "good",
                url="https://wa.me/34600123456/",
                data={"direct_profile": True},
            ),
            kind="keyword",
        )
        final = final_findings(scan)
        links = [item for item in final if item.url]
        self.assertEqual(links[0].url, "https://wa.me/34600123456")
        self.assertEqual(
            len({item.url.rstrip("/") for item in links}),
            len(links),
        )
        header = by_title(scan, "Enlaces destacados")
        self.assertIn("3 de 3", header.value)
        self.assertNotIn("DuckDuckGo", links[0].title)

    def test_link_limit_and_json_output(self) -> None:
        findings = [Finding("Servidor", "8.8.8.8", "info")]
        findings.extend(
            Finding(f"Perfil {index}", "ficha", "link", url=f"https://example.com/{index}")
            for index in range(MAX_LINKS + 5)
        )
        scan = make_scan(*findings, kind="keyword")
        final = final_findings(scan)
        links = [item for item in final if item.url]
        self.assertEqual(len(links), MAX_LINKS)
        self.assertIn(f"{MAX_LINKS} de {MAX_LINKS + 5}", by_title(scan, "Enlaces destacados").value)

        payload = json.loads(render_json(scan))
        self.assertIn("final_summary", payload)
        self.assertTrue(any(item["title"] == "Enlaces destacados" for item in payload["final_summary"]))
        self.assertTrue(any(item["title"].startswith("IP ") for item in payload["final_summary"]))


    def test_phone_summary_lists_every_page_and_identity(self) -> None:
        findings = [
            Finding("Nombre", "Ana Pérez", "info"),
            Finding("Nombre del país", "España", "info"),
            Finding("Dirección", "8.8.8.8", "info"),
        ]
        findings.extend(
            Finding(
                "Perfil",
                f"perfil {index}",
                "good",
                url=f"https://example.com/perfil/{index}",
                data={"direct_profile": True},
            )
            for index in range(15)
        )
        findings.append(
            Finding(
                "Foro",
                "mención pública",
                "link",
                url="https://foro.example/hilo/1",
            )
        )
        findings.append(
            Finding(
                "Directorio",
                "consulta manual",
                "link",
                url="https://directorio.example/buscar?q=+34600123456",
                data={"source_directory": True},
            )
        )
        findings.append(
            Finding(
                "WhatsApp · contacto directo",
                "contacto sin verificar",
                "link",
                url="https://wa.me/34600123456",
                data={"contact_link": True},
            )
        )
        findings.append(
            Finding(
                "Búsqueda manual",
                "DuckDuckGo",
                "link",
                url="https://duckduckgo.com/?q=%2B34600123456",
            )
        )
        scan = make_scan(*findings, target="+34 600 123 456", kind="phone")

        final = final_findings(scan)
        page_urls = [item.url for item in final if item.url]
        self.assertEqual(len(page_urls), 16)
        self.assertIn("https://example.com/perfil/14", page_urls)
        self.assertIn("https://foro.example/hilo/1", page_urls)
        self.assertNotIn("https://directorio.example/buscar?q=+34600123456", page_urls)
        self.assertNotIn("https://wa.me/34600123456", page_urls)
        self.assertNotIn("https://duckduckgo.com/?q=%2B34600123456", page_urls)

        header = by_title(scan, "Páginas y perfiles encontrados")
        self.assertEqual(header.data["pages"], 16)
        self.assertIn("16 únicos", header.value)
        self.assertIn("Ana Pérez", by_title(scan, "Nombre encontrado").value)
        self.assertNotIn("España", by_title(scan, "Nombre encontrado").value)
        self.assertEqual(by_title(scan, "IP encontrada").value, "8.8.8.8")
        self.assertNotIn("Enlaces destacados", titles(scan))

    def test_email_summary_only_lists_exact_email_pages(self) -> None:
        findings = [
            Finding("Email", "analista@gmail.com", "info"),
            Finding("Nombre", "Ana Pérez", "info"),
            Finding("Dirección", "2001:4860:4860::8888", "info"),
        ]
        findings.extend(
            Finding(
                "Sitio",
                f"perfil exacto {index}",
                "good",
                url=f"https://sitio{index}.example/analista",
                data={
                    "direct_profile": True,
                    "email_page": True,
                    "email_exact": True,
                },
            )
            for index in range(12)
        )
        findings.extend(
            Finding(
                "Sitio",
                f"alias {index}",
                "good",
                url=f"https://alias{index}.example/analista",
                data={"direct_profile": True, "alias_profile": True},
            )
            for index in range(8)
        )
        scan = make_scan(*findings, target="analista@gmail.com", kind="email")

        final = final_findings(scan)
        page_urls = [item.url for item in final if item.url]
        self.assertEqual(len(page_urls), 12)
        self.assertIn("https://sitio11.example/analista", page_urls)
        self.assertNotIn("https://alias0.example/analista", page_urls)
        self.assertIn("Ana Pérez", by_title(scan, "Nombre encontrado").value)
        self.assertEqual(by_title(scan, "IP encontrada").value, "2001:4860:4860::8888")
        self.assertIn("8", by_title(scan, "Coincidencias por alias").value)
        self.assertNotIn("Enlaces destacados", titles(scan))

        payload = json.loads(render_json(scan))
        json_urls = [
            item.get("url")
            for item in payload["final_summary"]
            if item.get("url")
        ]
        self.assertEqual(len(json_urls), 12)
        self.assertIn("https://sitio11.example/analista", json_urls)
        self.assertNotIn("https://alias0.example/analista", json_urls)

        for text in (
            render_console(scan, color=False),
            render_markdown(scan),
            render_html(scan),
        ):
            self.assertIn("https://sitio11.example/analista", text)
            self.assertIn("Páginas y perfiles encontrados", text)
            self.assertIn("Coincidencias por alias", text)

    def test_vehicle_and_device_technical_details(self) -> None:
        scan = make_scan(
            Finding("Vehículo", "HARLEY DAVIDSON FLHRSE5", "good"),
            Finding("Primera matriculación", "2012-12-11", "info"),
            Finding("Cilindrada", "1801 cm³", "info"),
            Finding("Ciclo detectado", "24.04 · Noble Numbat", "good"),
            Finding("Fin de vida", "2029-05-31", "good"),
            Finding("Última versión", "24.04.5", "info"),
            Finding("Fuente", "RDW", "link", url="https://opendata.rdw.nl/"),
            target="45-MF-HV",
            kind="plate",
        )
        names = titles(scan)
        for title in (
            "Vehículo",
            "Primera matriculación",
            "Cilindrada",
            "Ciclo detectado",
            "Fin de vida",
            "Última versión",
        ):
            self.assertIn(title, names)
        self.assertEqual(by_title(scan, "Direcciones IP encontradas").value, "ninguna en los resultados")


if __name__ == "__main__":
    unittest.main()
