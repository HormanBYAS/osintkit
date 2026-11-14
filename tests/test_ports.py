"""Pruebas de etiquetado de puertos y servicios."""

from __future__ import annotations

import unittest

from osintkit.ports import (
    annotate_port_line,
    as_port,
    describe_port,
    describe_ports,
    service_name,
)


class PortLabelTests(unittest.TestCase):
    def test_known_services(self) -> None:
        self.assertEqual(service_name(22), "SSH")
        self.assertEqual(service_name("443"), "HTTPS")
        self.assertEqual(service_name(3306), "MySQL")
        self.assertEqual(describe_port(22), "22: SSH")
        self.assertEqual(describe_port(443, "tcp", "https"), "443: HTTPS")

    def test_unknown_and_udp(self) -> None:
        self.assertEqual(service_name(45678), "desconocido")
        self.assertIn("desconocido", describe_port(45678))
        self.assertEqual(describe_port(53, "udp"), "53/udp: DNS")
        self.assertEqual(as_port("not-a-port"), None)

    def test_product_and_state(self) -> None:
        label = describe_port(22, "tcp", "ssh", "OpenSSH 8.9p1", "open")
        self.assertEqual(label, "22: SSH (OpenSSH 8.9p1) · open")

    def test_describe_ports(self) -> None:
        self.assertEqual(describe_ports([22, 80, 443]), "22: SSH, 80: HTTP, 443: HTTPS")
        self.assertIn("+2 más", describe_ports([22, 80, 443], limit=1))

    def test_annotate_nmap(self) -> None:
        self.assertEqual(
            annotate_port_line("22/tcp open ssh OpenSSH 8.9p1 Ubuntu"),
            "22: SSH (OpenSSH 8.9p1 Ubuntu) · open",
        )
        self.assertEqual(annotate_port_line("80/tcp open http"), "80: HTTP · open")

    def test_annotate_external_formats(self) -> None:
        self.assertEqual(annotate_port_line("1.2.3.4:22"), "1.2.3.4:22 (SSH)")
        self.assertEqual(
            annotate_port_line("Discovered open port 22/tcp on 1.2.3.4"),
            "Discovered open port 22/tcp on 1.2.3.4 · 22: SSH",
        )
        self.assertEqual(annotate_port_line("22"), "22: SSH")
        self.assertEqual(annotate_port_line("Nmap done"), "Nmap done")


if __name__ == "__main__":
    unittest.main()
