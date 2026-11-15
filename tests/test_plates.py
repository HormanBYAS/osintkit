"""Pruebas de resolución de países, normalización y validación de placas."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from osintkit.config import Config
from osintkit.core import Context
from osintkit.modules.vehicle import plate_info, plate_lookup, plate_sources
from osintkit.plates import (
    compact_plate,
    country_label,
    country_official_links,
    normalize_plate,
    resolve_country,
    split_plate_country,
    validate_plate,
    vehicle_countries,
)
from osintkit.util import detect_kind


class PlateCountryTests(unittest.TestCase):
    def test_resolve_country_by_code_and_alias(self) -> None:
        self.assertEqual(resolve_country("ES")["code"], "ES")
        self.assertEqual(resolve_country("España")["code"], "ES")
        self.assertEqual(resolve_country("reino unido")["code"], "GB")
        self.assertEqual(resolve_country("UK")["code"], "GB")
        self.assertEqual(resolve_country("paises bajos")["code"], "NL")
        self.assertIsNone(resolve_country("Atlántida"))

    def test_dataset_and_labels(self) -> None:
        countries = vehicle_countries()
        self.assertGreaterEqual(len(countries), 35)
        self.assertEqual(country_label(resolve_country("NL")), "Países Bajos (NL)")
        self.assertTrue(country_official_links(resolve_country("GB")))

    def test_normalize_and_compact(self) -> None:
        self.assertEqual(normalize_plate("  45-mf-hv "), "45-MF-HV")
        self.assertEqual(compact_plate(" 45-mf-hv "), "45MFHV")
        self.assertEqual(compact_plate("AB 12 CDE"), "AB12CDE")

    def test_embedded_country(self) -> None:
        plate, country = split_plate_country("1234ABC ES")
        self.assertEqual(plate, "1234ABC")
        self.assertEqual(country["code"], "ES")

        plate, country = split_plate_country("ES 1234ABC")
        self.assertEqual(plate, "1234ABC")
        self.assertEqual(country["code"], "ES")

        plate, country = split_plate_country("1234ABC, Reino Unido")
        self.assertEqual(plate, "1234ABC")
        self.assertEqual(country["code"], "GB")

        plate, country = split_plate_country("1234 ABC Reino Unido")
        self.assertEqual(plate, "1234 ABC")
        self.assertEqual(country["code"], "GB")

    def test_explicit_country_wins_and_is_required(self) -> None:
        plate, country = split_plate_country("1234ABC", "NL")
        self.assertEqual(plate, "1234ABC")
        self.assertEqual(country["code"], "NL")

        plate, country = split_plate_country("1234ABC UK", "ES")
        self.assertEqual(plate, "1234ABC")
        self.assertEqual(country["code"], "ES")

        plate, country = split_plate_country("1234ABC")
        self.assertEqual(plate, "1234ABC")
        self.assertIsNone(country)

    def test_validation_is_orientative(self) -> None:
        self.assertEqual(validate_plate("1234 ABC", resolve_country("ES"))[0], True)
        self.assertEqual(validate_plate("AB12 CDE", resolve_country("GB"))[0], True)
        self.assertEqual(validate_plate("45-MF-HV", resolve_country("NL"))[0], True)
        self.assertEqual(validate_plate("1234 ABC", resolve_country("GB"))[0], False)
        self.assertIsNone(validate_plate("ABC123", None)[0])

    def test_auto_detection_conservative(self) -> None:
        self.assertEqual(detect_kind("1234ABC ES"), "plate")
        self.assertEqual(detect_kind("ES 1234ABC"), "plate")
        self.assertEqual(detect_kind("1234ABC, Reino Unido"), "plate")
        self.assertEqual(detect_kind("1234ABC"), "username")


class PlateModuleTests(unittest.TestCase):
    def _ctx(self, target: str, country: str = "NL") -> Context:
        with tempfile.TemporaryDirectory() as tmp:
            cfg = Config(Path(tmp) / "config.json")
        return Context(cfg, None, target, "plate", options={"country": country})  # type: ignore[arg-type]

    def test_plate_info(self) -> None:
        findings = plate_info(self._ctx("45-MF-HV"), None)
        by_title = {finding.title: finding for finding in findings}
        self.assertEqual(by_title["País"].value, "Países Bajos (NL)")
        self.assertIn("coincide", by_title["Validación orientativa"].value)
        self.assertIn("RDW", by_title["Consulta automática"].value)

    def test_plate_sources(self) -> None:
        findings = plate_sources(self._ctx("45-MF-HV"), None)
        urls = [finding.url for finding in findings if finding.url]
        self.assertTrue(any("rdw.nl" in url for url in urls))

    def test_dvla_without_key_is_a_warning(self) -> None:
        findings = plate_lookup(self._ctx("AB12 CDE", "GB"), None)
        by_title = {finding.title: finding for finding in findings}
        self.assertIn("DVLA_API_KEY", by_title["DVLA"].value)
        self.assertEqual(by_title["DVLA"].level, "warn")


if __name__ == "__main__":
    unittest.main()
