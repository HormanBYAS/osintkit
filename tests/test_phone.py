"""Pruebas de ubicación por código de área y confirmación de números."""

from __future__ import annotations

import unittest
from typing import Any
from unittest import mock

from osintkit.datasets import phone_area_codes, phone_area_codes_meta
from osintkit.modules import phone as phone_module


class _Response:
    def __init__(self, data: dict[str, Any]) -> None:
        self.status = 200
        self.ok = True
        self._data = data

    def json(self) -> dict[str, Any]:
        return self._data


class _Context:
    def __init__(self, target: str, data: dict[str, Any] | None = None) -> None:
        self.target = target
        self.kind = "phone"
        self.data = data or {}
        self.http = self

    def key(self, _name: str) -> str:
        return "clave-de-prueba"

    def get(self, *_args: Any, **_kwargs: Any) -> _Response:
        return _Response(self.data)


class PhoneAreaTests(unittest.TestCase):
    def test_dataset_has_example_and_metadata(self) -> None:
        areas = phone_area_codes()
        self.assertGreaterEqual(len(areas), 20)
        self.assertEqual(phone_area_codes_meta().get("count"), len(areas))
        villa = [item for item in areas if item.get("code") == "3544"]
        self.assertEqual(len(villa), 1)
        self.assertEqual(villa[0].get("city"), "Villa Dolores")
        self.assertEqual(villa[0].get("province"), "Córdoba")

    def test_infers_city_from_international_and_national_formats(self) -> None:
        for number in (
            "+54 3544 123456",
            "+543544123456",
            "+54 9 3544 123456",
            "+5493544123456",
            "3544-123456",
        ):
            with self.subTest(number=number):
                area = phone_module.infer_area(number)
                self.assertIsNotNone(area)
                assert area is not None
                self.assertEqual(area["code"], "3544")
                self.assertEqual(area["city"], "Villa Dolores")

    def test_infers_other_known_areas(self) -> None:
        self.assertEqual(
            (phone_module.infer_area("+54 11 1234 5678") or {}).get("city"),
            "Buenos Aires",
        )
        self.assertEqual(
            (phone_module.infer_area("+54 351 123 4567") or {}).get("city"),
            "Córdoba",
        )

    def test_unknown_or_short_numbers_have_no_area(self) -> None:
        self.assertIsNone(phone_module.infer_area("+54 9999 123456"))
        self.assertIsNone(phone_module.infer_area("123"))

    def test_phone_info_reports_area_and_city(self) -> None:
        findings = phone_module.phone_info(_Context("+54 3544 123456"), mock.Mock())
        values = [finding.value for finding in findings]
        titles = [finding.title for finding in findings]
        self.assertIn("Código de área", titles)
        self.assertTrue(any("Villa Dolores" in value for value in values), values)

    def test_national_number_is_not_mistaken_for_another_country(self) -> None:
        findings = phone_module.phone_info(_Context("3544-123456"), mock.Mock())
        values = [finding.value for finding in findings]
        self.assertTrue(any("Argentina" in value for value in values), values)
        self.assertFalse(any("Islandia" in value for value in values), values)

    def test_area_findings_use_geocoder_when_available(self) -> None:
        findings = phone_module._area_findings("+54 3544 123456", "Villa Dolores, Córdoba")
        city = [item for item in findings if item.title == "Ciudad"]
        self.assertEqual(len(city), 1)
        self.assertEqual(city[0].value, "Villa Dolores, Córdoba")
        self.assertEqual(city[0].data.get("source"), "phonenumbers")
        self.assertEqual(city[0].data.get("area_code"), "3544")


class RegistrationConfirmationTests(unittest.TestCase):
    def test_true_flags_are_detected(self) -> None:
        self.assertTrue(phone_module._is_true(True))
        self.assertTrue(phone_module._is_true("true"))
        self.assertTrue(phone_module._is_true("sí"))
        self.assertTrue(phone_module._is_true(1))
        self.assertFalse(phone_module._is_true(False))
        self.assertFalse(phone_module._is_true("false"))
        self.assertFalse(phone_module._is_true(None))

    def test_confirmation_finding_is_only_emitted_for_explicit_true(self) -> None:
        finding = phone_module._confirmation_finding("Numverify", {"valid": True}, ("valid",))
        self.assertIsNotNone(finding)
        assert finding is not None
        self.assertTrue(finding.data.get("registration_confirmed"))
        self.assertEqual(finding.data.get("provider"), "Numverify")
        self.assertIsNone(
            phone_module._confirmation_finding("Numverify", {"valid": False}, ("valid",))
        )
        self.assertIsNone(
            phone_module._confirmation_finding("Numverify", {}, ("valid",))
        )

    def test_numverify_marks_confirmation(self) -> None:
        findings = phone_module.phone_numverify(
            _Context("+54 3544 123456", {"valid": True, "country_name": "Argentina"}),
            mock.Mock(),
        )
        confirmed = [item for item in findings if item.data.get("registration_confirmed")]
        self.assertEqual(len(confirmed), 1)
        self.assertEqual(confirmed[0].data.get("provider"), "Numverify")

    def test_ipqualityscore_marks_active_number(self) -> None:
        findings = phone_module.phone_ipqualityscore(
            _Context("+54 3544 123456", {"active": True, "carrier": "Personal"}),
            mock.Mock(),
        )
        confirmed = [item for item in findings if item.data.get("registration_confirmed")]
        self.assertEqual(len(confirmed), 1)
        self.assertEqual(confirmed[0].data.get("provider"), "IPQualityScore")


if __name__ == "__main__":
    unittest.main()
