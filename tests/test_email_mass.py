"""Pruebas de la búsqueda masiva de emails y Gmail."""

from __future__ import annotations

import unittest
from unittest.mock import patch

from osintkit.modules import email_mass
from osintkit.modules.email_mass import _email_alias


class EmailMassTests(unittest.TestCase):
    def test_plain_email_uses_local_part(self) -> None:
        self.assertEqual(_email_alias("analista@example.com"), "analista")

    def test_gmail_plus_tag_is_removed(self) -> None:
        self.assertEqual(_email_alias("analista+osint@gmail.com"), "analista")

    def test_googlemail_and_case_are_supported(self) -> None:
        self.assertEqual(_email_alias("Analista+prueba@GoogleMail.com"), "Analista")

    def test_plus_is_kept_for_non_gmail_domains(self) -> None:
        self.assertEqual(_email_alias("analista+osint@example.com"), "analista+osint")

    def test_invalid_emails_return_empty_alias(self) -> None:
        for value in (
            "",
            "sin-arroba",
            "@example.com",
            "analista@",
            "a b@example.com",
            "a@b@example.com",
        ):
            self.assertEqual(_email_alias(value), "", value)

    def test_module_scans_alias_and_warns_about_collisions(self) -> None:
        class Ctx:
            target = "analista+osint@gmail.com"

        with patch.object(email_mass, "_mass_scan", return_value=[]) as scan:
            email_mass.email_mass(Ctx(), object())
        args, kwargs = scan.call_args
        self.assertEqual(args[2], "analista")
        self.assertEqual(kwargs["target_value"], "analista+osint@gmail.com")
        self.assertIn("no demuestran", kwargs["warning"])
        self.assertEqual(kwargs["found_label"], "Coincidencias por alias")
        self.assertTrue(kwargs["alias_profile"])

    def test_invalid_email_does_not_scan(self) -> None:
        class Ctx:
            target = "sin-arroba"

        with patch.object(email_mass, "_mass_scan", return_value=[]) as scan:
            findings = email_mass.email_mass(Ctx(), object())
        scan.assert_not_called()
        self.assertEqual(findings[0].level, "warn")


if __name__ == "__main__":
    unittest.main()
