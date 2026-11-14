"""Pruebas de la base masiva de usuarios y del clasificador."""

from __future__ import annotations

import unittest

from osintkit import datasets
from osintkit.core import render_template
from osintkit.modules import username_mass


class UsernameMassTests(unittest.TestCase):
    def test_database_has_at_least_2000_sites(self) -> None:
        sites = datasets.username_sites()
        self.assertGreaterEqual(len(sites), 2000)
        self.assertTrue(all("{username}" in str(site.get("url", "")) for site in sites))
        meta = datasets.username_sites_meta()
        self.assertEqual(meta.get("license"), "MIT")

    def test_classifier_status_code(self) -> None:
        site = {"check": "status_code"}
        self.assertEqual(
            username_mass._classify(site, status=200, text="")[0], "yes"
        )
        self.assertEqual(
            username_mass._classify(site, status=404, text="")[0], "no"
        )
        self.assertEqual(
            username_mass._classify(site, status=403, text="")[0], "unknown"
        )

    def test_classifier_message_markers(self) -> None:
        site = {
            "check": "message",
            "presence": ["Profile of foo"],
            "absence": ["User not found"],
        }
        self.assertEqual(
            username_mass._classify(
                site, status=200, text="<h1>Profile of foo</h1>"
            )[0],
            "yes",
        )
        self.assertEqual(
            username_mass._classify(
                site, status=200, text="<h1>User not found</h1>"
            )[0],
            "no",
        )
        self.assertEqual(
            username_mass._classify(site, status=200, text="<h1>Welcome</h1>")[0],
            "no",
        )

    def test_classifier_rejects_antibot_pages(self) -> None:
        site = {"check": "status_code"}
        self.assertEqual(
            username_mass._classify(
                site, status=200, text="<title>Checking your browser</title>"
            )[0],
            "unknown",
        )

    def test_format_and_regex(self) -> None:
        site = {"regex": r"^[a-z0-9_]+$"}
        self.assertTrue(username_mass._regex_ok(site, "foo_123"))
        self.assertFalse(username_mass._regex_ok(site, "foo bar"))
        self.assertEqual(
            username_mass._format("https://example.com/{username}", "a b"),
            "https://example.com/a%20b",
        )

    def test_phone_sources_data(self) -> None:
        sources = datasets.phone_sources()
        self.assertGreaterEqual(len(sources), 60)
        self.assertTrue(all("{phone" in str(item.get("url", "")) for item in sources))

    def test_phone_template_placeholders(self) -> None:
        self.assertIn(
            "34600123456",
            render_template("https://wa.me/{phone_digits}", "+34 600 123 456", "phone"),
        )
        self.assertIn(
            "34+600",
            render_template("https://example.com/?q={phone_q}", "+34 600", "phone"),
        )


if __name__ == "__main__":
    unittest.main()
