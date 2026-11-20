"""Pruebas de consistencia del catálogo."""

from __future__ import annotations

import unittest

from osintkit import catalog
from osintkit.core import MODULES, load_builtin_modules


class CatalogTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        load_builtin_modules()

    def test_validation_is_clean(self) -> None:
        self.assertEqual(catalog.validate_catalog(), [])

    def test_unique_ids(self) -> None:
        ids = [tool.id for tool in catalog.TOOLS]
        self.assertEqual(len(ids), len(set(ids)))

    def test_all_modules_implemented(self) -> None:
        referenced = {tool.module for tool in catalog.TOOLS if tool.module}
        self.assertEqual(referenced - set(MODULES), set())

    def test_profiles_resolve(self) -> None:
        for kind in catalog.ALL:
            profile = catalog.resolve_profile(None, kind)
            self.assertIn(profile, catalog.PROFILES)
            tools = catalog.profile_tools(profile, kind)
            self.assertTrue(tools, f"perfil vacío para {kind}")

    def test_target_type_menu(self) -> None:
        kinds = [item[0] for item in catalog.TARGET_TYPES]
        self.assertEqual(kinds[0], "auto")
        self.assertEqual(set(kinds[1:]), set(catalog.ALL))
        for kind in catalog.ALL:
            self.assertTrue(catalog.profiles_for_kind(kind), kind)

    def test_catalog_has_breadth(self) -> None:
        self.assertGreaterEqual(len(catalog.TOOLS), 200)
        self.assertGreaterEqual(len(catalog.CATEGORIES), 10)
        self.assertGreaterEqual(len(MODULES), 70)

    def test_mass_username_and_phone_sources(self) -> None:
        mass = catalog.get_tool("username_mass")
        self.assertIsNotNone(mass)
        self.assertEqual(mass.module, "username_mass")
        phone_sources = [t for t in catalog.TOOLS if t.id.startswith("phone_src_")]
        self.assertGreaterEqual(len(phone_sources), 60)
        profile = catalog.PROFILES["username"]
        self.assertIn("username_mass", profile["tools"])

    def test_mass_email_uses_username_database(self) -> None:
        mass = catalog.get_tool("email_mass")
        self.assertIsNotNone(mass)
        self.assertEqual(mass.module, "email_mass")
        self.assertIn("email", mass.kinds)
        self.assertNotIn("email_mass", catalog.PROFILES["email"]["tools"])
        self.assertIn("email_mass", catalog.PROFILES["email-deep"]["tools"])
        self.assertNotIn("email_mass", catalog.PROFILES["email-quick"]["tools"])
        self.assertIn("email_dork", catalog.PROFILES["email"]["tools"])
        self.assertIn("email_dork", catalog.PROFILES["email-deep"]["tools"])
        self.assertEqual(catalog.resolve_profile("gmail", "email"), "email")

    def test_core_ids_exist(self) -> None:
        for tool_id in (
            "dns_records", "http_probe", "ip_geo", "email_validate",
            "username_presence", "phone_info", "btc_address", "gleif_lei",
            "nvd_search", "ddg_search", "file_hash", "overpass_poi",
            "device_lifecycle", "device_advisories", "device_web",
            "plate_info", "plate_lookup", "plate_sources", "plate_search",
        ):
            self.assertIsNotNone(catalog.get_tool(tool_id), tool_id)

    def test_device_and_vehicle_catalog(self) -> None:
        lifecycle = catalog.get_tool("device_lifecycle")
        self.assertIsNotNone(lifecycle)
        self.assertEqual(lifecycle.module, "device_lifecycle")
        self.assertIn("device", lifecycle.kinds)

        lookup = catalog.get_tool("plate_lookup")
        self.assertIsNotNone(lookup)
        self.assertEqual(lookup.module, "plate_lookup")
        self.assertIn("plate", lookup.kinds)

        nvd = catalog.get_tool("nvd_search")
        self.assertIsNotNone(nvd)
        self.assertIn("device", nvd.kinds)

        self.assertIn("device", catalog.DEFAULT_PROFILES)
        self.assertIn("plate", catalog.DEFAULT_PROFILES)
        self.assertIn("device_lifecycle", catalog.PROFILES["device"]["tools"])
        self.assertIn("plate_lookup", catalog.PROFILES["plate"]["tools"])
        self.assertTrue(catalog.profiles_for_kind("device"))
        self.assertTrue(catalog.profiles_for_kind("plate"))
        self.assertEqual(catalog.resolve_profile("placa", "plate"), "plate")
        self.assertEqual(catalog.resolve_profile("dispositivo", "device"), "device")


if __name__ == "__main__":
    unittest.main()
