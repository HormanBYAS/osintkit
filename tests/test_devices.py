"""Pruebas de detección local de dispositivos y ciclos de vida."""

from __future__ import annotations

import unittest

from osintkit.devices import (
    device_products,
    looks_like_device,
    match_cycle,
    match_device_product,
)
from osintkit.util import detect_kind


class DeviceDetectionTests(unittest.TestCase):
    def test_product_matching(self) -> None:
        product, remainder = match_device_product("ubuntu 24.04")
        self.assertIsNotNone(product)
        self.assertEqual(product["name"], "Ubuntu")
        self.assertIn("24.04", remainder)

        product, remainder = match_device_product("macOS Sonoma")
        self.assertIsNotNone(product)
        self.assertEqual(product["name"], "macOS")
        self.assertEqual(remainder, "sonoma")

        product, _ = match_device_product("linux mint 21")
        self.assertIsNotNone(product)
        self.assertEqual(product["name"], "Linux Mint")

        product, _ = match_device_product("samsung galaxy s23")
        self.assertIsNotNone(product)
        self.assertEqual(product["name"], "Samsung Galaxy")

    def test_unknown_product(self) -> None:
        product, _ = match_device_product("usuario_normal")
        self.assertIsNone(product)

    def test_conservative_auto_detection(self) -> None:
        for value in (
            "ubuntu 24.04",
            "debian 12",
            "android 14",
            "macOS Sonoma",
            "iPhone 15",
            "pixel 8",
        ):
            self.assertTrue(looks_like_device(value), value)
            self.assertEqual(detect_kind(value), "device", value)
        self.assertFalse(looks_like_device("ubuntu"))
        self.assertFalse(looks_like_device("usuario_normal"))
        self.assertEqual(detect_kind("ubuntu"), "username")

    def test_dataset_has_breadth(self) -> None:
        products = device_products()
        self.assertGreaterEqual(len(products), 30)
        names = {str(item.get("name")) for item in products}
        self.assertIn("Ubuntu", names)
        self.assertIn("Android", names)
        self.assertIn("macOS", names)
        self.assertIn("Windows", names)

    def test_cycle_matching(self) -> None:
        cycles = [
            {
                "cycle": "24.04",
                "releaseLabel": "24.04 LTS",
                "codename": "Noble Numbat",
                "eol": "2029-05-31",
            },
            {
                "cycle": "22.04",
                "releaseLabel": "22.04 LTS",
                "codename": "Jammy Jellyfish",
                "eol": "2027-04-29",
            },
        ]
        selected = match_cycle(cycles, "ubuntu 24.04")
        self.assertIsNotNone(selected)
        self.assertEqual(selected["cycle"], "24.04")

        selected = match_cycle(cycles, "ubuntu noble")
        self.assertIsNotNone(selected)
        self.assertEqual(selected["cycle"], "24.04")

        self.assertIsNone(match_cycle(cycles, "openbsd 7.6"))

    def test_cycle_keeps_plus_variant(self) -> None:
        cycles = [
            {"cycle": "galaxy-s23", "releaseLabel": "Galaxy S23"},
            {"cycle": "galaxy-s23+", "releaseLabel": "Galaxy S23+"},
        ]
        selected = match_cycle(cycles, "samsung galaxy s23")
        self.assertIsNotNone(selected)
        self.assertEqual(selected["cycle"], "galaxy-s23")

        selected = match_cycle(cycles, "samsung galaxy s23+")
        self.assertIsNotNone(selected)
        self.assertEqual(selected["cycle"], "galaxy-s23+")


if __name__ == "__main__":
    unittest.main()
