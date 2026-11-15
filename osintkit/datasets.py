"""Carga de bases de datos internas incluidas con el paquete.

Los archivos viven en ``osintkit/data`` y se leen una sola vez por proceso.
Se mantienen fuera del código para poder actualizarlos sin tocar la lógica.
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

DATA_DIR = Path(__file__).resolve().parent / "data"


@lru_cache(maxsize=8)
def _load(name: str) -> Any:
    path = DATA_DIR / name
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def username_sites() -> list[dict[str, Any]]:
    """Sitios de enumeración de usuarios, con marcadores de presencia."""
    data = _load("username_sites.json")
    sites = data.get("sites") if isinstance(data, dict) else None
    if not isinstance(sites, list):
        return []
    return [item for item in sites if isinstance(item, dict)]


def username_sites_meta() -> dict[str, Any]:
    data = _load("username_sites.json")
    if not isinstance(data, dict):
        return {}
    return {key: value for key, value in data.items() if key != "sites"}


def phone_sources() -> list[dict[str, Any]]:
    """Directorios y buscadores de teléfono para consulta manual."""
    data = _load("phone_sources.json")
    sources = data.get("sources") if isinstance(data, dict) else None
    if not isinstance(sources, list):
        return []
    return [item for item in sources if isinstance(item, dict)]


def phone_sources_meta() -> dict[str, Any]:
    data = _load("phone_sources.json")
    if not isinstance(data, dict):
        return {}
    return {key: value for key, value in data.items() if key != "sources"}


def device_products() -> list[dict[str, Any]]:
    """Sistemas operativos, distribuciones y dispositivos conocidos."""
    data = _load("device_products.json")
    products = data.get("products") if isinstance(data, dict) else None
    if not isinstance(products, list):
        return []
    return [item for item in products if isinstance(item, dict)]


def device_products_meta() -> dict[str, Any]:
    data = _load("device_products.json")
    if not isinstance(data, dict):
        return {}
    return {key: value for key, value in data.items() if key != "products"}


def vehicle_countries() -> list[dict[str, Any]]:
    """Países con formatos de placa, fuentes oficiales y APIs disponibles."""
    data = _load("vehicle_plates.json")
    countries = data.get("countries") if isinstance(data, dict) else None
    if not isinstance(countries, list):
        return []
    return [item for item in countries if isinstance(item, dict)]


def vehicle_countries_meta() -> dict[str, Any]:
    data = _load("vehicle_plates.json")
    if not isinstance(data, dict):
        return {}
    return {key: value for key, value in data.items() if key != "countries"}
