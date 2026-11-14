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
