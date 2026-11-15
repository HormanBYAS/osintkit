"""Utilidades locales para matrículas y países.

El kit no consulta datos personales ni titulares. Estas funciones solo
normalizan la entrada, validan el formato de manera orientativa y resuelven
fuentes oficiales del país.
"""

from __future__ import annotations

import re
from typing import Any

from .datasets import vehicle_countries as _vehicle_countries
from .devices import fold_text


def vehicle_countries() -> list[dict[str, Any]]:
    return _vehicle_countries()


def _country_keys(country: dict[str, Any]) -> list[str]:
    keys = [
        str(country.get("code") or ""),
        str(country.get("name") or ""),
    ]
    aliases = country.get("aliases")
    if isinstance(aliases, list):
        keys.extend(str(alias) for alias in aliases)
    return [fold_text(key) for key in keys if fold_text(key)]


def country_label(country: dict[str, Any] | None) -> str:
    if not country:
        return "—"
    code = str(country.get("code") or "").upper()
    name = str(country.get("name") or "").strip()
    if code and name:
        return f"{name} ({code})"
    return name or code or "—"


def resolve_country(value: str) -> dict[str, Any] | None:
    """Resuelve un código, nombre o alias de país sin distinguir acentos."""
    needle = fold_text(value)
    if not needle:
        return None
    for country in vehicle_countries():
        if needle in _country_keys(country):
            return country
    return None


def normalize_plate(value: str) -> str:
    """Mayúsculas, espacios simples y sin puntuación en los extremos."""
    text = re.sub(r"\s+", " ", str(value or "").upper()).strip()
    text = text.strip(" \t\r\n-.,;:()[]{}")
    return text


def compact_plate(value: str) -> str:
    """Forma compacta para APIs y búsquedas: solo A-Z y 0-9."""
    return re.sub(r"[^A-Z0-9]", "", normalize_plate(value))


def validate_plate(plate: str, country: dict[str, Any] | None) -> tuple[bool | None, str]:
    """Validación orientativa según el formato del país.

    Devuelve ``None`` cuando no hay patrón fiable; en ese caso no se debe
    presentar el resultado como inválido.
    """
    compact = compact_plate(plate)
    if not compact:
        return False, "la placa está vacía"
    if not country:
        return None, "sin país no se puede validar el formato"
    pattern = str(country.get("plate_regex") or "").strip()
    if not pattern:
        return None, "el país no tiene un formato validado"
    try:
        valid = bool(re.fullmatch(pattern, compact))
    except re.error:
        return None, "patrón de formato no disponible"
    if valid:
        return True, "coincide con el formato orientativo"
    example = str(country.get("example") or "").strip()
    if example:
        return False, f"no coincide con el formato orientativo; ejemplo: {example}"
    return False, "no coincide con el formato orientativo"


def split_plate_country(value: str, explicit_country: str = "") -> tuple[str, dict[str, Any] | None]:
    """Separa una placa de su país.

    Acepta ``1234ABC ES``, ``ES 1234ABC``, ``1234ABC, Reino Unido`` o un país
    indicado aparte con ``--country``. Si no se reconoce el país devuelve la
    placa tal cual y ``None``.
    """
    text = normalize_plate(value)
    explicit = resolve_country(explicit_country) if explicit_country.strip() else None
    if explicit:
        plate, _embedded = _split_tokens(text)
        return normalize_plate(plate), explicit

    plate, country = _split_tokens(text)
    if country:
        return normalize_plate(plate), country
    return text, None


def _split_tokens(text: str) -> tuple[str, dict[str, Any] | None]:
    if not text:
        return "", None
    # Separadores explícitos primero: permiten nombres de país con espacios.
    parts = [part.strip() for part in re.split(r"[|;/,]", text) if part.strip()]
    if len(parts) >= 2:
        for index, part in enumerate(parts):
            country = resolve_country(part)
            if not country:
                continue
            rest = " ".join(parts[:index] + parts[index + 1 :]).strip()
            if rest:
                return rest, country
    tokens = re.split(r"\s+", text)
    for size in (3, 2, 1):
        if len(tokens) <= size:
            continue
        left = " ".join(tokens[:size])
        right = " ".join(tokens[size:]).strip()
        country = resolve_country(left)
        if country and right:
            return right, country
        right_size = " ".join(tokens[-size:])
        left_size = " ".join(tokens[:-size]).strip()
        country = resolve_country(right_size)
        if country and left_size:
            return left_size, country
    return text, None


def country_official_links(country: dict[str, Any] | None) -> list[dict[str, str]]:
    if not country:
        return []
    official = country.get("official")
    if not isinstance(official, list):
        return []
    links: list[dict[str, str]] = []
    for item in official:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or "").strip()
        url = str(item.get("url") or "").strip()
        if not name or not url:
            continue
        links.append(
            {
                "name": name,
                "url": url,
                "description": str(item.get("description") or "").strip(),
            }
        )
    return links


def plate_search_query(plate: str, country: dict[str, Any] | None, suffix: str = "") -> str:
    compact = compact_plate(plate)
    display = normalize_plate(plate)
    name = str((country or {}).get("name") or "").strip()
    terms = [f'"{display}"', f'"{compact}"']
    if name:
        terms.append(f'"{name}"')
    if suffix:
        terms.append(suffix)
    return " ".join(terms)
