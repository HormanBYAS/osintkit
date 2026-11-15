"""Detección local de sistemas operativos, distribuciones y dispositivos.

No hace red: solo normaliza el texto del objetivo y lo compara con el catálogo
de ``osintkit/data/device_products.json``.
"""

from __future__ import annotations

import re
import unicodedata
from typing import Any

from .datasets import device_products as _device_products


def fold_text(value: str) -> str:
    """Minúsculas sin acentos, con separadores simples."""
    text = unicodedata.normalize("NFKD", str(value or ""))
    text = "".join(char for char in text if not unicodedata.combining(char))
    text = text.casefold().replace("_", " ")
    return re.sub(r"\s+", " ", text).strip()


def match_text(value: str) -> str:
    """Normalización conservadora para comparar versiones y modelos."""
    text = fold_text(value)
    text = re.sub(r"[^a-z0-9.+-]+", " ", text)
    return re.sub(r"\s+", " ", text).strip()


def device_products() -> list[dict[str, Any]]:
    return _device_products()


def _alias_pattern(alias: str) -> re.Pattern[str]:
    return re.compile(r"(?<![a-z0-9])" + re.escape(alias) + r"(?![a-z0-9])")


def match_device_product(value: str) -> tuple[dict[str, Any] | None, str]:
    """Devuelve el producto detectado y el texto restante (versión/modelo).

    Se prueban primero los alias más largos para que «linux mint» no se quede
    en «linux» y «samsung galaxy» no se quede en «samsung».
    """
    normalized = match_text(value)
    if not normalized:
        return None, ""
    candidates: list[tuple[int, str, dict[str, Any]]] = []
    for product in device_products():
        aliases = product.get("aliases")
        if not isinstance(aliases, list):
            continue
        for alias in aliases:
            alias_norm = match_text(str(alias))
            if alias_norm:
                candidates.append((len(alias_norm), alias_norm, product))
    for _length, alias, product in sorted(candidates, key=lambda item: item[0], reverse=True):
        match = _alias_pattern(alias).search(normalized)
        if not match:
            continue
        remainder = (normalized[: match.start()] + " " + normalized[match.end() :]).strip()
        return product, remainder
    return None, normalized


def looks_like_device(value: str) -> bool:
    """True solo si hay un producto conocido y además versión, modelo o código.

    Un alias suelto como «ubuntu» puede ser un nombre de usuario; en ese caso el
    usuario debe indicar ``-k device`` explícitamente.
    """
    product, remainder = match_device_product(value)
    if not product or not remainder:
        return False
    if re.search(r"\d", remainder):
        return True
    family = str(product.get("family") or "")
    if family in {"macos", "android", "ios", "ipados", "windows"}:
        return bool(re.search(r"[a-z]", remainder))
    return len(remainder.split()) >= 1 and len(remainder) >= 3


def _label_pattern(label: str) -> re.Pattern[str]:
    return re.compile(r"(?<![a-z0-9])" + re.escape(label) + r"(?![a-z0-9])")


def match_cycle(cycles: list[dict[str, Any]], value: str) -> dict[str, Any] | None:
    """Busca el ciclo de endoflife.date que mejor encaja con el objetivo.

    Acepta versiones (24.04), nombres en clave (Sonoma), nombres parciales
    (Noble) y modelos de teléfono (Pixel 8 Pro, Galaxy S23). Si no hay
    coincidencia devuelve ``None``.
    """
    target = match_text(value)
    if not target:
        return None
    best: tuple[int, dict[str, Any]] | None = None
    for cycle in cycles:
        if not isinstance(cycle, dict):
            continue
        for key, weight in (
            ("cycle", 4),
            ("releaseLabel", 3),
            ("codename", 3),
            ("apiVersion", 2),
        ):
            label = match_text(str(cycle.get(key) or ""))
            if not label:
                continue
            if _label_pattern(label).search(target):
                score = weight * 100 + len(label)
                if best is None or score > best[0]:
                    best = (score, cycle)
                continue
            # Coincidencia parcial por palabras: «Noble Numbat» con «noble» o
            # «11 24H2 (E)» con «windows 11 24h2». Se ignoran palabras de una
            # letra y etiquetas demasiado genéricas.
            tokens = [
                token for token in re.findall(r"[a-z0-9]+(?:\.[a-z0-9]+)*", label)
                if len(token) >= 2
            ]
            matched = sum(1 for token in tokens if _label_pattern(token).search(target))
            if not matched:
                continue
            extra = max(0, len(tokens) - matched)
            score = weight * 20 + min(matched, 3) * 10 + len(label) - extra * 6
            if best is None or score > best[0]:
                best = (score, cycle)
    return best[1] if best else None


def product_aliases(product: dict[str, Any]) -> str:
    aliases = product.get("aliases")
    if not isinstance(aliases, list):
        return ""
    return ", ".join(str(alias) for alias in aliases)
