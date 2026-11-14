"""Carga de todos los módulos internos de osintkit.

Importar este paquete registra cada función decorada con ``@module`` en
``osintkit.core.MODULES``. El orden de los imports no importa salvo por las
dependencias internas entre módulos.
"""

from __future__ import annotations

from . import (  # noqa: F401
    crypto,
    dns,
    email,
    files,
    ip,
    org,
    phone,
    search,
    threat,
    username,
    username_mass,
    web,
)

__all__ = [
    "crypto",
    "dns",
    "email",
    "files",
    "ip",
    "org",
    "phone",
    "search",
    "threat",
    "username",
    "username_mass",
    "web",
]
