"""Búsqueda masiva de un email o Gmail en la base de usuarios."""

from __future__ import annotations

from typing import Any

from ..core import Context, Finding, module
from .base import f
from .username_mass import _mass_scan

_GMAIL_DOMAINS = {"gmail.com", "googlemail.com"}


def _email_alias(email: str) -> str:
    """Extrae el alias que se puede buscar en la base de usuarios.

    La base de Maigret usa ``{username}``; para un email se emplea la parte
    local. En Gmail/Googlemail se elimina el sufijo ``+etiqueta`` porque la
    cuenta es la misma. El resto del email no se usa para no enviar consultas
    con la dirección completa a sitios de perfiles.
    """
    email = email.strip()
    if email.count("@") != 1:
        return ""
    local, sep, domain = email.partition("@")
    if not sep or not local or not domain:
        return ""
    if any(char.isspace() for char in local + domain):
        return ""
    if domain.casefold() in _GMAIL_DOMAINS:
        local = local.split("+", 1)[0]
    return local.strip()


@module("email_mass")
def email_mass(ctx: Context, tool: Any) -> list[Finding]:
    """Comprueba la parte local de un email en más de 2.000 sitios."""
    email = ctx.target.strip()
    alias = _email_alias(email)
    if not alias:
        return [f("Email", "dirección de email no válida", "warn")]

    warning = (
        f"Se comprueba la parte local '{alias}' en sitios de usuario. "
        "Puede coincidir con otras personas y no demuestra que esos perfiles "
        "pertenezcan al titular del email."
    )
    return _mass_scan(
        ctx,
        tool,
        alias,
        target_label="Email",
        target_value=email,
        limit_setting="email_mass_limit",
        workers_setting="email_mass_workers",
        timeout_setting="email_mass_timeout",
        found_label="Perfiles posibles",
        warning=warning,
    )
