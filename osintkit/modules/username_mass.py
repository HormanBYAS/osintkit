"""Enumeración masiva de usuarios y emails en la base incluida (2.000+ sitios)."""

from __future__ import annotations

import concurrent.futures
import re
import time
from typing import Any
from urllib.parse import quote

from ..core import Context, Finding, module
from ..datasets import username_sites, username_sites_meta
from ..http import HttpError, NetworkError
from ..util import truncate
from .base import f, fetch_title, join_limited
from .websearch import is_search_page, profile_label

_GLOBAL_NEGATIVES = (
    "user not found",
    "usuario no encontrado",
    "profile not found",
    "perfil no encontrado",
    "page not found",
    "no such user",
    "could not be found",
    "doesn't exist",
    "does not exist",
    "nobody on reddit goes by that name",
)

_LOGIN_MARKERS = (
    "sign in",
    "sign up",
    "log in",
    "login",
    "create account",
    "enable javascript",
    "access denied",
    "captcha",
)

_CHALLENGE_MARKERS = (
    "checking your browser",
    "just a moment",
    "verify you are human",
    "enable javascript and cookies",
    "cf-browser-verification",
    "challenge-platform",
    "cloudflare",
    "ddos protection",
    "attention required",
)


def _format(template: str, username: str) -> str:
    return str(template).replace("{username}", quote(username, safe=""))


def _regex_ok(site: dict[str, Any], username: str) -> bool:
    pattern = str(site.get("regex") or "").strip()
    if not pattern:
        return True
    try:
        return re.match(pattern, username) is not None
    except re.error:
        return True


def _markers(site: dict[str, Any], key: str) -> tuple[str, ...]:
    value = site.get(key)
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, list):
        return ()
    return tuple(str(item).casefold() for item in value if str(item).strip())


def _classify(
    site: dict[str, Any],
    *,
    status: int,
    text: str,
    final_url: str = "",
    probe_url: str = "",
) -> tuple[str, str]:
    """Devuelve ``(estado, detalle)`` para un sitio.

    ``estado`` es ``yes``, ``no`` o ``unknown``. La función es pura para poder
    probarla sin red. Los marcadores de Maigret se interpretan primero para
    evitar falsos positivos en páginas que devuelven 200 para usuarios que no
    existen.
    """
    if status in (404, 410):
        return "no", f"HTTP {status}"
    if status in (401, 403, 429):
        return "unknown", f"HTTP {status}"
    if status >= 500:
        return "unknown", f"HTTP {status}"

    body = (text or "")[:250_000]
    lower = body.casefold()
    absence = _markers(site, "absence")
    presence = _markers(site, "presence")

    for marker in absence:
        if marker and marker in lower:
            return "no", "marcador de no encontrado"
    for marker in _GLOBAL_NEGATIVES:
        if marker in lower:
            return "no", "marcador de no encontrado"

    if 200 <= status < 400 and any(marker in lower for marker in _CHALLENGE_MARKERS):
        return "unknown", "desafío anti-bot o JavaScript"

    if final_url and probe_url and final_url != probe_url and is_search_page(final_url):
        return "unknown", "redirigido a portada o búsqueda"

    check = str(site.get("check") or "message").strip().lower()
    ok = 200 <= status < 400
    title = truncate(fetch_title(body), 120)

    if check in {"status", "status_code"}:
        if ok:
            return "yes", title or f"HTTP {status}"
        return "unknown", f"HTTP {status}"

    if presence:
        if any(marker and marker in lower for marker in presence):
            return "yes", title or f"HTTP {status}"
        return "no", "sin marcador de perfil"

    if ok:
        # Algunos sitios solo declaran cadenas de ausencia. Si la página no
        # contiene ninguna, el perfil se considera presente.
        if any(marker in lower for marker in _LOGIN_MARKERS) and len(body) < 30_000:
            return "unknown", "muro de login/JavaScript"
        return "yes", title or f"HTTP {status}"
    return "unknown", f"HTTP {status}"


def _check_site(
    ctx: Context,
    site: dict[str, Any],
    username: str,
    *,
    timeout: float,
) -> tuple[str, str, str]:
    """Comprueba un sitio y devuelve ``(estado, detalle, url)``."""
    profile_url = _format(str(site.get("url") or ""), username)
    if not profile_url.startswith(("http://", "https://")):
        return "unknown", "URL inválida", profile_url
    probe_url = _format(str(site.get("probe") or site.get("url") or ""), username)
    if not probe_url.startswith(("http://", "https://")):
        probe_url = profile_url

    method = "HEAD" if site.get("head") else "GET"
    try:
        response = ctx.http.request(
            method,
            probe_url,
            timeout=timeout,
            retries=0,
            allow_cache=False,
            max_bytes=350_000,
        )
        if method == "HEAD" and response.status in (405, 501):
            response = ctx.http.get(
                probe_url,
                timeout=timeout,
                retries=0,
                allow_cache=False,
                max_bytes=350_000,
            )
    except (NetworkError, HttpError) as exc:
        return "unknown", truncate(str(exc), 100), profile_url

    state, detail = _classify(
        site,
        status=response.status,
        text=response.text,
        final_url=str(response.url or ""),
        probe_url=probe_url,
    )
    return state, detail, profile_url


def _mass_scan(
    ctx: Context,
    tool: Any,
    query: str,
    *,
    target_label: str,
    target_value: str,
    limit_setting: str,
    workers_setting: str,
    timeout_setting: str,
    found_label: str,
    warning: str = "",
) -> list[Finding]:
    """Ejecuta la base de sitios para un alias y devuelve hallazgos comunes."""
    query = query.strip()
    if not query:
        return [f(target_label, "objetivo vacío", "warn")]

    sites = username_sites()
    meta = username_sites_meta()
    if not sites:
        return [f("Base de sitios", "no se encontró username_sites.json", "bad")]

    requested = int(
        ctx.get("limit")
        or tool.options.get("limit")
        or ctx.cfg.int(limit_setting, 0)
        or 0
    )
    available = len(sites)
    if requested > 0:
        sites = sites[:requested]
    if available < 2000:
        return [
            f(
                "Base de sitios",
                f"solo hay {available} sitios disponibles; se requieren 2.000",
                "bad",
            )
        ]

    workers = int(
        ctx.get("workers") or ctx.cfg.int(workers_setting, 40) or 40
    )
    workers = max(1, min(workers, 120))
    timeout = float(
        ctx.get("request_timeout")
        or ctx.cfg.float(timeout_setting, 6.0)
        or 6.0
    )
    timeout = max(2.0, min(timeout, 30.0))
    deadline = time.monotonic() + max(15.0, float(ctx.timeout) - 5.0)

    findings: list[Finding] = [
        f(target_label, target_value, "info"),
    ]
    if query != target_value:
        findings.append(f("Alias comprobado", query, "info"))
    findings.extend(
        [
            f(
                "Base de sitios",
                f"{available} disponibles · fuente {meta.get('source', 'Maigret')} "
                f"({meta.get('license', 'MIT')})",
                "info",
            ),
            f("Sitios seleccionados", f"{len(sites)} de {available}", "info"),
        ]
    )
    if warning:
        findings.append(f("Aviso", warning, "warn"))

    found: list[tuple[str, str, str]] = []
    unknown: list[str] = []
    checked = 0
    omitted = 0
    cancelled = 0

    def work(site: dict[str, Any]) -> tuple[str, str, str, str]:
        name = str(site.get("name") or "sitio")
        if ctx.cancel.is_set() or time.monotonic() > deadline:
            return name, "cancelled", "", ""
        if not _regex_ok(site, query):
            return name, "omitted", "", ""
        state, detail, url = _check_site(ctx, site, query, timeout=timeout)
        return name, state, detail, url

    with concurrent.futures.ThreadPoolExecutor(
        max_workers=workers, thread_name_prefix="osintkit-mass"
    ) as pool:
        futures = {pool.submit(work, site): site for site in sites}
        for future in concurrent.futures.as_completed(futures):
            name, state, detail, url = future.result()
            if state == "cancelled":
                cancelled += 1
                continue
            if state == "omitted":
                omitted += 1
                continue
            checked += 1
            if state == "yes":
                found.append((name, url, detail))
            elif state == "unknown":
                unknown.append(name)

    found.sort(key=lambda item: (profile_label(item[1]) or item[0], item[0]))
    findings.append(f("Sitios comprobados", str(checked), "info"))
    findings.append(
        f(found_label, str(len(found)), "good" if found else "info")
    )
    if omitted:
        findings.append(f("Omitidos por formato", str(omitted), "info"))
    if cancelled:
        findings.append(
            f("Sin completar", f"{cancelled} por cancelación o tiempo límite", "warn")
        )
    if unknown:
        findings.append(
            f("Sin verificar", f"{len(unknown)} · {join_limited(unknown, 25)}", "warn")
        )
    for name, url, detail in found:
        findings.append(
            f(
                profile_label(url) or name,
                detail or url,
                "good",
                url=url,
                data={
                    "site": name,
                    "database": "Maigret",
                    "license": "MIT",
                    "query": query,
                },
            )
        )
    if not found:
        findings.append(
            f(
                "Resultado",
                f"no se encontró '{query}' en los {checked} sitios comprobados",
                "info",
            )
        )
    return findings


@module("username_mass")
def username_mass(ctx: Context, tool: Any) -> list[Finding]:
    """Comprueba el alias en más de 2.000 sitios de la base interna."""
    username = ctx.target.strip().lstrip("@")
    return _mass_scan(
        ctx,
        tool,
        username,
        target_label="Usuario",
        target_value=username,
        limit_setting="username_mass_limit",
        workers_setting="username_mass_workers",
        timeout_setting="username_mass_timeout",
        found_label="Cuentas encontradas",
    )
