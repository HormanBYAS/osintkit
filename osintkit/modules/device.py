"""Módulos de dispositivos: ciclo de vida, avisos, CVEs y búsqueda web."""

from __future__ import annotations

from datetime import date
from typing import Any
from urllib.parse import quote_plus

from ..core import Context, Finding, module
from ..devices import match_cycle, match_device_product
from ..util import truncate
from .base import f, safe_json
from .websearch import is_profile_url, profile_label, resolve_direct, search_url


def _date(value: Any) -> date | None:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        return date.fromisoformat(value.strip()[:10])
    except ValueError:
        return None


def _fmt_date(value: Any) -> str:
    if value is False or value is None:
        return "—"
    if value is True:
        return "sí (sin fecha)"
    parsed = _date(value)
    return parsed.isoformat() if parsed else str(value)


def _eol_state(value: Any) -> tuple[str, str]:
    if value is False:
        return "sin fecha de fin anunciada", "good"
    if value is True:
        return "fin de vida anunciado", "bad"
    parsed = _date(value)
    if not parsed:
        return "sin datos", "info"
    if parsed < date.today():
        return f"fin de vida desde {parsed.isoformat()}", "bad"
    return f"soporte hasta {parsed.isoformat()}", "good"


def _cycle_label(cycle: dict[str, Any]) -> str:
    label = str(cycle.get("releaseLabel") or cycle.get("cycle") or "").strip()
    codename = str(cycle.get("codename") or "").strip()
    if codename and codename.casefold() not in label.casefold():
        return f"{label} · {codename}"
    return label or "—"


def _recent_cycles(cycles: list[dict[str, Any]], limit: int = 8) -> str:
    rows: list[str] = []
    for cycle in cycles[:limit]:
        label = str(cycle.get("cycle") or "").strip()
        eol = cycle.get("eol")
        if eol is False or eol is None:
            state = "activo"
        elif eol is True:
            state = "EOL"
        else:
            state = f"EOL {str(eol)[:10]}"
        rows.append(f"{label} ({state})" if label else state)
    return ", ".join(rows)


def _product_finding(product: dict[str, Any]) -> Finding:
    name = str(product.get("name") or "Producto")
    vendor = str(product.get("vendor") or "—")
    family = str(product.get("family") or "—")
    return f("Producto", f"{name} · {vendor} · {family}", "info")


@module("device_lifecycle")
def device_lifecycle(ctx: Context, tool: Any) -> list[Finding]:
    """Consulta endoflife.date y explica soporte, última versión y EOL."""
    product, remainder = match_device_product(ctx.target)
    if not product:
        known = ", ".join(
            str(item.get("name") or "") for item in _known_products()[:14]
        )
        return [
            f("Dispositivo", "no reconocido en el catálogo local", "warn"),
            f("Ejemplos admitidos", "ubuntu 24.04, debian 12, android 14, macOS Sonoma", "info"),
            f("Catálogo", known, "info"),
            f(
                "Búsqueda manual",
                "consulta el fabricante y NVD con el nombre y la versión exactos",
                "link",
                url=search_url(f'"{ctx.target}" security advisory EOL'),
            ),
        ]

    findings: list[Finding] = [_product_finding(product)]
    notes = str(product.get("notes") or "").strip()
    if notes:
        findings.append(f("Nota", notes, "info"))

    slug = str(product.get("slug") or "").strip()
    security_url = str(product.get("security_url") or "").strip()
    if not slug:
        findings.append(
            f(
                "Ciclo de vida",
                "sin calendario automático en endoflife.date para este producto",
                "warn",
            )
        )
        if security_url:
            findings.append(f("Avisos del fabricante", "consultar fuente oficial", "link", url=security_url))
        if remainder:
            findings.append(f("Versión o modelo indicado", remainder, "info"))
        findings.append(
            f(
                "Búsqueda manual",
                f'"{ctx.target}" (EOL OR "fin de soporte" OR "security advisory")',
                "link",
                url=search_url(f'"{ctx.target}" (EOL OR "fin de soporte" OR "security advisory")'),
            )
        )
        return findings

    url = f"https://endoflife.date/api/{slug}.json"
    payload = safe_json(ctx, url, timeout=25, retries=1)
    if not isinstance(payload, list) or not payload:
        findings.append(f("Ciclo de vida", "no se pudo consultar endoflife.date", "warn"))
        findings.append(
            f(
                "Fuente",
                f"endoflife.date/{slug}",
                "link",
                url=f"https://endoflife.date/{slug}",
            )
        )
        return findings

    cycles = [item for item in payload if isinstance(item, dict)]
    selected = match_cycle(cycles, ctx.target)
    recognized = selected is not None
    if selected is None:
        selected = cycles[0]
        if remainder and any(char.isdigit() for char in remainder):
            findings.append(
                f(
                    "Versión",
                    f"«{remainder}» no se reconoció; se muestra el ciclo más reciente",
                    "warn",
                )
            )

    current = selected or {}
    label = _cycle_label(current)
    findings.append(f("Ciclo detectado", label, "good" if recognized else "info"))
    if current.get("releaseDate"):
        findings.append(f("Lanzamiento", _fmt_date(current.get("releaseDate")), "info"))
    latest = str(current.get("latest") or "").strip()
    if latest:
        latest_date = _fmt_date(current.get("latestReleaseDate"))
        value = latest if latest_date == "—" else f"{latest} ({latest_date})"
        findings.append(f("Última versión", value, "good"))

    if current.get("apiVersion"):
        findings.append(f("API Android", str(current.get("apiVersion")), "info"))
    if "lts" in current:
        findings.append(f("LTS", "sí" if current.get("lts") else "no", "info"))

    support = current.get("support")
    if support not in (None, False, True):
        findings.append(f("Soporte", _fmt_date(support), "info"))
    eol = current.get("eol")
    eol_text, eol_level = _eol_state(eol)
    findings.append(f("Fin de vida", _fmt_date(eol), eol_level))
    findings.append(f("Estado", eol_text, eol_level))

    extended = current.get("extendedSupport")
    if extended not in (None, False, True):
        findings.append(f("Soporte extendido", _fmt_date(extended), "info"))

    if not recognized:
        findings.append(f("Ciclos recientes", _recent_cycles(cycles), "info"))

    findings.append(
        f(
            "Fuente",
            f"endoflife.date · {slug}",
            "link",
            url=f"https://endoflife.date/{slug}",
        )
    )
    if security_url:
        findings.append(f("Avisos del fabricante", "consultar fuente oficial", "link", url=security_url))
    findings.append(
        f(
            "Aviso",
            "el soporte del dispositivo puede ser menor que el del sistema operativo base "
            "(especialmente en Android y macOS)",
            "info",
        )
    )
    return findings


def _known_products() -> list[dict[str, Any]]:
    from ..devices import device_products

    return device_products()


@module("device_advisories")
def device_advisories(ctx: Context, tool: Any) -> list[Finding]:
    """Enlaces verificables a avisos, CVEs, exploits y catálogos públicos."""
    query = quote_plus(ctx.target)
    product, _remainder = match_device_product(ctx.target)
    findings: list[Finding] = []
    if product:
        findings.append(_product_finding(product))
        security_url = str(product.get("security_url") or "").strip()
        vendor_url = str(product.get("vendor_url") or "").strip()
        if security_url:
            findings.append(
                f(
                    f"Avisos de {product.get('vendor') or 'fabricante'}",
                    "boletines y parches oficiales",
                    "link",
                    url=security_url,
                )
            )
        if vendor_url:
            findings.append(f("Sitio del fabricante", "documentación y descargas", "link", url=vendor_url))
    else:
        findings.append(
            f(
                "Producto no reconocido",
                "se generan búsquedas genéricas; usa el nombre y la versión exactos",
                "warn",
            )
        )

    findings.extend(
        [
            f(
                "NVD · CVEs",
                f"búsqueda de «{ctx.target}»",
                "link",
                url=f"https://nvd.nist.gov/vuln/search/results?query={query}&search_type=all",
            ),
            f(
                "Exploit-DB",
                f"exploits públicos para «{ctx.target}»",
                "link",
                url=f"https://www.exploit-db.com/search?q={query}",
            ),
            f(
                "GitHub Advisory Database",
                f"avisos y paquetes afectados por «{ctx.target}»",
                "link",
                url=f"https://github.com/advisories?query={query}",
            ),
            f(
                "CISA KEV",
                "catálogo de vulnerabilidades explotadas conocidas",
                "link",
                url="https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
            ),
            f(
                "Búsqueda manual",
                f'"{ctx.target}" (CVE OR exploit OR "security advisory" OR firmware)',
                "link",
                url=search_url(f'"{ctx.target}" (CVE OR exploit OR "security advisory" OR firmware)'),
            ),
        ]
    )
    findings.append(
        f(
            "Aviso",
            "un CVE o un exploit público no demuestra que el dispositivo sea vulnerable; "
            "verifica versión, configuración y parches",
            "info",
        )
    )
    return findings


@module("device_web")
def device_web(ctx: Context, tool: Any) -> list[Finding]:
    """Busca documentación, firmware, credenciales por defecto y exploits."""
    product, remainder = match_device_product(ctx.target)
    if product:
        name = str(product.get("name") or "").strip()
        terms = [token for token in (name.split()[0], remainder.split()[0] if remainder else "") if token]
    else:
        terms = [token for token in ctx.target.split()[:2] if len(token) >= 3]

    queries = [
        f'"{ctx.target}" (manual OR firmware OR update OR download)',
        f'"{ctx.target}" ("default password" OR "default credentials" OR admin)',
        f'"{ctx.target}" (CVE OR exploit OR "security advisory")',
    ]
    hits = resolve_direct(ctx, queries, terms=terms, limit=18, timeout=25)
    findings: list[Finding] = []
    if product:
        findings.append(_product_finding(product))
    for hit in hits:
        direct = is_profile_url(hit.url)
        label = profile_label(hit.url)
        findings.append(
            f(
                f"{label} · {'perfil' if direct else 'resultado'}",
                truncate(hit.snippet or hit.url, 240),
                "good" if direct else "link",
                url=hit.url,
                data={"direct_profile": direct, "engine": hit.engine, "query": hit.query},
            )
        )
    if not hits:
        findings.append(
            f("Resultados web", "sin enlaces directos; prueba las búsquedas manuales", "warn")
        )
    findings.append(
        f(
            "Búsqueda manual",
            f'"{ctx.target}" (manual OR firmware OR CVE OR exploit)',
            "link",
            url=search_url(f'"{ctx.target}" (manual OR firmware OR CVE OR exploit)'),
        )
    )
    findings.append(
        f(
            "Aviso",
            "las credenciales por defecto y los exploits solo deben probarse en equipos propios o autorizados",
            "warn",
        )
    )
    return findings
