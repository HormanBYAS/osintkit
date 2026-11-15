"""Resumen final de indicadores técnicos, identidad y páginas encontradas."""

from __future__ import annotations

import ipaddress
import re
import unicodedata
from collections.abc import Iterable, Mapping
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from .core import Finding, ScanResult
from .util import truncate

MAX_IPS = 12
MAX_TECH = 8
MAX_LINKS = 10

# El resumen de teléfonos e emails muestra todas las páginas encontradas, sin
# el límite de "Enlaces destacados". El resto de tipos conserva el resumen
# compacto de siempre.
_FULL_PAGE_KINDS = {"phone", "email"}

_IPV4_RE = re.compile(
    r"(?<![\d.])(?:25[0-5]|2[0-4]\d|1?\d?\d)"
    r"(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}(?![\d.])"
)
_IPV6_RE = re.compile(
    r"(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}"
    r"(?![0-9A-Fa-f:])"
)
_TECH_TITLES = (
    "asn",
    "organización",
    "organizacion",
    "proveedor",
    "mx",
    "país",
    "pais",
    "región",
    "region",
    "ciudad",
    "ubicación",
    "ubicacion",
    "coordenadas",
    "operador",
    "carrier",
    "tipo de línea",
    "tipo de linea",
    "zona horaria",
    "timezone",
    "ptr",
    "hostnames",
    "mcc",
    "mnc",
    "vehículo",
    "vehiculo",
    "marca",
    "modelo",
    "combustible",
    "primera matriculación",
    "primera matriculacion",
    "matrícula",
    "matricula",
    "cilindrada",
    "cilindros",
    "plazas",
    "puertas",
    "masa",
    "dimensiones",
    "color",
    "apk",
    "itv",
    "mot",
    "impuesto",
    "emisiones",
    "año de fabricación",
    "ano de fabricacion",
    "categoría europea",
    "categoria europea",
    "precio de catálogo",
    "precio de catalogo",
    "recall",
    "exportación",
    "exportacion",
    "último v5c",
    "ultimo v5c",
    "ciclo detectado",
    "última versión",
    "ultima version",
    "fin de vida",
    "lanzamiento",
    "soporte",
    "api android",
    "lts",
    "validación orientativa",
    "validacion orientativa",
    "consulta automática",
    "consulta automatica",
)

# Títulos que en los módulos representan el nombre de una persona. Se excluyen
# variantes como "Nombre del país" para no confundir datos del operador con una
# identidad.
_NAME_TITLES = {
    "nombre",
    "nombre completo",
    "nombre de la persona",
    "nombre del titular",
    "nombre titular",
    "titular",
    "name",
    "full name",
    "fullname",
    "display name",
    "displayname",
    "caller name",
    "person",
    "persona",
}
_NAME_TITLE_EXCLUDES = (
    "pais",
    "country",
    "operador",
    "carrier",
    "dominio",
    "domain",
    "empresa",
    "company",
    "archivo",
    "file",
    "modelo",
    "model",
    "marca",
    "brand",
    "ciudad",
    "city",
    "region",
    "ubicacion",
    "location",
    "calle",
    "street",
    "sitio",
    "site",
)
_NAME_FIELDS = {
    "name",
    "full_name",
    "fullname",
    "display_name",
    "displayname",
    "caller_name",
    "callername",
    "person",
    "owner",
    "nombre",
    "nombre_completo",
}
_EMPTY_NAME_VALUES = {
    "",
    "-",
    "—",
    "n/a",
    "na",
    "none",
    "null",
    "unknown",
    "desconocido",
    "no disponible",
}

_HOST_PRIORITY = {
    "github.com": 35,
    "gitlab.com": 30,
    "linkedin.com": 35,
    "x.com": 32,
    "twitter.com": 32,
    "instagram.com": 30,
    "facebook.com": 30,
    "tiktok.com": 28,
    "youtube.com": 25,
    "t.me": 28,
    "telegram.me": 28,
    "wa.me": 35,
    "truecaller.com": 30,
    "sync.me": 28,
    "gravatar.com": 30,
    "keys.openpgp.org": 30,
    "haveibeenpwned.com": 28,
    "epieos.com": 28,
}


def _walk_strings(value: Any) -> Iterable[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, Mapping):
        for item in value.values():
            yield from _walk_strings(item)
    elif isinstance(value, (list, tuple, set)):
        for item in value:
            yield from _walk_strings(item)


def _clean_candidate(value: str) -> str:
    return value.strip(" \t\r\n[](){}<>.,;\"'")


def _ip_scope(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str:
    if ip.is_loopback:
        return "loopback"
    if ip.is_private:
        return "privada"
    if ip.is_link_local:
        return "link-local"
    if ip.is_multicast:
        return "multicast"
    if ip.is_reserved:
        return "reservada"
    return "pública"


def _add_ip(
    found: dict[str, dict[str, Any]],
    candidate: str,
    source: str,
) -> None:
    candidate = _clean_candidate(candidate)
    if not candidate:
        return
    try:
        ip = ipaddress.ip_address(candidate)
    except ValueError:
        return
    key = str(ip)
    item = found.setdefault(
        key,
        {
            "kind": f"IPv{ip.version}",
            "scope": _ip_scope(ip),
            "sources": set(),
        },
    )
    if source:
        item["sources"].add(source)


def _url_host(url: str) -> str:
    try:
        return urlsplit(url).hostname or ""
    except ValueError:
        return ""


def _extract_ips(scan: ScanResult) -> dict[str, dict[str, Any]]:
    found: dict[str, dict[str, Any]] = {}
    for result in scan.results:
        for finding in result.findings:
            source = result.name
            for text in (finding.title, finding.value, finding.url):
                if not text:
                    continue
                for match in _IPV4_RE.findall(text):
                    _add_ip(found, match, source)
                for match in _IPV6_RE.findall(text):
                    _add_ip(found, match, source)
            if finding.url:
                host = _url_host(finding.url)
                if host:
                    _add_ip(found, host, source)
            for text in _walk_strings(finding.data):
                for match in _IPV4_RE.findall(text):
                    _add_ip(found, match, source)
                for match in _IPV6_RE.findall(text):
                    _add_ip(found, match, source)
    return found


def _ip_sort_key(item: tuple[str, dict[str, Any]]) -> tuple[int, int, int]:
    address, info = item
    ip = ipaddress.ip_address(address)
    return (0 if info["scope"] == "pública" else 1, ip.version, int(ip))


def _technical_details(scan: ScanResult) -> list[tuple[str, str]]:
    details: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for result in scan.results:
        for finding in result.findings:
            title = finding.title.strip()
            value = finding.value.strip()
            if not title or not value:
                continue
            lowered = title.casefold()
            if not any(marker in lowered for marker in _TECH_TITLES):
                continue
            key = (title, value)
            if key in seen:
                continue
            seen.add(key)
            details.append((title, truncate(value, 180)))
    return details


def _normalize_url(url: str) -> str:
    try:
        parsed = urlsplit(url)
    except ValueError:
        return url
    path = parsed.path.rstrip("/") or "/"
    return urlunsplit(
        (parsed.scheme.lower(), parsed.netloc.lower(), path, parsed.query, "")
    )


def _host(url: str) -> str:
    host = _url_host(url)
    return host[4:] if host.startswith("www.") else host


def _link_entries(scan: ScanResult) -> list[dict[str, Any]]:
    from .modules.websearch import is_profile_url, is_search_page

    entries: list[dict[str, Any]] = []
    for result in scan.results:
        for finding in result.findings:
            url = finding.url.strip()
            if not url.startswith(("http://", "https://")):
                continue
            try:
                direct = bool(finding.data.get("direct_profile")) or is_profile_url(url)
                search = is_search_page(url)
            except ValueError:
                continue
            host = _host(url)
            manual = finding.title.casefold() in {"búsqueda manual", "busqueda manual"}
            source_directory = bool(finding.data.get("source_directory"))
            contact_link = bool(finding.data.get("contact_link"))
            score = 0
            if direct:
                score += 100
            if not search:
                score += 20
            elif not direct:
                score -= 10
            score += _HOST_PRIORITY.get(host, 0)
            if finding.level == "good":
                score += 15
            elif finding.level == "link":
                score += 5
            if manual:
                score -= 15
            entries.append(
                {
                    "url": url,
                    "normalized": _normalize_url(url),
                    "title": finding.title,
                    "value": finding.value,
                    "level": finding.level,
                    "tool": result.name,
                    "tool_id": result.tool_id,
                    "category": result.category,
                    "direct": direct,
                    "search": search,
                    "manual": manual,
                    "source_directory": source_directory,
                    "contact_link": contact_link,
                    "score": score,
                    "order": len(entries),
                }
            )
    return entries


def _ranked_entries(scan: ScanResult) -> list[dict[str, Any]]:
    """Devuelve los enlaces únicos ordenados por relevancia."""
    best: dict[str, dict[str, Any]] = {}
    for entry in _link_entries(scan):
        previous = best.get(entry["normalized"])
        if previous is None or entry["score"] > previous["score"]:
            best[entry["normalized"]] = entry
    return sorted(best.values(), key=lambda item: (-item["score"], item["order"]))


def _link_finding(entry: Mapping[str, Any]) -> Finding:
    from .modules.websearch import profile_label

    try:
        label = profile_label(str(entry["url"]))
    except ValueError:
        label = ""
    title = str(entry["title"]).strip()
    if label and label.casefold() not in title.casefold():
        title = f"{label} · {title}" if title else label
    if not title:
        title = label or str(entry["tool"])
    if entry["direct"]:
        reason = "perfil directo"
    elif entry["contact_link"]:
        reason = "contacto directo"
    elif entry["source_directory"]:
        reason = "fuente o directorio"
    elif entry["search"]:
        reason = "búsqueda"
    else:
        reason = "página o mención"
    value = " · ".join((reason, str(entry["tool"])))
    detail = str(entry["value"]).strip()
    if (
        detail
        and not entry["search"]
        and detail.casefold() not in {"perfil directo", "búsqueda", "resultado", "ver"}
    ):
        value += f" — {truncate(detail, 180)}"
    return Finding(
        title=title,
        value=value,
        level="good" if entry["direct"] else "link",
        url=str(entry["url"]),
        data={
            "tool": entry["tool_id"],
            "direct_profile": entry["direct"],
            "search_page": entry["search"],
            "source_directory": entry["source_directory"],
            "score": entry["score"],
        },
    )


def _notable_links(scan: ScanResult, limit: int = MAX_LINKS) -> tuple[list[Finding], int]:
    ranked = _ranked_entries(scan)
    return [_link_finding(entry) for entry in ranked[:limit]], len(ranked)


def _target_pages(scan: ScanResult) -> list[dict[str, Any]]:
    """Todas las páginas del objetivo, sin el límite de enlaces destacados.

    Se excluyen buscadores, búsquedas manuales y directorios de consulta: esos
    enlaces no demuestran que el teléfono o el email figuren en la página. El
    resto se conserva completo para que el informe final no oculte coincidencias.
    """
    return [
        entry
        for entry in _ranked_entries(scan)
        if not entry["search"]
        and not entry["manual"]
        and not entry["source_directory"]
        and not entry["contact_link"]
    ]


def _fold_text(value: str) -> str:
    normalized = unicodedata.normalize("NFKD", str(value))
    return "".join(
        char for char in normalized if not unicodedata.combining(char)
    ).casefold().strip()


def _name_candidate(value: Any) -> str:
    if not isinstance(value, str):
        return ""
    candidate = " ".join(value.split())
    if not candidate or len(candidate) > 120:
        return ""
    folded = _fold_text(candidate)
    if folded in _EMPTY_NAME_VALUES:
        return ""
    if re.match(r"^(?:https?://|www\.)", candidate, re.I):
        return ""
    if "@" in candidate and " " not in candidate:
        return ""
    if not re.search(r"[^\W\d_]", candidate, re.UNICODE):
        return ""
    return candidate


def _target_names(scan: ScanResult) -> list[tuple[str, str]]:
    """Extrae nombres estructurados de los hallazgos del teléfono o email."""
    found: dict[str, tuple[str, str]] = {}
    for result in scan.results:
        for finding in result.findings:
            folded_title = _fold_text(finding.title)
            candidates: list[Any] = []
            if (
                folded_title in _NAME_TITLES
                and not any(marker in folded_title for marker in _NAME_TITLE_EXCLUDES)
            ):
                candidates.append(finding.value)
            for key, value in finding.data.items():
                if _fold_text(str(key)) in _NAME_FIELDS:
                    candidates.append(value)
            for raw in candidates:
                name = _name_candidate(raw)
                if not name:
                    continue
                key = _fold_text(name)
                if key not in found:
                    found[key] = (name, result.name)
    return list(found.values())


def _target_identity(
    scan: ScanResult,
    ips: list[tuple[str, dict[str, Any]]],
) -> list[Finding]:
    """Bloque inicial del resumen especializado para teléfono y email."""
    label = "teléfono" if scan.kind == "phone" else "email"
    names = _target_names(scan)
    findings: list[Finding] = [
        Finding(
            f"Datos del {label}",
            "nombre, IP y todas las páginas encontradas",
            "info",
        )
    ]
    if names:
        for index, (name, source) in enumerate(names):
            title = "Nombre encontrado" if index == 0 else "Otro nombre encontrado"
            value = f"{name} · {source}" if source else name
            findings.append(
                Finding(
                    title,
                    value,
                    "good",
                    data={"name": name, "source": source},
                )
            )
    else:
        findings.append(Finding("Nombre encontrado", "no se encontró en los resultados", "info"))

    if ips:
        addresses = [address for address, _info in ips]
        title = "IP encontrada" if len(addresses) == 1 else "IPs encontradas"
        findings.append(
            Finding(
                title,
                ", ".join(addresses),
                "good",
                data={"addresses": addresses},
            )
        )
    else:
        findings.append(Finding("IP encontrada", "ninguna en los resultados", "info"))
    return findings


def _target_pages_findings(scan: ScanResult) -> list[Finding]:
    pages = _target_pages(scan)
    if scan.kind == "phone":
        warning = (
            "Las búsquedas manuales y los directorios quedan en cada herramienta. "
            "El número puede aparecer en avisos, páginas de terceros o perfiles de "
            "otras personas; revisa cada enlace antes de atribuirlo al titular."
        )
    else:
        warning = (
            "Las búsquedas manuales y los directorios quedan en cada herramienta. "
            "Los perfiles de la búsqueda masiva coinciden con la parte local del "
            "email y pueden pertenecer a otras personas; no demuestran por sí solos "
            "que la cuenta esté registrada."
        )
    findings: list[Finding] = [
        Finding(
            "Páginas y perfiles encontrados",
            (
                f"{len(pages)} {'único' if len(pages) == 1 else 'únicos'}; "
                "se listan todos"
                if pages
                else "no se encontraron páginas directas en los resultados"
            ),
            "info" if pages else "warn",
            data={"pages": len(pages), "kind": scan.kind},
        ),
        Finding("Aviso", warning, "warn"),
    ]
    findings.extend(_link_finding(entry) for entry in pages)
    return findings


def final_findings(scan: ScanResult) -> list[Finding]:
    """Genera el bloque final con IPs, datos técnicos y páginas encontradas."""
    findings: list[Finding] = []

    ips = sorted(_extract_ips(scan).items(), key=_ip_sort_key)
    if scan.kind in _FULL_PAGE_KINDS:
        findings.extend(_target_identity(scan, ips))

    if ips:
        findings.append(
            Finding(
                "Direcciones IP encontradas",
                f"{len(ips)} única{'s' if len(ips) != 1 else ''} en los resultados",
                "good",
                data={"addresses": [address for address, _info in ips]},
            )
        )
        for address, info in ips[:MAX_IPS]:
            sources = ", ".join(sorted(info["sources"])[:4])
            value = f"{info['kind']} · {info['scope']}"
            if sources:
                value += f" · {sources}"
            findings.append(
                Finding(
                    f"IP {address}",
                    value,
                    "good",
                    data={
                        "address": address,
                        "kind": info["kind"],
                        "scope": info["scope"],
                        "sources": sorted(info["sources"]),
                    },
                )
            )
        if len(ips) > MAX_IPS:
            findings.append(
                Finding("IPs adicionales", str(len(ips) - MAX_IPS), "info")
            )
    else:
        findings.append(
            Finding("Direcciones IP encontradas", "ninguna en los resultados", "info")
        )

    technical = _technical_details(scan)
    if technical:
        findings.append(
            Finding(
                "Otros datos técnicos",
                f"{len(technical)} detectados; se muestran los más relevantes",
                "info",
            )
        )
        for title, value in technical[:MAX_TECH]:
            findings.append(Finding(title, value, "info"))
        if len(technical) > MAX_TECH:
            findings.append(
                Finding("Datos adicionales", str(len(technical) - MAX_TECH), "info")
            )

    if scan.kind in _FULL_PAGE_KINDS:
        findings.extend(_target_pages_findings(scan))
        return findings

    links, total = _notable_links(scan)
    if links:
        findings.append(
            Finding(
                "Enlaces destacados",
                f"{len(links)} de {total} enlaces; ordenados por perfil directo y relevancia",
                "info",
            )
        )
        findings.extend(links)
    else:
        findings.append(
            Finding("Enlaces destacados", "no se encontraron enlaces en los resultados", "info")
        )
    return findings
