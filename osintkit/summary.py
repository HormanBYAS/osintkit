"""Resumen final de indicadores técnicos y enlaces destacados."""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable, Mapping
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from .core import Finding, ScanResult
from .util import truncate

MAX_IPS = 12
MAX_TECH = 8
MAX_LINKS = 10

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
)

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
            if finding.title.casefold() in {"búsqueda manual", "busqueda manual"}:
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
                    "score": score,
                    "order": len(entries),
                }
            )
    return entries


def _notable_links(scan: ScanResult, limit: int = MAX_LINKS) -> tuple[list[Finding], int]:
    from .modules.websearch import profile_label

    entries = _link_entries(scan)
    best: dict[str, dict[str, Any]] = {}
    for entry in entries:
        previous = best.get(entry["normalized"])
        if previous is None or entry["score"] > previous["score"]:
            best[entry["normalized"]] = entry
    ranked = sorted(best.values(), key=lambda item: (-item["score"], item["order"]))
    selected = ranked[:limit]
    findings: list[Finding] = []
    for entry in selected:
        try:
            label = profile_label(entry["url"])
        except ValueError:
            label = ""
        title = entry["title"].strip()
        if label and label.casefold() not in title.casefold():
            title = f"{label} · {title}" if title else label
        if not title:
            title = label or entry["tool"]
        reasons = ["perfil directo" if entry["direct"] else "búsqueda" if entry["search"] else "resultado"]
        reasons.append(entry["tool"])
        value = " · ".join(reasons)
        detail = entry["value"].strip()
        if (
            detail
            and not entry["search"]
            and detail.casefold() not in {"perfil directo", "búsqueda", "resultado", "ver"}
        ):
            value += f" — {truncate(detail, 180)}"
        findings.append(
            Finding(
                title=title,
                value=value,
                level="good" if entry["direct"] else "link",
                url=entry["url"],
                data={
                    "tool": entry["tool_id"],
                    "direct_profile": entry["direct"],
                    "search_page": entry["search"],
                    "score": entry["score"],
                },
            )
        )
    return findings, len(best)


def final_findings(scan: ScanResult) -> list[Finding]:
    """Genera el bloque final con IPs, datos técnicos y enlaces destacados."""
    findings: list[Finding] = []

    ips = sorted(_extract_ips(scan).items(), key=_ip_sort_key)
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
