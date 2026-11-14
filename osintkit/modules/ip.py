"""Módulos de IP, ASN, reputación y puertos (pasivos)."""

from __future__ import annotations

import ipaddress
import re
from typing import Any

from ..core import Context, Finding, module
from ..http import HttpError, NetworkError
from ..ports import as_port, describe_port, service_name
from ..util import collapse_ws, days_until, dedupe, is_ip, truncate
from .base import (
    doh_txt,
    doh_values,
    domain_for,
    f,
    ip_for,
    join_limited,
    resolve_ips,
    reverse_dns_name,
    safe_get,
    safe_json,
    vt_url_id,
)


def _ip(ctx: Context) -> str | None:
    return ip_for(ctx)


@module("ip_geo")
def ip_geo(ctx: Context, tool: Any) -> list[Finding]:
    ip = _ip(ctx)
    if not ip:
        return [f("Geolocalización", "no se pudo resolver una IP", "warn")]
    data: dict[str, Any] | None = None
    source = ""
    for url, name in (
        (f"https://ipwho.is/{ip}", "ipwho.is"),
        (f"https://ipapi.co/{ip}/json/", "ipapi.co"),
        (f"https://ipinfo.io/{ip}/json", "ipinfo.io"),
    ):
        try:
            response = ctx.http.get(url, timeout=20, retries=1)
        except (NetworkError, HttpError):
            continue
        if response.ok:
            try:
                candidate = response.json()
            except ValueError:
                continue
            if isinstance(candidate, dict) and candidate.get("success") is not False:
                data = candidate
                source = name
                break
    if not data:
        return [f("Geolocalización", f"sin datos para {ip}", "warn")]
    findings: list[Finding] = [f("IP", ip, "info", data={"source": source})]
    mapping = {
        "country": ("País", None),
        "country_name": ("País", None),
        "region": ("Región", None),
        "regionName": ("Región", None),
        "city": ("Ciudad", None),
        "postal": ("Código postal", None),
        "postal_code": ("Código postal", None),
        "timezone": ("Zona horaria", None),
        "time_zone": ("Zona horaria", None),
        "isp": ("ISP", None),
        "org": ("Organización", None),
        "asn": ("ASN", None),
        "as": ("ASN/Org", None),
        "connection": ("Conexión", None),
        "hostname": ("Hostname", None),
        "latitude": ("Latitud", None),
        "longitude": ("Longitud", None),
        "lat": ("Latitud", None),
        "lon": ("Longitud", None),
        "loc": ("Coordenadas", None),
    }
    seen: set[str] = set()
    for key, (label, _) in mapping.items():
        if key not in data or label in seen:
            continue
        value = data[key]
        if isinstance(value, (dict, list)):
            value = str(value)
        if value in (None, ""):
            continue
        seen.add(label)
        findings.append(f(label, str(value), "info"))
    lat = data.get("latitude") or data.get("lat")
    lon = data.get("longitude") or data.get("lon")
    if not (lat and lon) and data.get("loc"):
        loc = str(data["loc"]).split(",")
        if len(loc) == 2:
            lat, lon = loc
    if lat and lon:
        findings.append(f("Mapa", f"https://www.openstreetmap.org/?mlat={lat}&mlon={lon}#map=12/{lat}/{lon}", "link",
                        url=f"https://www.openstreetmap.org/?mlat={lat}&mlon={lon}"))
    findings.append(f("Fuente", source, "info"))
    return findings


@module("ip_asn")
def ip_asn(ctx: Context, tool: Any) -> list[Finding]:
    ip = _ip(ctx)
    if not ip:
        return [f("ASN", "no se pudo resolver una IP", "warn")]
    findings: list[Finding] = []
    data = safe_json(ctx, f"https://stat.ripe.net/data/prefix-overview/data.json?resource={ip}", timeout=25)
    if isinstance(data, dict):
        payload = data.get("data") or {}
        if payload.get("resource"):
            findings.append(f("Recurso", str(payload["resource"]), "info"))
        prefixes = payload.get("prefixes") or []
        for prefix in prefixes[:5]:
            if isinstance(prefix, dict):
                findings.append(f("Prefijo", str(prefix.get("prefix", "")), "info"))
        asns = payload.get("asns") or []
        for asn in asns[:5]:
            if isinstance(asn, dict):
                number = asn.get("asn")
                holder = asn.get("holder", "")
                findings.append(f("ASN", f"AS{number} · {holder}", "good"))
                if number:
                    overview = safe_json(
                        ctx, f"https://stat.ripe.net/data/as-overview/data.json?resource=AS{number}", timeout=20
                    )
                    if isinstance(overview, dict):
                        info = overview.get("data") or {}
                        if info.get("holder"):
                            findings.append(f("Organización", str(info["holder"]), "info"))
                        if info.get("announced"):
                            findings.append(f("Anunciado", str(info["announced"]), "info"))
    # Team Cymru por DNS como respaldo
    rev = reverse_dns_name(ip)
    if rev:
        base = rev.replace(".in-addr.arpa", "").replace(".ip6.arpa", "")
        suffix = "origin6.asn.cymru.com" if ":" in ip else "origin.asn.cymru.com"
        values = doh_txt(ctx, f"{base}.{suffix}")
        for value in values:
            findings.append(f("Team Cymru", value, "info", data={"source": "dns"}))
    if not findings:
        findings.append(f("ASN", "sin datos de enrutamiento", "warn"))
    return findings


@module("reverse_dns")
def reverse_dns(ctx: Context, tool: Any) -> list[Finding]:
    ip = _ip(ctx) if ctx.kind != "ip" else ctx.target
    if not ip:
        return [f("DNS inverso", "no se pudo resolver una IP", "warn")]
    name = reverse_dns_name(ip)
    if not name:
        return [f("DNS inverso", f"IP inválida: {ip}", "warn")]
    values = doh_values(ctx, name, "PTR")
    if values:
        return [f("PTR", v.rstrip("."), "good") for v in dedupe(values)]
    return [f("PTR", f"sin registro inverso para {ip}", "info")]


@module("shodan_internetdb")
def shodan_internetdb(ctx: Context, tool: Any) -> list[Finding]:
    ip = _ip(ctx)
    if not ip:
        return [f("InternetDB", "no se pudo resolver una IP", "warn")]
    try:
        response = ctx.http.get(f"https://internetdb.shodan.io/{ip}", timeout=25, retries=1)
    except (NetworkError, HttpError) as exc:
        return [f("InternetDB", str(exc), "warn")]
    if response.status == 404:
        return [f("InternetDB", f"sin datos para {ip}", "info")]
    if not response.ok:
        return [f("InternetDB", f"HTTP {response.status}", "warn")]
    try:
        data = response.json()
    except ValueError:
        return [f("InternetDB", "respuesta no JSON", "warn")]
    findings: list[Finding] = [f("IP", ip, "info")]
    ports = data.get("ports") or []
    if ports:
        count = len(ports)
        findings.append(
            f("Puertos abiertos", f"{count} {'detectado' if count == 1 else 'detectados'}", "warn")
        )
        for port in sorted(ports, key=lambda value: as_port(value) or 65536):
            name = service_name(port)
            findings.append(
                f(f"Puerto {port}", name, "warn", data={"port": port, "service": name})
            )
    if data.get("hostnames"):
        findings.append(f("Hostnames", join_limited(data["hostnames"], 30), "info"))
    if data.get("cpes"):
        findings.append(f("CPEs", join_limited(data["cpes"], 20), "info"))
    if data.get("tags"):
        findings.append(f("Tags", join_limited(data["tags"], 20), "info"))
    vulns = data.get("vulns") or []
    if vulns:
        findings.append(f("CVEs observados", join_limited(vulns, 40), "bad"))
        for vuln in vulns[:20]:
            findings.append(f("CVE", str(vuln), "bad", url=f"https://nvd.nist.gov/vuln/detail/{vuln}"))
    if len(findings) == 1:
        findings.append(f("InternetDB", "sin puertos ni etiquetas", "info"))
    return findings


@module("tor_exit")
def tor_exit(ctx: Context, tool: Any) -> list[Finding]:
    ip = ctx.target
    if not is_ip(ip):
        return [f("Tor", "se esperaba una IP", "warn")]
    try:
        response = ctx.http.get("https://check.torproject.org/torbulkexitlist", timeout=30, retries=1)
    except (NetworkError, HttpError) as exc:
        return [f("Tor exit", str(exc), "warn")]
    if not response.ok:
        return [f("Tor exit", f"HTTP {response.status}", "warn")]
    exits = {line.strip() for line in response.text.splitlines() if line.strip()}
    if ip in exits:
        return [f("Nodo de salida Tor", f"{ip} figura en la lista oficial", "warn", data={"listed": True})]
    return [f("Nodo de salida Tor", f"{ip} no figura en la lista", "good", data={"listed": False})]


@module("dnsbl")
def dnsbl(ctx: Context, tool: Any) -> list[Finding]:
    ip = ctx.target
    if not is_ip(ip) or ":" in ip:
        return [f("DNSBL", "solo se admiten IPv4 para listas DNS", "info")]
    rev = ".".join(reversed(ip.split(".")))
    zones = [
        "zen.spamhaus.org",
        "bl.spamcop.net",
        "b.barracudacentral.org",
        "dnsbl.sorbs.net",
        "psbl.surriel.com",
    ]
    findings: list[Finding] = []
    listed = 0
    for zone in zones:
        values = doh_values(ctx, f"{rev}.{zone}", "A")
        codes = [v for v in values if v.startswith("127.")]
        if codes:
            if any(v in ("127.255.255.252", "127.255.255.254") for v in codes):
                findings.append(f(f"{zone}", "consulta bloqueada por el resolutor público", "warn"))
            else:
                listed += 1
                findings.append(f(f"{zone}", f"listada: {', '.join(codes)}", "bad", data={"codes": codes}))
        else:
            findings.append(f(f"{zone}", "no listada", "good"))
    findings.insert(0, f("Listas que reportan", str(listed), "bad" if listed else "good"))
    return findings


@module("ip_bgp_prefixes")
def ip_bgp_prefixes(ctx: Context, tool: Any) -> list[Finding]:
    ip = _ip(ctx)
    if not ip:
        return [f("BGP", "no se pudo resolver una IP", "warn")]
    data = safe_json(ctx, f"https://stat.ripe.net/data/prefix-overview/data.json?resource={ip}", timeout=25)
    if not isinstance(data, dict):
        return [f("BGP", "RIPEstat no respondió", "warn")]
    payload = data.get("data") or {}
    findings: list[Finding] = []
    for prefix in (payload.get("prefixes") or [])[:10]:
        if isinstance(prefix, dict):
            findings.append(f("Prefijo", str(prefix.get("prefix", "")), "info"))
    for asn in (payload.get("asns") or [])[:10]:
        if isinstance(asn, dict):
            findings.append(f("Origen", f"AS{asn.get('asn')} · {asn.get('holder', '')}", "info"))
    routing = safe_json(ctx, f"https://stat.ripe.net/data/routing-status/data.json?resource={ip}", timeout=25)
    if isinstance(routing, dict):
        info = routing.get("data") or {}
        if info.get("visibility"):
            findings.append(f("Visibilidad", f"{info['visibility']} ({info.get('visibility_v4', '')})", "info"))
        if info.get("last_seen"):
            findings.append(f("Última observación", str(info["last_seen"]), "info"))
    if not findings:
        findings.append(f("BGP", "sin prefijos anunciados", "warn"))
    return findings


@module("otx_indicator")
def otx_indicator(ctx: Context, tool: Any) -> list[Finding]:
    kind_map = {"ip": "ip", "domain": "domain", "hash": "file", "url": "url"}
    otx_type = kind_map.get(ctx.kind, "domain")
    value = ctx.target
    try:
        response = ctx.http.get(
            f"https://otx.alienvault.com/api/v1/indicators/{otx_type}/{value}/general",
            timeout=30,
            retries=1,
        )
    except (NetworkError, HttpError) as exc:
        return [f("OTX", str(exc), "warn")]
    if response.status == 429:
        return [f("OTX", "límite de tasa alcanzado (429)", "warn")]
    if response.status == 404:
        return [f("OTX", "indicador no encontrado", "info")]
    if not response.ok:
        return [f("OTX", f"HTTP {response.status}", "warn")]
    try:
        data = response.json()
    except ValueError:
        return [f("OTX", "respuesta no JSON", "warn")]
    findings: list[Finding] = [f("Indicador", f"{value} ({otx_type})", "info")]
    pulse = data.get("pulse_info") or {}
    if isinstance(pulse, dict) and pulse.get("count") is not None:
        count = int(pulse.get("count") or 0)
        findings.append(f("Pulsos", str(count), "bad" if count else "good"))
        for item in (pulse.get("pulses") or [])[:10]:
            if isinstance(item, dict):
                findings.append(f("Pulso", str(item.get("name", "")), "warn", data={"tags": item.get("tags"), "created": item.get("created")}))
    for key, label in (("reputation", "Reputación"), ("country_name", "País"), ("asn", "ASN"), ("city", "Ciudad")):
        if data.get(key) not in (None, "", 0):
            findings.append(f(label, str(data[key]), "info"))
    if data.get("validation"):
        findings.append(f("Validación", str(data["validation"]), "info"))
    return findings


def _vt_headers(ctx: Context) -> dict[str, str]:
    return {"x-apikey": ctx.key("VIRUSTOTAL_API_KEY")}


@module("virustotal")
def virustotal(ctx: Context, tool: Any) -> list[Finding]:
    vt_type = str(tool.options.get("vt_type", "domains"))
    value = ctx.target
    if vt_type == "urls":
        value = vt_url_id(ctx.target)
    if vt_type == "files" and ctx.kind == "file":
        from ..util import file_hashes

        value = file_hashes(ctx.target)["sha256"]
    url = f"https://www.virustotal.com/api/v3/{vt_type}/{value}"
    try:
        response = ctx.http.get(url, headers=_vt_headers(ctx), timeout=30, retries=1)
    except (NetworkError, HttpError) as exc:
        return [f("VirusTotal", str(exc), "warn")]
    if response.status in (401, 403):
        return [f("VirusTotal", "clave API inválida o sin permisos", "warn")]
    if response.status == 404:
        return [f("VirusTotal", f"sin resultados para {ctx.target}", "info")]
    if response.status == 429:
        return [f("VirusTotal", "límite de la API alcanzado (429)", "warn")]
    if not response.ok:
        return [f("VirusTotal", f"HTTP {response.status}", "warn")]
    try:
        payload = response.json()
    except ValueError:
        return [f("VirusTotal", "respuesta no JSON", "warn")]
    data = payload.get("data") or {}
    attributes = data.get("attributes") or {}
    findings: list[Finding] = [f("Objeto", f"{vt_type}: {value}", "info", data={"id": data.get("id")})]
    stats = attributes.get("last_analysis_stats") or {}
    if stats:
        malicious = int(stats.get("malicious", 0))
        suspicious = int(stats.get("suspicious", 0))
        harmless = int(stats.get("harmless", 0))
        undetected = int(stats.get("undetected", 0))
        level = "bad" if malicious else ("warn" if suspicious else "good")
        findings.append(f("Detecciones", f"{malicious} maliciosas · {suspicious} sospechosas · {harmless + undetected} limpias", level))
    if attributes.get("reputation") is not None:
        findings.append(f("Reputación", str(attributes["reputation"]), "info"))
    if attributes.get("categories"):
        findings.append(f("Categorías", join_limited(list(attributes["categories"].values()), 15), "info"))
    if attributes.get("tags"):
        findings.append(f("Tags", join_limited(attributes["tags"], 20), "info"))
    if attributes.get("last_analysis_date"):
        findings.append(f("Último análisis", str(attributes["last_analysis_date"]), "info"))
    results = attributes.get("last_analysis_results") or {}
    flagged = [
        f"{engine}: {res.get('result') or res.get('category')}"
        for engine, res in results.items()
        if isinstance(res, dict) and res.get("category") in ("malicious", "suspicious")
    ]
    for item in flagged[:20]:
        findings.append(f("Motor", item, "bad"))
    if attributes.get("whois"):
        whois_text = str(attributes["whois"])
        findings.append(f("WHOIS", truncate(collapse_ws(whois_text), 400), "info"))
    return findings


@module("abuseipdb")
def abuseipdb(ctx: Context, tool: Any) -> list[Finding]:
    ip = ctx.target
    try:
        response = ctx.http.get(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": ip, "maxAgeInDays": "90", "verbose": "true"},
            headers={"Key": ctx.key("ABUSEIPDB_API_KEY"), "Accept": "application/json"},
            timeout=30,
            retries=1,
        )
    except (NetworkError, HttpError) as exc:
        return [f("AbuseIPDB", str(exc), "warn")]
    if response.status in (401, 403):
        return [f("AbuseIPDB", "clave inválida o sin permisos", "warn")]
    if not response.ok:
        return [f("AbuseIPDB", f"HTTP {response.status}", "warn")]
    try:
        data = (response.json().get("data") or {})
    except ValueError:
        return [f("AbuseIPDB", "respuesta no JSON", "warn")]
    score = int(data.get("abuseConfidenceScore", 0))
    level = "bad" if score >= 75 else ("warn" if score >= 25 else "good")
    findings: list[Finding] = [
        f("Confianza de abuso", f"{score}/100", level),
        f("Reportes", str(data.get("totalReports", 0)), "warn" if data.get("totalReports") else "good"),
        f("País", str(data.get("countryCode", "")), "info"),
        f("ISP", str(data.get("isp", "")), "info"),
        f("Uso", str(data.get("usageType", "")), "info"),
        f("Dominio", str(data.get("domain", "")), "info"),
        f("Último reporte", str(data.get("lastReportedAt", "")), "info"),
    ]
    for report in (data.get("reports") or [])[:10]:
        if isinstance(report, dict):
            findings.append(f("Reporte", f"{report.get('reportedAt')} · {report.get('comment', '')}", "warn"))
    return findings


@module("greynoise")
def greynoise(ctx: Context, tool: Any) -> list[Finding]:
    ip = ctx.target
    try:
        response = ctx.http.get(
            f"https://api.greynoise.io/v3/community/{ip}",
            headers={"key": ctx.key("GREYNOISE_API_KEY")},
            timeout=25,
            retries=1,
        )
    except (NetworkError, HttpError) as exc:
        return [f("GreyNoise", str(exc), "warn")]
    if response.status == 404:
        return [f("GreyNoise", "IP no observada", "info")]
    if response.status in (401, 403):
        return [f("GreyNoise", "clave inválida", "warn")]
    if not response.ok:
        return [f("GreyNoise", f"HTTP {response.status}", "warn")]
    try:
        data = response.json()
    except ValueError:
        return [f("GreyNoise", "respuesta no JSON", "warn")]
    findings: list[Finding] = [f("IP", ip, "info")]
    classification = str(data.get("classification", "unknown"))
    findings.append(f("Clasificación", classification, "bad" if classification == "malicious" else "info"))
    for key, label in (("name", "Actor"), ("last_seen", "Última vez"), ("link", "Enlace"), ("message", "Mensaje")):
        if data.get(key):
            findings.append(f(label, str(data[key]), "info", url=str(data[key]) if key == "link" else ""))
    if data.get("noise"):
        findings.append(f("Ruido de internet", "sí", "warn"))
    if data.get("riot"):
        findings.append(f("RIOT", "servicio conocido y benigno", "good"))
    return findings


@module("shodan_host")
def shodan_host(ctx: Context, tool: Any) -> list[Finding]:
    ip = ctx.target
    try:
        response = ctx.http.get(
            "https://api.shodan.io/shodan/host/" + ip,
            params={"key": ctx.key("SHODAN_API_KEY")},
            timeout=30,
            retries=1,
        )
    except (NetworkError, HttpError) as exc:
        return [f("Shodan", str(exc), "warn")]
    if response.status == 404:
        return [f("Shodan", "host no encontrado", "info")]
    if response.status in (401, 403):
        return [f("Shodan", "clave inválida", "warn")]
    if not response.ok:
        return [f("Shodan", f"HTTP {response.status}", "warn")]
    try:
        data = response.json()
    except ValueError:
        return [f("Shodan", "respuesta no JSON", "warn")]
    findings: list[Finding] = [f("IP", ip, "info")]
    for key, label in (("org", "Organización"), ("isp", "ISP"), ("os", "Sistema"), ("country_name", "País"),
                       ("city", "Ciudad"), ("last_update", "Actualizado")):
        if data.get(key):
            findings.append(f(f"{label}", str(data[key]), "info"))
    if data.get("hostnames"):
        findings.append(f("Hostnames", join_limited(data["hostnames"], 20), "info"))
    services = [service for service in (data.get("data") or []) if isinstance(service, dict)]
    display_services = services[:20]
    service_ports = {
        str(as_port(service.get("port")))
        for service in display_services
        if as_port(service.get("port")) is not None
    }
    raw_ports = data.get("ports") or []
    if raw_ports:
        count = len(raw_ports)
        findings.append(
            f("Puertos", f"{count} {'detectado' if count == 1 else 'detectados'}", "warn")
        )
        for port in sorted(raw_ports, key=lambda value: as_port(value) or 65536):
            if str(as_port(port)) in service_ports:
                continue
            name = service_name(port)
            findings.append(
                f(f"Puerto {port}", name, "warn", data={"port": port, "service": name})
            )
    if data.get("tags"):
        findings.append(f("Tags", join_limited(data["tags"], 20), "info"))
    for service in display_services:
        port = service.get("port")
        product = " ".join(str(service.get(x, "")) for x in ("product", "version")).strip()
        if port not in (None, ""):
            label = describe_port(
                port,
                str(service.get("transport") or service.get("transport_type") or "tcp"),
                product=product,
            )
        else:
            label = product or "servicio sin puerto"
        findings.append(
            f("Servicio", label, "info", data={"banner": truncate(str(service.get("data", "")), 200)})
        )
    vulns = data.get("vulns") or {}
    for cve in list(vulns)[:30]:
        findings.append(f("CVE", str(cve), "bad", url=f"https://nvd.nist.gov/vuln/detail/{cve}"))
    return findings


@module("censys_ip")
def censys_ip(ctx: Context, tool: Any) -> list[Finding]:
    import base64

    ip = ctx.target
    ident = ctx.key("CENSYS_API_ID")
    secret = ctx.key("CENSYS_API_SECRET")
    auth = base64.b64encode(f"{ident}:{secret}".encode()).decode()
    try:
        response = ctx.http.get(
            f"https://search.censys.io/api/v2/hosts/{ip}",
            headers={"Authorization": f"Basic {auth}"},
            timeout=30,
            retries=1,
        )
    except (NetworkError, HttpError) as exc:
        return [f("Censys", str(exc), "warn")]
    if response.status in (401, 403):
        return [f("Censys", "credenciales inválidas", "warn")]
    if response.status == 404:
        return [f("Censys", "host no encontrado", "info")]
    if not response.ok:
        return [f("Censys", f"HTTP {response.status}", "warn")]
    try:
        data = (response.json().get("result") or {})
    except ValueError:
        return [f("Censys", "respuesta no JSON", "warn")]
    findings: list[Finding] = [f("IP", ip, "info")]
    for key, label in (("autonomous_system.name", "ASN"), ("autonomous_system.asn", "AS number"),
                       ("operating_system.product", "Sistema"), ("location.country", "País"),
                       ("location.city", "Ciudad")):
        current: Any = data
        for part in key.split("."):
            current = current.get(part) if isinstance(current, dict) else None
        if current not in (None, ""):
            findings.append(f(f"{label}", str(current), "info"))
    for service in (data.get("services") or [])[:25]:
        if isinstance(service, dict):
            port = service.get("port")
            transport = service.get("transport_type") or service.get("transport") or "tcp"
            product = " ".join(
                str(service.get(key, "")) for key in ("product", "version") if service.get(key)
            ).strip()
            if port not in (None, ""):
                label = describe_port(
                    port,
                    str(transport),
                    str(service.get("service_name") or ""),
                    product,
                )
            else:
                label = str(service.get("service_name") or product or "servicio sin puerto")
            findings.append(
                f("Servicio", label, "info", data={"banner": truncate(str(service.get("banner", "")), 200)}
            ))
    if data.get("labels"):
        findings.append(f("Etiquetas", join_limited(data["labels"], 20), "info"))
    return findings
