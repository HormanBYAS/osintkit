"""Módulos de amenazas: CVEs, EPSS, malware e indicadores."""

from __future__ import annotations

import re
from typing import Any

from ..core import Context, Finding, module
from ..http import HttpError, NetworkError
from ..ports import describe_port
from ..util import collapse_ws, is_ip, strip_ansi, truncate
from .base import cve_id, f, join_limited, safe_get, safe_json


# ---------------------------------------------------------------------------
# Ayudas
# ---------------------------------------------------------------------------

def _auth_headers(ctx: Context) -> dict[str, str]:
    key = ctx.key("ABUSECH_AUTH_KEY")
    return {"Auth-Key": key} if key else {}


def _abusec_disabled() -> list[Finding]:
    return [
        f(
            "abuse.ch",
            "Este servicio requiere ABUSECH_AUTH_KEY. Configúrala con "
            "`osintkit config set-key ABUSECH_AUTH_KEY ...` o en el entorno.",
            "warn",
            url="https://auth.abuse.ch/",
        )
    ]


def _post_abusec(ctx: Context, endpoint: str, form: dict[str, str]) -> Any:
    response = ctx.http.post_form(
        endpoint,
        form,
        headers=_auth_headers(ctx),
        timeout=30,
        retries=1,
    )
    if response.status in (401, 403):
        return None
    if not response.ok:
        return None
    try:
        return response.json()
    except ValueError:
        return None


def _nvd_headers(ctx: Context) -> dict[str, str]:
    key = ctx.key("NVD_API_KEY")
    return {"apiKey": key} if key else {}


def _cve_from_target(target: str) -> str | None:
    return cve_id(target)


# ---------------------------------------------------------------------------
# Vulnerabilidades
# ---------------------------------------------------------------------------

@module("nvd_search")
def nvd_search(ctx: Context, tool: Any) -> list[Finding]:
    query = ctx.target.strip()
    cve = _cve_from_target(query)
    params: dict[str, Any] = {"resultsPerPage": 20}
    if cve:
        params["cveId"] = cve
    else:
        params["keywordSearch"] = query
        params["keywordExactMatch"] = ""
    try:
        response = ctx.http.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params=params,
            headers=_nvd_headers(ctx),
            timeout=40,
            retries=1,
        )
    except (NetworkError, HttpError) as exc:
        return [f("NVD", str(exc), "warn", url="https://nvd.nist.gov/")]

    if response.status == 403:
        return [
            f(
                "NVD",
                "la API rechazó la consulta; sin NVD_API_KEY el límite es muy bajo",
                "warn",
                url="https://nvd.nist.gov/developers/request-an-api-key",
            )
        ]
    if response.status == 429:
        return [f("NVD", "límite de la API alcanzado (429); intenta más tarde", "warn")]
    if not response.ok:
        return [f("NVD", f"HTTP {response.status}", "warn")]

    try:
        payload = response.json()
    except ValueError:
        return [f("NVD", "respuesta no JSON", "warn")]

    vulnerabilities = payload.get("vulnerabilities") or []
    if not vulnerabilities:
        return [f("NVD", f"sin resultados para «{query}»", "info")]

    findings: list[Finding] = [
        f("Resultados", str(payload.get("totalResults", len(vulnerabilities))), "info")
    ]
    for item in vulnerabilities[:20]:
        cve_data = item.get("cve") or {}
        identifier = str(cve_data.get("id") or "")
        descriptions = cve_data.get("descriptions") or []
        description = next(
            (d.get("value", "") for d in descriptions if d.get("lang") == "en"),
            descriptions[0].get("value", "") if descriptions else "",
        )
        metrics = cve_data.get("metrics") or {}
        score = ""
        severity = ""
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            entries = metrics.get(key) or []
            if entries:
                cvss = entries[0].get("cvssData") or {}
                score = str(cvss.get("baseScore", ""))
                severity = str(cvss.get("baseSeverity") or entries[0].get("baseSeverity") or "")
                break
        level = "bad" if severity.upper() in ("CRITICAL", "HIGH") else "warn"
        value = f"{severity or 'sin severidad'} · CVSS {score or '—'} · {truncate(collapse_ws(description), 240)}"
        findings.append(
            f(
                identifier or "CVE",
                value,
                level,
                url=f"https://nvd.nist.gov/vuln/detail/{identifier}" if identifier else "",
                data={"score": score, "severity": severity},
            )
        )
    return findings


@module("circl_cve")
def circl_cve(ctx: Context, tool: Any) -> list[Finding]:
    query = ctx.target.strip()
    cve = _cve_from_target(query)
    if not cve:
        findings = [f("CIRCL", "se esperaba un identificador CVE (CVE-AAAA-NNNN)", "warn")]
        if re.fullmatch(r"\d{4}-\d{4,}", query):
            cve = f"CVE-{query}"
        else:
            return findings
    url = f"https://cve.circl.lu/api/cve/{cve}"
    try:
        data = ctx.http.get_json(url, timeout=30, retries=1)
    except (NetworkError, HttpError, ValueError) as exc:
        return [f("CIRCL", str(exc), "warn", url=f"https://cve.circl.lu/cve/{cve}")]
    if not isinstance(data, dict) or not data:
        return [f("CIRCL", f"sin datos para {cve}", "info")]

    findings: list[Finding] = [
        f(cve, str(data.get("summary") or "sin resumen"), "info", url=f"https://cve.circl.lu/cve/{cve}")
    ]
    cvss = data.get("cvss") or data.get("cvss3")
    if cvss:
        findings.append(f("CVSS", str(cvss), "bad" if _as_float(cvss) >= 7 else "warn"))
    for key, label in (
        ("Published", "Publicado"),
        ("Modified", "Modificado"),
        ("last-modified", "Última modificación"),
        ("cvss-time", "Fecha CVSS"),
    ):
        if data.get(key):
            findings.append(f(label, str(data[key]), "info"))
    vendors = data.get("vendors") or []
    if vendors:
        findings.append(f("Vendedores", join_limited(vendors, 20), "info"))
    products = data.get("products") or []
    if products:
        findings.append(f("Productos", join_limited(products, 20), "info"))
    references = data.get("references") or []
    for ref in references[:15]:
        if isinstance(ref, str):
            findings.append(f("Referencia", ref, "link", url=ref))
        elif isinstance(ref, dict):
            link = str(ref.get("url") or "")
            findings.append(f("Referencia", str(ref.get("name") or link), "link", url=link))
    cwe = data.get("cwe") or data.get("cwe-id")
    if cwe:
        findings.append(f("CWE", str(cwe), "info"))
    return findings


def _as_float(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


@module("epss_score")
def epss_score(ctx: Context, tool: Any) -> list[Finding]:
    query = ctx.target.strip()
    cve = _cve_from_target(query)
    if not cve and re.fullmatch(r"\d{4}-\d{4,}", query):
        cve = f"CVE-{query}"
    if not cve:
        return [f("EPSS", "se esperaba un identificador CVE (CVE-AAAA-NNNN)", "warn")]
    url = "https://api.first.org/data/v1/epss"
    try:
        data = ctx.http.get_json(url, params={"cve": cve}, timeout=30, retries=1)
    except (NetworkError, HttpError, ValueError) as exc:
        return [f("EPSS", str(exc), "warn", url="https://www.first.org/epss/")]
    rows = (data or {}).get("data") or []
    if not rows:
        return [f("EPSS", f"sin puntuación para {cve}", "info")]
    row = rows[0]
    score = _as_float(row.get("epss"))
    percentile = _as_float(row.get("percentile"))
    level = "bad" if score >= 0.7 else ("warn" if score >= 0.2 else "good")
    findings = [
        f("CVE", str(row.get("cve") or cve), "info"),
        f("Probabilidad de explotación", f"{score:.2%}", level),
        f("Percentil", f"{percentile:.2%}", "info"),
    ]
    if row.get("date"):
        findings.append(f("Fecha del modelo", str(row["date"]), "info"))
    findings.append(
        f("Consulta", "EPSS estima la probabilidad de explotación en 30 días", "info",
          url=f"https://www.first.org/epss/")
    )
    return findings


# ---------------------------------------------------------------------------
# Malware e IOC
# ---------------------------------------------------------------------------

@module("urlhaus_url")
def urlhaus_url(ctx: Context, tool: Any) -> list[Finding]:
    if not ctx.has_key("ABUSECH_AUTH_KEY"):
        return _abusec_disabled()
    target = ctx.target if ctx.target.startswith(("http://", "https://")) else f"https://{ctx.target}"
    data = _post_abusec(ctx, "https://urlhaus-api.abuse.ch/v1/url/", {"url": target})
    if data is None:
        return [f("URLhaus", "consulta fallida o clave rechazada", "warn", url="https://urlhaus.abuse.ch/")]
    status = str(data.get("query_status") or "")
    if status == "no_results":
        return [f("URLhaus", f"sin reportes para {target}", "good")]
    if status not in ("ok", ""):
        return [f("URLhaus", f"estado: {status}", "warn")]
    findings: list[Finding] = [f("URL", target, "info", data={"id": data.get("id")})]
    if data.get("url_status"):
        findings.append(f("Estado", str(data["url_status"]), "bad" if data["url_status"] == "online" else "warn"))
    for key, label in (
        ("threat", "Tipo de amenaza"),
        ("date_added", "Añadida"),
        ("last_online", "Última vez en línea"),
        ("reporter", "Reportada por"),
        ("blacklists", "Listas negras"),
        ("tags", "Etiquetas"),
    ):
        value = data.get(key)
        if value:
            findings.append(f(label, join_limited(value, 15) if isinstance(value, list) else str(value), "info"))
    payloads = data.get("payloads") or []
    for payload in payloads[:10]:
        if isinstance(payload, dict):
            findings.append(
                f(
                    "Payload",
                    f"{payload.get('filename') or '—'} · {payload.get('file_type') or ''} · "
                    f"{payload.get('response_sha256') or payload.get('sha256_hash') or ''}",
                    "bad",
                )
            )
    return findings


@module("malwarebazaar")
def malwarebazaar(ctx: Context, tool: Any) -> list[Finding]:
    if not ctx.has_key("ABUSECH_AUTH_KEY"):
        return _abusec_disabled()
    value = ctx.target.strip()
    forms: list[dict[str, str]] = []
    if ctx.kind == "file":
        from ..util import file_hashes

        try:
            forms.append({"query": "get_info", "hash": file_hashes(value)["sha256"]})
        except OSError as exc:
            return [f("MalwareBazaar", str(exc), "warn")]
    else:
        forms.append({"query": "get_info", "hash": value})
        if not re.fullmatch(r"[a-fA-F0-9]{32,64}", value):
            forms = [{"query": "get_taginfo", "tag": value, "limit": "20"}]

    data = None
    for form in forms:
        data = _post_abusec(ctx, "https://mb-api.abuse.ch/api/v1/", form)
        if data is not None:
            break
    if data is None:
        return [f("MalwareBazaar", "consulta fallida o clave rechazada", "warn", url="https://bazaar.abuse.ch/")]
    status = str(data.get("query_status") or "")
    if status == "no_results":
        return [f("MalwareBazaar", "sin resultados", "good")]
    if status not in ("ok", "hash_found", ""):
        return [f("MalwareBazaar", f"estado: {status}", "warn")]

    rows = data.get("data") or []
    if isinstance(rows, dict):
        rows = [rows]
    findings: list[Finding] = [f("Muestras", str(len(rows)), "warn")]
    for row in rows[:20]:
        if not isinstance(row, dict):
            continue
        name = str(row.get("file_name") or row.get("signature") or "muestra")
        sha = str(row.get("sha256_hash") or "")
        findings.append(
            f(
                name,
                f"{row.get('file_type_mime') or row.get('file_type') or '—'} · "
                f"{row.get('signature') or 'sin firma'} · primera vez {row.get('first_seen') or '—'}",
                "bad",
                url=f"https://bazaar.abuse.ch/sample/{sha}/" if sha else "",
                data={"sha256": sha, "md5": row.get("md5_hash"), "tags": row.get("tags")},
            )
        )
        if row.get("delivery_method"):
            findings.append(f("Entrega", str(row["delivery_method"]), "info"))
    return findings


@module("threatfox")
def threatfox(ctx: Context, tool: Any) -> list[Finding]:
    if not ctx.has_key("ABUSECH_AUTH_KEY"):
        return _abusec_disabled()
    target = ctx.target.strip()
    data = _post_abusec(
        ctx,
        "https://threatfox-api.abuse.ch/api/v1/",
        {"query": "search_ioc", "search_term": target, "exact_match": "true"},
    )
    if data is None:
        return [f("ThreatFox", "consulta fallida o clave rechazada", "warn", url="https://threatfox.abuse.ch/")]
    status = str(data.get("query_status") or "")
    if status == "no_results":
        return [f("ThreatFox", f"sin IOCs para {target}", "good")]
    if status not in ("ok", ""):
        return [f("ThreatFox", f"estado: {status}", "warn")]

    rows = data.get("data") or []
    findings: list[Finding] = [f("IOC", target, "info"), f("Coincidencias", str(len(rows)), "warn")]
    for row in rows[:25]:
        if not isinstance(row, dict):
            continue
        malware = str(row.get("malware_printable") or row.get("malware") or "desconocido")
        ioc = str(row.get("ioc") or target)
        findings.append(
            f(
                malware,
                f"{row.get('ioc_type') or '—'} · confianza {row.get('confidence_level', '—')}% · "
                f"{row.get('first_seen') or '—'}",
                "bad",
                data={
                    "ioc": ioc,
                    "threat_type": row.get("threat_type"),
                    "tags": row.get("tags"),
                    "reference": row.get("reference"),
                },
            )
        )
    return findings


@module("feodo_tracker")
def feodo_tracker(ctx: Context, tool: Any) -> list[Finding]:
    ip = ctx.target.strip()
    if not is_ip(ip):
        from .base import ip_for

        resolved = ip_for(ctx)
        ip = resolved or ip
    if not ip:
        return [f("Feodo Tracker", "no se pudo resolver una IP", "warn")]
    try:
        response = ctx.http.get(
            "https://feodotracker.abuse.ch/downloads/ipblocklist.json",
            timeout=40,
            retries=1,
        )
    except (NetworkError, HttpError) as exc:
        return [f("Feodo Tracker", str(exc), "warn")]
    if not response.ok:
        return [f("Feodo Tracker", f"HTTP {response.status}", "warn")]
    try:
        rows = response.json()
    except ValueError:
        return [f("Feodo Tracker", "respuesta no JSON", "warn")]
    if isinstance(rows, dict):
        rows = rows.get("data") or rows.get("blocklist") or []
    matches = [
        row for row in rows
        if isinstance(row, dict) and str(row.get("ip_address") or row.get("ip") or "") == ip
    ]
    if not matches:
        return [f("Feodo Tracker", f"{ip} no aparece en la lista de C2", "good")]
    findings: list[Finding] = [f("IP", ip, "info")]
    for row in matches:
        port = row.get("port")
        port_text = describe_port(port) if port not in (None, "") else "puerto —"
        findings.append(
            f(
                str(row.get("malware") or "C2"),
                f"{port_text} · estado {row.get('status') or '—'} · "
                f"visto {row.get('last_online') or row.get('first_seen') or '—'}",
                "bad",
                data=row,
            )
        )
    return findings


@module("virustotal_file")
def virustotal_file(ctx: Context, tool: Any) -> list[Finding]:
    if ctx.kind != "file":
        return [f("VirusTotal", "este módulo espera la ruta de un archivo", "warn")]
    from ..util import file_hashes

    try:
        hashes = file_hashes(ctx.target)
    except OSError as exc:
        return [f("VirusTotal", str(exc), "warn")]
    sha256 = hashes["sha256"]
    url = f"https://www.virustotal.com/api/v3/files/{sha256}"
    try:
        response = ctx.http.get(
            url,
            headers={"x-apikey": ctx.key("VIRUSTOTAL_API_KEY")},
            timeout=40,
            retries=1,
        )
    except (NetworkError, HttpError) as exc:
        return [f("VirusTotal", str(exc), "warn")]
    if response.status in (401, 403):
        return [f("VirusTotal", "clave API inválida o sin permisos", "warn")]
    if response.status == 404:
        return [f("VirusTotal", f"el archivo no está en VirusTotal ({sha256})", "info")]
    if response.status == 429:
        return [f("VirusTotal", "límite de la API alcanzado (429)", "warn")]
    if not response.ok:
        return [f("VirusTotal", f"HTTP {response.status}", "warn")]
    try:
        payload = response.json()
    except ValueError:
        return [f("VirusTotal", "respuesta no JSON", "warn")]

    attributes = ((payload.get("data") or {}).get("attributes") or {})
    stats = attributes.get("last_analysis_stats") or {}
    malicious = int(stats.get("malicious", 0))
    suspicious = int(stats.get("suspicious", 0))
    findings: list[Finding] = [
        f("SHA-256", sha256, "info"),
        f("SHA-1", hashes["sha1"], "info"),
        f("MD5", hashes["md5"], "info"),
        f(
            "Detecciones",
            f"{malicious} maliciosas · {suspicious} sospechosas",
            "bad" if malicious else ("warn" if suspicious else "good"),
            url=f"https://www.virustotal.com/gui/file/{sha256}",
        ),
    ]
    for key, label in (
        ("type_description", "Tipo"),
        ("meaningful_name", "Nombre"),
        ("size", "Tamaño"),
        ("reputation", "Reputación"),
    ):
        if attributes.get(key) not in (None, ""):
            findings.append(f(label, str(attributes[key]), "info"))
    if attributes.get("tags"):
        findings.append(f("Etiquetas", join_limited(attributes["tags"], 20), "info"))
    names = attributes.get("names") or []
    if names:
        findings.append(f("Nombres", join_limited(names, 10), "info"))
    return findings
