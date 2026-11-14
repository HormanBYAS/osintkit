"""Módulos de DNS, certificados y WHOIS."""  # noqa: D415

from __future__ import annotations

import json
import re
import shutil
import subprocess
from typing import Any

from ..core import Context, Finding, module
from ..http import HttpError, NetworkError
from ..util import days_until, dedupe, normalize_domain, parse_datetime, truncate
from .base import (
    doh,
    doh_answers,
    doh_txt,
    doh_values,
    domain_for,
    f,
    join_limited,
    resolve_ips,
)

DNS_TYPES = {
    "A": "A",
    "AAAA": "AAAA",
    "MX": "MX",
    "NS": "NS",
    "TXT": "TXT",
    "SOA": "SOA",
    "CNAME": "CNAME",
    "CAA": "CAA",
    "SRV": "SRV",
}


@module("dns_records")
def dns_records(ctx: Context, tool: Any) -> list[Finding]:
    domain = domain_for(ctx)
    findings: list[Finding] = []
    summary: dict[str, list[str]] = {}
    for label, rtype in DNS_TYPES.items():
        try:
            data = doh(ctx, domain, rtype)
        except NetworkError as exc:
            findings.append(f(f"{label}", str(exc), "warn"))
            continue
        values = []
        for answer in data.get("Answer") or []:
            value = str(answer.get("data", "")).strip()
            if value:
                values.append(value)
        values = dedupe(values)
        summary[label] = values
        if not values:
            findings.append(f(f"Registro {label}", "sin registros", "info"))
            continue
        for value in values[:20]:
            level = "info"
            if label == "TXT":
                lower = value.lower()
                if "v=spf1" in lower and ("+all" in lower or "?all" in lower):
                    level = "warn"
                if "v=spf1" in lower:
                    level = "good"
            elif label in ("A", "AAAA"):
                level = "good"
            findings.append(f(f"{label}", value, level, data={"type": label}))
        if len(values) > 20:
            findings.append(f(f"{label} (resto)", f"{len(values) - 20} registros más", "info"))

    ns = summary.get("NS") or []
    if ns:
        findings.append(f("Nameservers", join_limited(ns, 10), "info"))
    mx = summary.get("MX") or []
    if mx:
        findings.append(f("Proveedor de correo", join_limited(mx, 10), "info"))
    if not (summary.get("A") or summary.get("AAAA")):
        findings.append(f("Resolución", "el dominio no resuelve a ninguna IP", "warn"))
    return findings


@module("dns_email_security")
def dns_email_security(ctx: Context, tool: Any) -> list[Finding]:
    domain = domain_for(ctx)
    findings: list[Finding] = []
    txt = doh_txt(ctx, domain)
    spf = next((t for t in txt if t.lower().startswith("v=spf1")), "")
    if not spf:
        findings.append(f("SPF", "no se encontró registro SPF", "warn"))
    else:
        level = "good"
        warnings = []
        lower = spf.lower()
        if "+all" in lower:
            level = "bad"
            warnings.append("+all permite que cualquiera envíe como el dominio")
        elif "?all" in lower or "~all" not in lower and "-all" not in lower:
            level = "warn"
            warnings.append("política final débil (se espera ~all o -all)")
        if "redirect=" in lower:
            warnings.append("usa redirect= (revisar el destino)")
        findings.append(f("SPF", spf, level, data={"warnings": warnings}))
        lookups = len(re.findall(r"\b(?:include:|a|mx|ptr|exists:|redirect=)", lower))
        if lookups > 10:
            findings.append(f("SPF lookups", f"{lookups} mecanismos; el límite recomendado es 10", "warn"))

    dmarc_records = doh_txt(ctx, f"_dmarc.{domain}")
    dmarc = next((t for t in dmarc_records if t.lower().startswith("v=dmarc1")), "")
    if not dmarc:
        findings.append(f("DMARC", "no hay política DMARC", "warn"))
    else:
        policy = re.search(r"\bp\s*=\s*(none|quarantine|reject)", dmarc, re.I)
        policy_value = policy.group(1).lower() if policy else "?"
        level = {"reject": "good", "quarantine": "good", "none": "warn"}.get(policy_value, "warn")
        findings.append(f("DMARC", dmarc, level, data={"policy": policy_value}))
        if policy_value == "none":
            findings.append(f("DMARC", "p=none solo monitorea; no bloquea suplantación", "warn"))
        if "rua=" in dmarc.lower():
            findings.append(f("DMARC reportes", "tiene dirección de reportes agregados", "info"))

    selectors = ("default", "google", "selector1", "selector2", "k1", "mail", "dkim", "s1", "s2", "smtp", "mandrill", "amazonses")
    found = []
    for selector in selectors:
        values = doh_txt(ctx, f"{selector}._domainkey.{domain}")
        if values:
            found.append((selector, values[0]))
    if found:
        for selector, value in found:
            findings.append(
                f(f"DKIM {selector}", truncate(value, 300), "good", data={"selector": selector})
            )
    else:
        findings.append(f("DKIM", "no se detectaron selectores comunes", "info"))

    bimi = doh_txt(ctx, f"default._bimi.{domain}")
    if bimi:
        findings.append(f("BIMI", bimi[0], "info"))
    mta_sts = doh_txt(ctx, f"_mta-sts.{domain}")
    if mta_sts:
        findings.append(f("MTA-STS", mta_sts[0], "good"))
    tls_rpt = doh_txt(ctx, f"_smtp._tls.{domain}")
    if tls_rpt:
        findings.append(f("TLS-RPT", tls_rpt[0], "good"))
    return findings


@module("dns_dnssec")
def dns_dnssec(ctx: Context, tool: Any) -> list[Finding]:
    domain = domain_for(ctx)
    findings: list[Finding] = []
    try:
        response = doh(ctx, domain, "A")
    except NetworkError as exc:
        return [f("DNSSEC", str(exc), "warn")]
    ad = bool(response.get("AD"))
    ds = doh_values(ctx, domain, "DS")
    dnskey = doh_values(ctx, domain, "DNSKEY")
    if ds or dnskey:
        findings.append(f("DNSSEC", "la zona publica DS/DNSKEY", "good"))
        findings.append(f("DS", join_limited(ds, 5), "info"))
        findings.append(f("DNSKEY", f"{len(dnskey)} clave(s) publicada(s)", "info"))
    else:
        findings.append(f("DNSSEC", "no se encontraron registros DS ni DNSKEY", "warn"))
    findings.append(
        f(
            "Validación del resolutor",
            "el resolutor validó DNSSEC (AD=1)" if ad else "el resolutor no marcó AD=1",
            "good" if ad else "warn",
        )
    )
    return findings


# ---------------------------------------------------------------------------
# RDAP / WHOIS
# ---------------------------------------------------------------------------

def _vcard_fields(vcard: list[Any]) -> dict[str, list[str]]:
    fields: dict[str, list[str]] = {}
    if not isinstance(vcard, list) or len(vcard) < 2 or not isinstance(vcard[1], list):
        return fields
    for item in vcard[1]:
        if not isinstance(item, list) or len(item) < 4:
            continue
        name = str(item[0]).lower()
        value = item[3]
        if isinstance(value, list):
            value = " ".join(str(v) for v in value)
        if value is None or str(value).strip() == "":
            continue
        fields.setdefault(name, []).append(str(value).strip())
    return fields


def _collect_entities(entities: list[Any], roles_wanted: set[str] | None = None) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for entity in entities or []:
        if not isinstance(entity, dict):
            continue
        roles = set(entity.get("roles") or [])
        vcard = _vcard_fields(entity.get("vcardArray") or [])
        if roles and (roles_wanted is None or roles & roles_wanted):
            out.append({"roles": sorted(roles), "fields": vcard})
        out.extend(_collect_entities(entity.get("entities") or [], roles_wanted))
    return out


def _rdap_bootstrap(tld: str, ctx: Context) -> list[str]:
    data = None
    try:
        response = ctx.http.get("https://data.iana.org/rdap/dns.json", timeout=15, retries=1)
        if response.ok:
            data = response.json()
    except (NetworkError, HttpError, ValueError):
        data = None
    if not isinstance(data, dict):
        return []
    tld = tld.lower()
    for service in data.get("services") or []:
        if not isinstance(service, list) or len(service) < 2:
            continue
        tlds, urls = service[0], service[1]
        if tld in [str(x).lower() for x in tlds]:
            return [str(u).rstrip("/") for u in urls]
    return []


def _rdap_try(ctx: Context, urls: list[str], suffix: str) -> dict[str, Any] | None:
    for base in urls:
        url = base.rstrip("/") + "/" + suffix.lstrip("/")
        try:
            response = ctx.http.get(url, timeout=25, retries=1)
        except (NetworkError, HttpError):
            continue
        if response.ok:
            try:
                data = response.json()
            except ValueError:
                continue
            if isinstance(data, dict) and not data.get("errorCode"):
                return data
    return None


def _parse_events(events: list[Any]) -> dict[str, str]:
    out: dict[str, str] = {}
    for event in events or []:
        if not isinstance(event, dict):
            continue
        action = str(event.get("eventAction", "")).lower()
        date = str(event.get("eventDate", ""))
        if action:
            out[action] = date
    return out


def _whois_cli(ctx: Context, target: str) -> list[Finding]:
    if not shutil.which("whois"):
        return []
    try:
        proc = subprocess.run(
            ["whois", target], capture_output=True, text=True, errors="replace", timeout=30, check=False
        )
    except (OSError, subprocess.TimeoutExpired):
        return []
    findings: list[Finding] = []
    for line in (proc.stdout or "").splitlines():
        if ":" in line:
            key, value = line.split(":", 1)
            key = key.strip()
            value = value.strip()
            if key and value and not value.startswith("%") and len(value) < 500:
                findings.append(f(key, value, "info", data={"source": "whois"}))
    return findings[:120]


@module("whois")
def whois(ctx: Context, tool: Any) -> list[Finding]:
    findings: list[Finding] = []
    if ctx.kind == "domain":
        domain = domain_for(ctx)
        tld = domain.rsplit(".", 1)[-1]
        urls = _rdap_bootstrap(tld, ctx) + ["https://rdap.org"]
        data = _rdap_try(ctx, urls, f"domain/{domain}")
        if data:
            findings.append(f("Dominio", data.get("ldhName", domain), "good"))
            status = data.get("status") or []
            if status:
                findings.append(f("Estados", join_limited(status, 15), "info"))
            events = _parse_events(data.get("events") or [])
            labels = {
                "registration": "Creado",
                "expiration": "Vence",
                "last changed": "Último cambio",
                "last update of rdap database": "Actualizado",
                "transfer": "Transferencia",
            }
            for key, label in labels.items():
                if events.get(key):
                    level = "info"
                    if key == "expiration":
                        days = days_until(events[key])
                        if days is not None and days < 30:
                            level = "bad"
                        elif days is not None and days < 90:
                            level = "warn"
                        findings.append(f(label, f"{events[key]} ({days} días)" if days is not None else events[key], level))
                    else:
                        findings.append(f(label, events[key], level))
            nameservers = [
                str(ns.get("ldhName", "")).rstrip(".")
                for ns in (data.get("nameservers") or [])
                if isinstance(ns, dict) and ns.get("ldhName")
            ]
            if nameservers:
                findings.append(f("Nameservers", join_limited(nameservers, 15), "info"))
            entities = _collect_entities(data.get("entities") or [])
            for entity in entities[:15]:
                roles = ", ".join(entity["roles"]) or "contacto"
                fields = entity["fields"]
                bits = []
                for key in ("fn", "org", "email", "tel", "adr"):
                    if fields.get(key):
                        bits.append(f"{key}: {', '.join(fields[key][:2])}")
                value = "; ".join(bits) or "(datos redactados)"
                level = "warn" if any(r in entity["roles"] for r in ("registrant", "administrative")) else "info"
                findings.append(f("Contacto", f"{roles} · {value}", level, data={"roles": entity["roles"]}))
        else:
            findings.append(f("RDAP", "no respondió; se intenta whois clásico", "warn"))
            findings.extend(_whois_cli(ctx, domain))
            if len(findings) <= 1:
                findings.append(
                    f("Alternativa web", "https://www.whois.com/whois/" + domain, "link",
                      url="https://www.whois.com/whois/" + domain)
                )
    else:
        ip = ctx.target
        urls = ["https://rdap.org"] + [
            "https://rdap.arin.net/registry",
            "https://rdap.db.ripe.net",
            "https://rdap.apnic.net",
            "https://rdap.lacnic.net/rdap",
            "https://rdap.afrinic.net/rdap",
        ]
        data = _rdap_try(ctx, urls, f"ip/{ip}")
        if data:
            findings.append(f("IP", data.get("handle", ip), "good"))
            if data.get("name"):
                findings.append(f("Red", data["name"], "info"))
            if data.get("startAddress") and data.get("endAddress"):
                findings.append(f("Rango", f"{data['startAddress']} - {data['endAddress']}", "info"))
            for entity in _collect_entities(data.get("entities") or [], {"registrant", "administrative", "technical", "abuse"}):
                fields = entity["fields"]
                bits = [f"{k}: {', '.join(fields[k][:2])}" for k in ("fn", "org", "email", "adr") if fields.get(k)]
                findings.append(f("Contacto", f"{', '.join(entity['roles'])} · {'; '.join(bits) or '(redactado)'}", "info"))
        else:
            findings.extend(_whois_cli(ctx, ip))
            if not findings:
                findings.append(f("RDAP", "sin respuesta para la IP", "warn"))
    return findings


# ---------------------------------------------------------------------------
# Certificate Transparency y fuentes pasivas
# ---------------------------------------------------------------------------

def _crtsh_rows(ctx: Context, domain: str) -> tuple[list[dict[str, Any]], Finding | None]:
    url = "https://crt.sh/"
    try:
        response = ctx.http.get(
            url,
            params={"q": f"%.{domain}", "output": "json"},
            timeout=45,
            retries=1,
            max_bytes=10_000_000,
        )
    except (NetworkError, HttpError) as exc:
        return [], f("crt.sh", f"no disponible: {exc}", "warn")
    if not response.ok:
        return [], f("crt.sh", f"HTTP {response.status}; suele estar limitado o caído", "warn")
    try:
        data = json.loads(response.text)
    except ValueError:
        return [], f("crt.sh", "respuesta no JSON (posible límite de tasa)", "warn")
    if not isinstance(data, list):
        return [], f("crt.sh", "respuesta inesperada", "warn")
    return [row for row in data if isinstance(row, dict)], None


@module("crtsh_subdomains")
def crtsh_subdomains(ctx: Context, tool: Any) -> list[Finding]:
    domain = domain_for(ctx)
    rows, error = _crtsh_rows(ctx, domain)
    if error:
        return [error]
    names: list[str] = []
    wildcard: list[str] = []
    for row in rows:
        for field in ("name_value", "common_name"):
            raw = str(row.get(field, ""))
            for name in raw.splitlines():
                name = name.strip().lower().rstrip(".")
                if not name or "@" in name:
                    continue
                if name.startswith("*."):
                    wildcard.append(name[2:])
                    name = name[2:]
                if name == domain or not name.endswith("." + domain):
                    continue
                names.append(name)
    names = dedupe(names)
    wildcard = dedupe(wildcard)
    findings: list[Finding] = [
        f("Subdominios únicos", str(len(names)), "good" if names else "info"),
        f("Certificados analizados", str(len(rows)), "info"),
    ]
    if wildcard:
        findings.append(f("Wildcards", join_limited(wildcard, 20), "info"))
    for name in names[:300]:
        findings.append(f("Subdominio", name, "info", data={"source": "crt.sh"}))
    if len(names) > 300:
        findings.append(f("Subdominios (resto)", f"{len(names) - 300} más", "info"))
    return findings


@module("crtsh_certificates")
def crtsh_certificates(ctx: Context, tool: Any) -> list[Finding]:
    domain = domain_for(ctx)
    rows, error = _crtsh_rows(ctx, domain)
    if error:
        return [error]
    issuers: dict[str, int] = {}
    dates: list[str] = []
    sans: list[str] = []
    for row in rows:
        issuer = str(row.get("issuer_name", "")).strip()
        if issuer:
            issuers[issuer] = issuers.get(issuer, 0) + 1
        for field in ("not_before", "not_after"):
            value = str(row.get(field, "")).strip()
            if value:
                dates.append(value)
        for field in ("name_value", "common_name"):
            for name in str(row.get(field, "")).splitlines():
                name = name.strip().lower()
                if name and name not in sans:
                    sans.append(name)
    findings: list[Finding] = [
        f("Certificados", str(len(rows)), "info"),
        f("Emisores distintos", str(len(issuers)), "info"),
    ]
    for issuer, count in sorted(issuers.items(), key=lambda kv: kv[1], reverse=True)[:10]:
        findings.append(f("Emisor", f"{issuer} ({count})", "info"))
    if dates:
        findings.append(f("Ventana temporal", f"{min(dates)} → {max(dates)}", "info"))
    for name in sans[:120]:
        findings.append(f("SAN", name, "info"))
    return findings


@module("hackertarget_hostsearch")
def hackertarget_hostsearch(ctx: Context, tool: Any) -> list[Finding]:
    domain = domain_for(ctx)
    try:
        response = ctx.http.get(
            "https://api.hackertarget.com/hostsearch/",
            params={"q": domain},
            timeout=25,
            retries=1,
        )
    except (NetworkError, HttpError) as exc:
        return [f("HackerTarget", str(exc), "warn")]
    text = response.text.strip()
    if not text or "error" in text.lower() or "API count exceeded" in text:
        return [f("HackerTarget", text[:300] or f"HTTP {response.status}", "warn")]
    findings: list[Finding] = []
    hosts: list[str] = []
    for line in text.splitlines():
        if "," not in line:
            continue
        host, ip = [x.strip() for x in line.split(",", 1)]
        if host:
            hosts.append(host)
            findings.append(f("Host", f"{host} → {ip}", "info", data={"ip": ip}))
    findings.insert(0, f("Hosts encontrados", str(len(dedupe(hosts))), "good" if hosts else "info"))
    return findings[:300]


@module("otx_passive_dns")
def otx_passive_dns(ctx: Context, tool: Any) -> list[Finding]:
    domain = domain_for(ctx)
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
    data = None
    try:
        response = ctx.http.get(url, timeout=25, retries=1)
        if response.status == 429:
            return [f("OTX", "límite de tasa alcanzado (429); probá más tarde", "warn")]
        if response.ok:
            data = response.json()
    except (NetworkError, HttpError, ValueError) as exc:
        return [f("OTX", f"no disponible: {exc}", "warn")]
    records = (data or {}).get("passive_dns") or []
    findings: list[Finding] = []
    seen: set[tuple[str, str]] = set()
    for record in records:
        if not isinstance(record, dict):
            continue
        hostname = str(record.get("hostname", "")).strip()
        address = str(record.get("address", "")).strip()
        rtype = str(record.get("record_type", "")).strip()
        key = (hostname, address)
        if not hostname or key in seen:
            continue
        seen.add(key)
        findings.append(
            f("Registro pasivo", f"{hostname} → {address} ({rtype})", "info",
              data={"first": record.get("first"), "last": record.get("last")})
        )
    findings.insert(0, f("Registros OTX", str(len(seen)), "good" if seen else "info"))
    return findings[:300]


@module("commoncrawl_index")
def commoncrawl_index(ctx: Context, tool: Any) -> list[Finding]:
    domain = domain_for(ctx)
    try:
        coll = ctx.http.get("https://index.commoncrawl.org/collinfo.json", timeout=20, retries=1)
        collections = coll.json() if coll.ok else []
    except (NetworkError, HttpError, ValueError):
        collections = []
    collection = ""
    if isinstance(collections, list) and collections:
        collection = str(collections[0].get("id", ""))
    if not collection:
        collection = "CC-MAIN-2024-10"
    url = f"https://index.commoncrawl.org/{collection}-index"
    try:
        response = ctx.http.get(
            url,
            params={"url": f"*.{domain}", "output": "json", "limit": "100"},
            timeout=40,
            retries=1,
        )
    except (NetworkError, HttpError) as exc:
        return [f("Common Crawl", f"{exc}", "warn")]
    if not response.ok:
        return [f("Common Crawl", f"HTTP {response.status} para {collection}", "warn")]
    lines = [line for line in response.text.splitlines() if line.strip()]
    findings: list[Finding] = [
        f("Colección", collection, "info"),
        f("URLs", str(len(lines)), "good" if lines else "info"),
    ]
    for line in lines[:100]:
        try:
            row = json.loads(line)
        except ValueError:
            continue
        if not isinstance(row, dict):
            continue
        url_value = row.get("url", "")
        status = row.get("status", "")
        mime = row.get("mime", "")
        findings.append(f("URL", f"{url_value} [{status} {mime}]", "info"))
    return findings


# ---------------------------------------------------------------------------
# WHOIS de dominio con fallback a subprocess (por si RDAP falla)
# ---------------------------------------------------------------------------

@module("dns_whois_fallback")
def _unused(ctx: Context, tool: Any) -> list[Finding]:  # pragma: no cover
    return []
