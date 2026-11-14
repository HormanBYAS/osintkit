"""Módulos de organizaciones, registros, sanciones y geocodificación."""

from __future__ import annotations

import base64
import html
import re
import xml.etree.ElementTree as ET
from typing import Any

from ..core import Context, Finding, module
from ..http import HttpError, NetworkError
from ..util import collapse_ws, dedupe, truncate
from .base import f, join_limited, safe_get, safe_json, strip_tags


@module("wikidata_search")
def wikidata_search(ctx: Context, tool: Any) -> list[Finding]:
    query = ctx.target
    try:
        data = ctx.http.get_json(
            "https://www.wikidata.org/w/api.php",
            params={
                "action": "wbsearchentities",
                "search": query,
                "language": "es",
                "uselang": "es",
                "format": "json",
                "limit": "10",
                "origin": "*",
            },
            timeout=25,
            retries=1,
        )
    except (NetworkError, HttpError, ValueError) as exc:
        # Reintento en inglés si el idioma español falla.
        try:
            data = ctx.http.get_json(
                "https://www.wikidata.org/w/api.php",
                params={"action": "wbsearchentities", "search": query, "language": "en",
                        "format": "json", "limit": "10", "origin": "*"},
                timeout=25,
                retries=1,
            )
        except (NetworkError, HttpError, ValueError):
            return [f("Wikidata", f"no disponible: {exc}", "warn")]
    results = (data or {}).get("search") or []
    if not results:
        return [f("Wikidata", "sin resultados", "info")]
    findings: list[Finding] = [f("Resultados", str(len(results)), "info")]
    for item in results[:10]:
        if not isinstance(item, dict):
            continue
        qid = item.get("id", "")
        label = item.get("label") or qid
        description = item.get("description") or ""
        findings.append(
            f("Entidad", f"{label} ({qid}) · {description}", "info",
            url=f"https://www.wikidata.org/wiki/{qid}", data={"concept": item.get("concepturi")}
        ))
    return findings


def _wikipedia_lang(ctx: Context, lang: str, query: str) -> Any:
    try:
        return ctx.http.get_json(
            f"https://{lang}.wikipedia.org/w/api.php",
            params={
                "action": "query", "list": "search", "srsearch": query,
                "format": "json", "srlimit": "10", "utf8": "1",
            },
            timeout=25,
            retries=1,
        )
    except (NetworkError, HttpError, ValueError):
        return None


@module("wikipedia_search")
def wikipedia_search(ctx: Context, tool: Any) -> list[Finding]:
    data = _wikipedia_lang(ctx, "es", ctx.target) or _wikipedia_lang(ctx, "en", ctx.target)
    results = (((data or {}).get("query") or {}).get("search") or []) if isinstance(data, dict) else []
    if not results:
        return [f("Wikipedia", "sin resultados", "info")]
    findings: list[Finding] = [f("Resultados", str(len(results)), "info")]
    for item in results[:10]:
        if not isinstance(item, dict):
            continue
        title = str(item.get("title", ""))
        snippet = strip_tags(str(item.get("snippet", "")))
        findings.append(
            f("Artículo", f"{title} · {truncate(snippet, 220)}", "info",
            url="https://es.wikipedia.org/wiki/" + title.replace(" ", "_"),
            data={"wordcount": item.get("wordcount"), "timestamp": item.get("timestamp")}
        ))
    return findings


@module("gleif_lei")
def gleif_lei(ctx: Context, tool: Any) -> list[Finding]:
    try:
        response = ctx.http.get(
            "https://api.gleif.org/api/v1/lei-records",
            params={"filter[entity.legalName]": ctx.target, "page[size]": "10"},
            timeout=30,
            retries=1,
        )
    except (NetworkError, HttpError) as exc:
        return [f("GLEIF", str(exc), "warn")]
    if not response.ok:
        return [f("GLEIF", f"HTTP {response.status}", "warn")]
    try:
        data = response.json().get("data") or []
    except ValueError:
        return [f("GLEIF", "respuesta no JSON", "warn")]
    if not data:
        return [f("GLEIF", "sin entidades", "info")]
    findings: list[Finding] = [f("Entidades", str(len(data)), "info")]
    for item in data[:10]:
        if not isinstance(item, dict):
            continue
        attrs = item.get("attributes") or {}
        entity = attrs.get("entity") or {}
        name = (entity.get("legalName") or {}).get("name") or ""
        address = entity.get("legalAddress") or {}
        parts = [address.get("addressLines"), address.get("city"), address.get("country")]
        address_text = ", ".join(str(p) for p in parts if p)
        findings.append(
            f("LEI", f"{name} · {attrs.get('lei') or item.get('id')}", "info",
            url=f"https://search.gleif.org/#/record/{attrs.get('lei') or item.get('id')}",
            data={"status": attrs.get("registration", {}).get("status"), "address": address_text}
        ))
    return findings


@module("sec_edgar")
def sec_edgar(ctx: Context, tool: Any) -> list[Finding]:
    headers = {"User-Agent": "osintkit/1.0 (contact: osintkit@example.invalid)"}
    try:
        response = ctx.http.get(
            "https://www.sec.gov/cgi-bin/browse-edgar",
            params={
                "action": "getcompany", "company": ctx.target, "type": "10-K",
                "dateb": "", "owner": "include", "count": "40", "output": "atom",
            },
            headers=headers,
            timeout=30,
            retries=1,
        )
    except (NetworkError, HttpError) as exc:
        return [f("SEC EDGAR", str(exc), "warn")]
    if not response.ok:
        return [f("SEC EDGAR", f"HTTP {response.status}", "warn")]
    try:
        root = ET.fromstring(response.text)
    except ET.ParseError:
        return [f("SEC EDGAR", "respuesta XML inválida", "warn")]
    ns = {"a": "http://www.w3.org/2005/Atom"}
    entries = root.findall("a:entry", ns)
    findings: list[Finding] = [f("Presentaciones", str(len(entries)), "info")]
    for entry in entries[:20]:
        title = collapse_ws(entry.findtext("a:title", default="", namespaces=ns))
        updated = entry.findtext("a:updated", default="", namespaces=ns)
        link_el = entry.find("a:link", ns)
        link = link_el.get("href") if link_el is not None else ""
        summary = strip_tags(entry.findtext("a:summary", default="", namespaces=ns))
        findings.append(
            f("Documento", f"{title} · {updated} · {truncate(summary, 160)}", "info",
            url=link
        ))
    if not entries:
        findings.append(f("SEC EDGAR", "sin presentaciones para la búsqueda", "info"))
    return findings


@module("opensanctions")
def opensanctions(ctx: Context, tool: Any) -> list[Finding]:
    headers = {}
    if ctx.has_key("OPENSANCTIONS_API_KEY"):
        headers["Authorization"] = "ApiKey " + ctx.key("OPENSANCTIONS_API_KEY")
    try:
        response = ctx.http.get(
            "https://api.opensanctions.org/search/default",
            params={"q": ctx.target, "limit": "10"},
            headers=headers,
            timeout=30,
            retries=1,
        )
    except (NetworkError, HttpError) as exc:
        return [f("OpenSanctions", str(exc), "warn")]
    if response.status in (401, 403):
        return [f("OpenSanctions", "requiere API key o límite excedido", "warn")]
    if response.status == 429:
        return [f("OpenSanctions", "límite alcanzado", "warn")]
    if not response.ok:
        return [f("OpenSanctions", f"HTTP {response.status}", "warn")]
    try:
        data = response.json()
    except ValueError:
        return [f("OpenSanctions", "respuesta no JSON", "warn")]
    results = data.get("results") or []
    findings: list[Finding] = [f("Coincidencias", str(len(results)), "warn" if results else "good")]
    for item in results[:10]:
        if not isinstance(item, dict):
            continue
        caption = item.get("caption") or item.get("id") or ""
        schema = item.get("schema") or ""
        score = item.get("score")
        datasets = item.get("datasets") or []
        findings.append(
            f("Entidad", f"{caption} · {schema} · score {score}", "warn",
            url=f"https://www.opensanctions.org/entities/{item.get('id')}/",
            data={"datasets": datasets, "properties": item.get("properties")}
        ))
    return findings


@module("opencorporates")
def opencorporates(ctx: Context, tool: Any) -> list[Finding]:
    try:
        response = ctx.http.get(
            "https://api.opencorporates.com/v0.4/companies/search",
            params={"q": ctx.target, "api_token": ctx.key("OPENCORPORATES_API_KEY"), "per_page": "10"},
            timeout=30,
            retries=1,
        )
    except (NetworkError, HttpError) as exc:
        return [f("OpenCorporates", str(exc), "warn")]
    if response.status in (401, 403):
        return [f("OpenCorporates", "clave inválida", "warn")]
    if not response.ok:
        return [f("OpenCorporates", f"HTTP {response.status}", "warn")]
    try:
        data = response.json()
    except ValueError:
        return [f("OpenCorporates", "respuesta no JSON", "warn")]
    companies = (((data.get("results") or {}).get("companies") or [])) if isinstance(data, dict) else []
    findings: list[Finding] = [f("Empresas", str(len(companies)), "info")]
    for wrapper in companies[:10]:
        company = wrapper.get("company") if isinstance(wrapper, dict) else None
        if not isinstance(company, dict):
            continue
        findings.append(
            f("Empresa", f"{company.get('name')} · {company.get('company_number')} · {company.get('jurisdiction_code')}", "info",
            url=str(company.get("opencorporates_url", "")),
            data={"status": company.get("current_status"), "created": company.get("incorporation_date"),
                  "type": company.get("company_type")}
        ))
    return findings


@module("companies_house")
def companies_house(ctx: Context, tool: Any) -> list[Finding]:
    key = ctx.key("COMPANIES_HOUSE_API_KEY")
    auth = base64.b64encode((key + ":").encode()).decode()
    try:
        response = ctx.http.get(
            "https://api.company-information.service.gov.uk/search/companies",
            params={"q": ctx.target, "items_per_page": "10"},
            headers={"Authorization": f"Basic {auth}"},
            timeout=30,
            retries=1,
        )
    except (NetworkError, HttpError) as exc:
        return [f("Companies House", str(exc), "warn")]
    if response.status in (401, 403):
        return [f("Companies House", "clave inválida", "warn")]
    if not response.ok:
        return [f("Companies House", f"HTTP {response.status}", "warn")]
    try:
        data = response.json()
    except ValueError:
        return [f("Companies House", "respuesta no JSON", "warn")]
    items = data.get("items") or []
    findings: list[Finding] = [f("Empresas", str(len(items)), "info")]
    for item in items[:10]:
        if not isinstance(item, dict):
            continue
        findings.append(
            f("Empresa", f"{item.get('title')} · {item.get('company_number')} · {item.get('company_status')}", "info",
            url=f"https://find-and-update.company-information.service.gov.uk/company/{item.get('company_number')}",
            data={"created": item.get("date_of_creation"), "type": item.get("company_type"),
                  "address": item.get("address_snippet")}
        ))
    return findings


@module("nominatim")
def nominatim(ctx: Context, tool: Any) -> list[Finding]:
    try:
        response = ctx.http.get(
            "https://nominatim.openstreetmap.org/search",
            params={"q": ctx.target, "format": "jsonv2", "limit": "5", "addressdetails": "1"},
            timeout=30,
            retries=1,
        )
    except (NetworkError, HttpError) as exc:
        return [f("Nominatim", str(exc), "warn")]
    if not response.ok:
        return [f("Nominatim", f"HTTP {response.status}", "warn")]
    try:
        data = response.json()
    except ValueError:
        return [f("Nominatim", "respuesta no JSON", "warn")]
    if not isinstance(data, list) or not data:
        return [f("Nominatim", "sin resultados", "info")]
    findings: list[Finding] = [f("Lugares", str(len(data)), "info")]
    for item in data[:5]:
        if not isinstance(item, dict):
            continue
        lat = item.get("lat")
        lon = item.get("lon")
        osm = f"{item.get('osm_type')}/{item.get('osm_id')}"
        findings.append(
            f("Lugar", f"{item.get('display_name')} · {item.get('type')}", "info",
            url=f"https://www.openstreetmap.org/{osm}" if item.get("osm_id") else "",
            data={"lat": lat, "lon": lon, "class": item.get("class")}
        ))
        if lat and lon:
            findings.append(f("Mapa", f"https://www.openstreetmap.org/?mlat={lat}&mlon={lon}#map=15/{lat}/{lon}", "link",
                            url=f"https://www.openstreetmap.org/?mlat={lat}&mlon={lon}"))
    return findings


@module("overpass_poi")
def overpass_poi(ctx: Context, tool: Any) -> list[Finding]:
    # Geocodificar primero.
    try:
        geo = ctx.http.get(
            "https://nominatim.openstreetmap.org/search",
            params={"q": ctx.target, "format": "jsonv2", "limit": "1"},
            timeout=25,
            retries=1,
        )
        places = geo.json() if geo.ok else []
    except (NetworkError, HttpError, ValueError):
        places = []
    if not isinstance(places, list) or not places:
        return [f("Overpass", "no se pudo geocodificar el lugar", "warn")]
    lat = places[0].get("lat")
    lon = places[0].get("lon")
    if not lat or not lon:
        return [f("Overpass", "sin coordenadas", "warn")]
    safe_name = re.sub(r'["\\]', " ", ctx.target)
    query = f"""[out:json][timeout:25];
(
  node(around:1500,{lat},{lon})["name"~"{safe_name}",i];
  way(around:1500,{lat},{lon})["name"~"{safe_name}",i];
);
out center tags 30;"""
    try:
        response = ctx.http.post_form(
            "https://overpass-api.de/api/interpreter", {"data": query}, timeout=40, retries=1
        )
    except (NetworkError, HttpError) as exc:
        return [f("Overpass", str(exc), "warn")]
    if not response.ok:
        return [f("Overpass", f"HTTP {response.status}", "warn")]
    try:
        data = response.json()
    except ValueError:
        return [f("Overpass", "respuesta no JSON", "warn")]
    elements = data.get("elements") or []
    findings: list[Finding] = [f("Puntos de interés", str(len(elements)), "info")]
    for element in elements[:30]:
        if not isinstance(element, dict):
            continue
        tags = element.get("tags") or {}
        name = tags.get("name") or tags.get("operator") or "(sin nombre)"
        category = tags.get("amenity") or tags.get("shop") or tags.get("tourism") or tags.get("office") or ""
        address = ", ".join(
            str(tags.get(k)) for k in ("addr:street", "addr:housenumber", "addr:city") if tags.get(k)
        )
        lat2 = element.get("lat") or (element.get("center") or {}).get("lat")
        lon2 = element.get("lon") or (element.get("center") or {}).get("lon")
        findings.append(
            f("POI", f"{name} · {category} · {address}".strip(" ·"), "info",
            url=f"https://www.openstreetmap.org/?mlat={lat2}&mlon={lon2}" if lat2 and lon2 else "",
            data={"tags": tags}
        ))
    return findings
