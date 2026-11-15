"""Módulos de vehículos: validación de placas, APIs públicas y fuentes."""

from __future__ import annotations

from datetime import date
from typing import Any
from urllib.parse import quote_plus

from ..core import Context, Finding, module
from ..http import HttpError, NetworkError
from ..plates import (
    compact_plate,
    country_label,
    country_official_links,
    normalize_plate,
    split_plate_country,
    validate_plate,
)
from ..util import truncate
from .base import f
from .websearch import is_profile_url, profile_label, resolve_direct, search_url

RDW_MAIN = "https://opendata.rdw.nl/resource/m9d7-ebf2.json"
RDW_FUEL = "https://opendata.rdw.nl/resource/8ys7-d773.json"
DVLA_URL = "https://driver-vehicle-licensing.api.gov.uk/vehicle-enquiry/v1/vehicles"


def _input(ctx: Context) -> tuple[str, dict[str, Any] | None]:
    explicit = str(ctx.get("country") or "").strip()
    plate, country = split_plate_country(ctx.target, explicit)
    return normalize_plate(plate), country


def _date(value: Any) -> str:
    raw = str(value or "").strip()
    if not raw:
        return ""
    if len(raw) == 8 and raw.isdigit():
        raw = f"{raw[:4]}-{raw[4:6]}-{raw[6:]}"
    try:
        return date.fromisoformat(raw[:10]).isoformat()
    except ValueError:
        return raw


def _rdw_value(value: Any) -> str:
    text = str(value or "").strip()
    if text in {"N.v.t.", "Niet geregistreerd", "Geen verstrekking in Open Data"}:
        return ""
    return text


def _rdw_json(ctx: Context, endpoint: str, plate: str) -> list[dict[str, Any]] | None:
    try:
        response = ctx.http.get(
            endpoint,
            params={"kenteken": plate, "$limit": 5},
            timeout=25,
            retries=1,
        )
    except (NetworkError, HttpError):
        return None
    if not response.ok:
        return None
    try:
        payload = response.json()
    except ValueError:
        return None
    if not isinstance(payload, list):
        return None
    return [item for item in payload if isinstance(item, dict)]


def _rdw_lookup(ctx: Context, plate: str, country: dict[str, Any]) -> list[Finding]:
    compact = compact_plate(plate)
    rows = _rdw_json(ctx, RDW_MAIN, compact)
    source_url = f"{RDW_MAIN}?kenteken={quote_plus(compact)}"
    if rows is None:
        return [
            f("RDW", "no se pudo consultar Open Data; intenta más tarde", "warn", url=source_url),
            f("Fuente", "RDW Open Data", "link", url=source_url),
        ]
    if not rows:
        return [
            f("RDW", f"sin datos para la matrícula «{compact}»", "warn", url=source_url),
            f(
                "Sugerencia",
                "verifica el formato neerlandés y prueba sin guiones ni espacios",
                "info",
            ),
            f("Fuente", "RDW Open Data", "link", url=source_url),
        ]
    row = rows[0]
    fuel_rows = _rdw_json(ctx, RDW_FUEL, compact) or []
    fuel = ", ".join(
        sorted(
            {
                _rdw_value(item.get("brandstof_omschrijving"))
                for item in fuel_rows
                if _rdw_value(item.get("brandstof_omschrijving"))
            }
        )
    )
    findings: list[Finding] = [
        f("País", country_label(country), "info"),
        f("Matrícula", compact, "good"),
    ]
    brand = _rdw_value(row.get("merk"))
    model = _rdw_value(row.get("handelsbenaming"))
    vehicle = " ".join(part for part in (brand, model) if part)
    if vehicle:
        findings.append(f("Vehículo", vehicle, "good"))
    kind = _rdw_value(row.get("voertuigsoort"))
    if kind:
        findings.append(f("Tipo", kind, "info"))
    if row.get("datum_eerste_toelating"):
        findings.append(f("Primera matriculación", _date(row.get("datum_eerste_toelating")), "info"))
    if row.get("datum_eerste_tenaamstelling_in_nederland"):
        findings.append(
            f("Alta en Países Bajos", _date(row.get("datum_eerste_tenaamstelling_in_nederland")), "info")
        )
    colours = [
        _rdw_value(row.get("eerste_kleur")),
        _rdw_value(row.get("tweede_kleur")),
    ]
    colour = " / ".join(value for value in colours if value)
    if colour:
        findings.append(f("Color", colour, "info"))
    if fuel:
        findings.append(f("Combustible", fuel, "info"))
    if _rdw_value(row.get("cilinderinhoud")):
        findings.append(f("Cilindrada", f"{_rdw_value(row.get('cilinderinhoud'))} cm³", "info"))
    if _rdw_value(row.get("aantal_cilinders")):
        findings.append(f("Cilindros", _rdw_value(row.get("aantal_cilinders")), "info"))
    if _rdw_value(row.get("aantal_zitplaatsen")):
        findings.append(f("Plazas", _rdw_value(row.get("aantal_zitplaatsen")), "info"))
    if _rdw_value(row.get("aantal_deuren")):
        findings.append(f("Puertas", _rdw_value(row.get("aantal_deuren")), "info"))
    if _rdw_value(row.get("aantal_wielen")):
        findings.append(f("Ruedas", _rdw_value(row.get("aantal_wielen")), "info"))
    if _rdw_value(row.get("massa_ledig_voertuig")):
        findings.append(f("Masa vacía", f"{_rdw_value(row.get('massa_ledig_voertuig'))} kg", "info"))
    if _rdw_value(row.get("toegestane_maximum_massa_voertuig")):
        findings.append(
            f(
                "Masa máxima",
                f"{_rdw_value(row.get('toegestane_maximum_massa_voertuig'))} kg",
                "info",
            )
        )
    length = _rdw_value(row.get("lengte"))
    width = _rdw_value(row.get("breedte"))
    if length and width and length != "0" and width != "0":
        findings.append(f("Dimensiones", f"{length} × {width} cm", "info"))
    if _rdw_value(row.get("vervaldatum_apk")):
        findings.append(f("APK / ITV", _date(row.get("vervaldatum_apk")), "info"))
    if _rdw_value(row.get("europese_voertuigcategorie")):
        findings.append(
            f("Categoría europea", _rdw_value(row.get("europese_voertuigcategorie")), "info")
        )
    if _rdw_value(row.get("catalogusprijs")):
        findings.append(f("Precio de catálogo", f"€ {_rdw_value(row.get('catalogusprijs'))}", "info"))
    if _rdw_value(row.get("wam_verzekerd")):
        findings.append(f("Seguro WAM", _rdw_value(row.get("wam_verzekerd")), "info"))
    if _rdw_value(row.get("openstaande_terugroepactie_indicator")).casefold() == "ja":
        findings.append(f("Recall abierto", "sí", "warn"))
    if _rdw_value(row.get("export_indicator")).casefold() == "ja":
        findings.append(f("Indicador de exportación", "sí", "warn"))
    findings.append(f("Fuente", "RDW Open Data · Países Bajos", "link", url=source_url))
    findings.append(
        f(
            "Privacidad",
            "RDW Open Data no incluye nombre, dirección ni datos del titular",
            "info",
        )
    )
    return findings


def _dvla_lookup(ctx: Context, plate: str, country: dict[str, Any]) -> list[Finding]:
    key = ctx.key("DVLA_API_KEY")
    if not key:
        return [
            f("País", country_label(country), "info"),
            f(
                "DVLA",
                "falta DVLA_API_KEY; configura la clave o usa el portal oficial",
                "warn",
                url="https://www.gov.uk/get-vehicle-information-from-dvla",
            ),
            f(
                "Cómo obtener la clave",
                "regístrate en el portal de desarrolladores de DVLA y configura "
                "`osintkit config set-key DVLA_API_KEY ...`",
                "link",
                url="https://developer-portal.driver-vehicle-licensing.api.gov.uk/",
            ),
        ]
    try:
        response = ctx.http.request(
            "POST",
            DVLA_URL,
            json_body={"registrationNumber": compact_plate(plate)},
            headers={"x-api-key": key, "Accept": "application/json"},
            timeout=25,
            retries=1,
            allow_cache=False,
        )
    except (NetworkError, HttpError) as exc:
        return [f("DVLA", str(exc), "warn", url="https://www.gov.uk/get-vehicle-information-from-dvla")]
    if response.status in (401, 403):
        return [
            f("DVLA", "clave rechazada o sin autorización", "bad"),
            f(
                "Portal oficial",
                "consulta manual por matrícula",
                "link",
                url="https://www.gov.uk/get-vehicle-information-from-dvla",
            ),
        ]
    if response.status == 404:
        return [
            f("DVLA", f"sin datos para «{compact_plate(plate)}»", "warn"),
            f(
                "Portal oficial",
                "verifica la matrícula en el servicio de DVLA",
                "link",
                url="https://www.gov.uk/get-vehicle-information-from-dvla",
            ),
        ]
    if not response.ok:
        return [f("DVLA", f"HTTP {response.status}", "warn")]
    try:
        data = response.json()
    except ValueError:
        return [f("DVLA", "respuesta no JSON", "warn")]
    if not isinstance(data, dict) or not data:
        return [f("DVLA", "sin datos del vehículo", "info")]

    findings: list[Finding] = [
        f("País", country_label(country), "info"),
        f("Matrícula", compact_plate(plate), "good"),
    ]
    make = str(data.get("make") or "").strip()
    if make:
        findings.append(f("Marca", make, "good"))
    for key_name, label in (
        ("yearOfManufacture", "Año de fabricación"),
        ("monthOfFirstRegistration", "Primera matriculación"),
        ("colour", "Color"),
        ("fuelType", "Combustible"),
        ("engineCapacity", "Cilindrada"),
        ("co2Emissions", "Emisiones CO₂"),
        ("taxStatus", "Estado del impuesto"),
        ("taxDueDate", "Impuesto hasta"),
        ("motStatus", "Estado de ITV/MOT"),
        ("motExpiryDate", "ITV/MOT hasta"),
        ("typeApproval", "Tipo homologado"),
        ("wheelplan", "Configuración de ejes"),
        ("revenueWeight", "Peso fiscal"),
    ):
        value = str(data.get(key_name) or "").strip()
        if value:
            findings.append(f(label, value, "info"))
    if data.get("markedForExport"):
        findings.append(f("Marcado para exportación", "sí", "warn"))
    if data.get("dateOfLastV5CIssued"):
        findings.append(f("Último V5C", _date(data.get("dateOfLastV5CIssued")), "info"))
    findings.append(
        f(
            "Fuente",
            "DVLA Vehicle Enquiry Service · Reino Unido",
            "link",
            url="https://www.gov.uk/get-vehicle-information-from-dvla",
        )
    )
    findings.append(
        f(
            "Privacidad",
            "la API devuelve datos del vehículo, no el nombre ni la dirección del titular",
            "info",
        )
    )
    return findings


@module("plate_info")
def plate_info(ctx: Context, tool: Any) -> list[Finding]:
    """Normaliza la placa y valida de forma orientativa el formato del país."""
    plate, country = _input(ctx)
    compact = compact_plate(plate)
    findings: list[Finding] = [
        f("Entrada", ctx.target, "info"),
        f("Matrícula normalizada", plate or "—", "info"),
        f("Forma compacta", compact or "—", "info"),
    ]
    if not country:
        findings.append(
            f(
                "País",
                "no indicado o no reconocido; usa --country ES, MX, AR, UK, NL…",
                "warn",
            )
        )
        findings.append(
            f(
                "Sugerencia",
                "ejemplos: `scan \"1234 ABC\" -k plate --pais ES` o `scan \"1234ABC, Reino Unido\"`",
                "info",
            )
        )
    else:
        findings.append(f("País", country_label(country), "good"))
        example = str(country.get("example") or "").strip()
        note = str(country.get("format_note") or "").strip()
        if note:
            findings.append(f("Formato", note, "info"))
        if example:
            findings.append(f("Ejemplo", example, "info"))
        valid, detail = validate_plate(plate, country)
        level = "good" if valid else ("warn" if valid is False else "info")
        findings.append(f("Validación orientativa", detail, level))
        api = str(country.get("api") or "").strip().upper()
        if api:
            findings.append(f("Consulta automática", f"disponible vía {api}", "good"))
        else:
            findings.append(
                f("Consulta automática", "no hay API pública gratuita mapeada", "info")
            )
        notes = str(country.get("notes") or "").strip()
        if notes:
            findings.append(f("Nota del país", notes, "info"))
    findings.append(
        f(
            "Límite legal",
            "osintkit solo usa datos públicos del vehículo; no busca titulares ni datos personales",
            "warn",
        )
    )
    return findings


@module("plate_sources")
def plate_sources(ctx: Context, tool: Any) -> list[Finding]:
    """Muestra fuentes oficiales y limitaciones para el país indicado."""
    plate, country = _input(ctx)
    findings: list[Finding] = [f("Matrícula", plate or "—", "info")]
    if not country:
        findings.append(f("País", "no indicado o no reconocido", "warn"))
        findings.append(
            f(
                "Cómo indicar el país",
                "usa --country/--pais o incluye el país: «1234ABC ES», «ES 1234ABC», "
                "«1234ABC, Reino Unido»",
                "info",
            )
        )
        findings.append(
            f(
                "Recursos generales",
                "DVLA, RDW Open Data, NMVTIS y registros estatales/provinciales",
                "link",
                url=search_url("consulta oficial matrícula vehículo registro público"),
            )
        )
        return findings

    findings.append(f("País", country_label(country), "good"))
    links = country_official_links(country)
    if not links:
        findings.append(f("Fuentes oficiales", "no hay enlaces mapeados para este país", "warn"))
    for link in links:
        findings.append(
            f(
                link["name"],
                link.get("description") or "consulta oficial",
                "link",
                url=link["url"],
            )
        )
    note = str(country.get("format_note") or "").strip()
    if note:
        findings.append(f("Formato", note, "info"))
    notes = str(country.get("notes") or "").strip()
    if notes:
        findings.append(f("Limitaciones", notes, "warn"))
    findings.append(
        f(
            "Búsqueda oficial",
            f'consulta «{plate}» en el portal del país',
            "link",
            url=search_url(f'"{plate}" "{country.get("name")}" consulta oficial vehículo'),
        )
    )
    findings.append(
        f(
            "Privacidad",
            "algunos portales piden captcha, pago o autorización del titular; no intentes "
            "eludir esos controles",
            "warn",
        )
    )
    return findings


@module("plate_lookup")
def plate_lookup(ctx: Context, tool: Any) -> list[Finding]:
    """Consulta APIs públicas gratuitas (RDW/DVLA) o deriva a la fuente oficial."""
    plate, country = _input(ctx)
    if not country:
        return [
            f("País", "no indicado o no reconocido", "warn"),
            f(
                "Sugerencia",
                "para consultar una placa indica el país con --country/--pais",
                "info",
            ),
        ]
    compact = compact_plate(plate)
    if not compact:
        return [f("Matrícula", "vacía o no válida", "warn")]
    api = str(country.get("api") or "").strip().lower()
    if api == "rdw":
        return _rdw_lookup(ctx, plate, country)
    if api == "dvla":
        return _dvla_lookup(ctx, plate, country)

    links = country_official_links(country)
    findings: list[Finding] = [
        f("País", country_label(country), "good"),
        f("Matrícula", compact, "info"),
        f(
            "Consulta automática",
            "no hay API pública gratuita mapeada para este país",
            "warn",
        ),
    ]
    for link in links[:3]:
        findings.append(
            f(link["name"], link.get("description") or "consulta oficial", "link", url=link["url"])
        )
    findings.append(
        f(
            "Búsqueda manual",
            f'"{compact}" "{country.get("name")}" vehículo',
            "link",
            url=search_url(f'"{compact}" "{country.get("name")}" vehículo'),
        )
    )
    findings.append(
        f(
            "Límite legal",
            "los datos de titularidad no son públicos en la mayoría de países; "
            "no se incluyen búsquedas de propietarios",
            "warn",
        )
    )
    return findings


@module("plate_search")
def plate_search(ctx: Context, tool: Any) -> list[Finding]:
    """Busca menciones públicas de la placa y devuelve enlaces directos."""
    plate, country = _input(ctx)
    compact = compact_plate(plate)
    display = normalize_plate(plate)
    name = str((country or {}).get("name") or "").strip()
    if not compact:
        return [f("Matrícula", "vacía o no válida", "warn")]
    terms = [compact]
    if display and display != compact:
        terms.append(display)
    queries = [
        f'"{display}" "{name}" (coche OR auto OR vehículo OR vehicle)',
        f'"{compact}" "{name}" (venta OR anuncio OR subasta OR auction)',
        f'"{compact}" (matrícula OR placa OR plate OR registration)',
    ]
    hits = resolve_direct(ctx, queries, terms=terms, limit=18, timeout=25)
    findings: list[Finding] = []
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
            f("Menciones públicas", "sin enlaces directos para esta placa", "warn")
        )
    query = f'"{compact}" {name}'.strip()
    findings.append(
        f(
            "Búsqueda manual · DuckDuckGo",
            query,
            "link",
            url=search_url(query),
        )
    )
    findings.append(
        f(
            "Búsqueda manual · Google",
            query,
            "link",
            url="https://www.google.com/search?q=" + quote_plus(query),
        )
    )
    findings.append(
        f(
            "Búsqueda manual · Bing",
            query,
            "link",
            url="https://www.bing.com/search?q=" + quote_plus(query),
        )
    )
    findings.append(
        f(
            "Aviso",
            "una mención pública no confirma titularidad, estado legal ni historial del vehículo",
            "warn",
        )
    )
    return findings
