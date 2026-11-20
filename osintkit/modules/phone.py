"""Módulos de teléfono: formato, reputación y perfiles directos."""

from __future__ import annotations

import base64
import re
from typing import Any
from urllib.parse import quote, quote_plus

from ..core import Context, Finding, module, render_template
from ..datasets import phone_area_codes as _phone_area_codes_data
from ..datasets import phone_sources as _phone_source_data
from ..http import HttpError, NetworkError
from ..util import dedupe, phone_digits, truncate
from .base import f
from .websearch import is_profile_url, profile_label, resolve_direct, search_url

# Códigos de llamada más comunes (los de 3 dígitos primero al buscar por prefijo).
COUNTRY_CODES: dict[str, str] = {
    "1": "Estados Unidos / Canadá / NANP",
    "7": "Rusia / Kazajistán",
    "20": "Egipto", "27": "Sudáfrica", "30": "Grecia", "31": "Países Bajos",
    "32": "Bélgica", "33": "Francia", "34": "España", "36": "Hungría",
    "39": "Italia", "40": "Rumania", "41": "Suiza", "43": "Austria",
    "44": "Reino Unido", "45": "Dinamarca", "46": "Suecia", "47": "Noruega",
    "48": "Polonia", "49": "Alemania", "51": "Perú", "52": "México",
    "53": "Cuba", "54": "Argentina", "55": "Brasil", "56": "Chile",
    "57": "Colombia", "58": "Venezuela", "60": "Malasia", "61": "Australia",
    "62": "Indonesia", "63": "Filipinas", "64": "Nueva Zelanda", "65": "Singapur",
    "66": "Tailandia", "81": "Japón", "82": "Corea del Sur", "84": "Vietnam",
    "86": "China", "90": "Turquía", "91": "India", "92": "Pakistán",
    "93": "Afganistán", "94": "Sri Lanka", "95": "Myanmar", "98": "Irán",
    "211": "Sudán del Sur", "212": "Marruecos", "213": "Argelia", "216": "Túnez",
    "218": "Libia", "220": "Gambia", "221": "Senegal", "222": "Mauritania",
    "223": "Malí", "224": "Guinea", "225": "Costa de Marfil", "226": "Burkina Faso",
    "227": "Níger", "228": "Togo", "229": "Benín", "230": "Mauricio",
    "231": "Liberia", "232": "Sierra Leona", "233": "Ghana", "234": "Nigeria",
    "235": "Chad", "236": "República Centroafricana", "237": "Camerún", "238": "Cabo Verde",
    "239": "Santo Tomé y Príncipe", "240": "Guinea Ecuatorial", "241": "Gabón", "242": "República del Congo",
    "243": "RD Congo", "244": "Angola", "245": "Guinea-Bisáu", "246": "Islas Diego García",
    "248": "Seychelles", "249": "Sudán", "250": "Ruanda", "251": "Etiopía",
    "252": "Somalia", "253": "Yibuti", "254": "Kenia", "255": "Tanzania",
    "256": "Uganda", "257": "Burundi", "258": "Mozambique", "260": "Zambia",
    "261": "Madagascar", "262": "Reunión", "263": "Zimbabue", "264": "Namibia",
    "265": "Malaui", "266": "Lesoto", "267": "Botsuana", "268": "Esuatini",
    "269": "Comoras", "290": "Santa Elena", "291": "Eritrea", "297": "Aruba",
    "298": "Islas Feroe", "299": "Groenlandia",
    "350": "Gibraltar", "351": "Portugal", "352": "Luxemburgo", "353": "Irlanda",
    "354": "Islandia", "355": "Albania", "356": "Malta", "357": "Chipre",
    "358": "Finlandia", "359": "Bulgaria", "370": "Lituania", "371": "Letonia",
    "372": "Estonia", "373": "Moldavia", "374": "Armenia", "375": "Bielorrusia",
    "376": "Andorra", "377": "Mónaco", "378": "San Marino", "379": "Ciudad del Vaticano",
    "380": "Ucrania", "381": "Serbia", "382": "Montenegro", "383": "Kosovo",
    "385": "Croacia", "386": "Eslovenia", "387": "Bosnia y Herzegovina", "389": "Macedonia del Norte",
    "420": "Chequia", "421": "Eslovaquia", "423": "Liechtenstein",
    "501": "Belice", "502": "Guatemala", "503": "El Salvador", "504": "Honduras",
    "505": "Nicaragua", "506": "Costa Rica", "507": "Panamá", "509": "Haití",
    "591": "Bolivia", "592": "Guyana", "593": "Ecuador", "594": "Guayana Francesa",
    "595": "Paraguay", "596": "Martinica", "597": "Surinam", "598": "Uruguay",
    "599": "Curazao / Caribe neerlandés",
    "670": "Timor Oriental", "672": "Islas del Pacífico", "673": "Brunéi",
    "674": "Nauru", "675": "Papúa Nueva Guinea", "676": "Tonga", "677": "Islas Salomón",
    "678": "Vanuatu", "679": "Fiyi", "680": "Palaos", "681": "Wallis y Futuna",
    "682": "Islas Cook", "683": "Niue", "685": "Samoa", "686": "Kiribati",
    "687": "Nueva Caledonia", "688": "Tuvalu", "689": "Polinesia Francesa",
    "690": "Tokelau", "691": "Micronesia", "692": "Islas Marshall",
    "850": "Corea del Norte", "852": "Hong Kong", "853": "Macao", "855": "Camboya",
    "856": "Laos", "880": "Bangladesh", "886": "Taiwán",
    "960": "Maldivas", "961": "Líbano", "962": "Jordania", "963": "Siria",
    "964": "Irak", "965": "Kuwait", "966": "Arabia Saudita", "967": "Yemen",
    "968": "Omán", "970": "Palestina", "971": "Emiratos Árabes Unidos",
    "972": "Israel", "973": "Baréin", "974": "Catar", "975": "Bután",
    "976": "Mongolia", "977": "Nepal", "992": "Tayikistán", "993": "Turkmenistán",
    "994": "Azerbaiyán", "995": "Georgia", "996": "Kirguistán", "998": "Uzbekistán",
}


def _split_country(number: str) -> tuple[str, str, str]:
    digits = phone_digits(number)
    if len(digits) < 7:
        return "", "", digits
    # Probar prefijos de 3, 2 y 1 dígitos.
    for size in (3, 2, 1):
        prefix = digits[:size]
        if prefix in COUNTRY_CODES:
            return prefix, COUNTRY_CODES[prefix], digits[size:]
    return "", "", digits


def _is_true(value: Any) -> bool:
    """Interpreta booleanos devueltos como true/1/sí por las APIs."""
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value == 1
    return str(value).strip().casefold() in {"1", "true", "sí", "si", "yes"}


def infer_area(number: str) -> dict[str, str] | None:
    """Devuelve la zona de la base offline a partir del código de área.

    Se prueban primero los códigos más largos para no confundir, por ejemplo,
    ``3544`` (Villa Dolores) con un prefijo más corto. En números argentinos con
    el ``9`` de móvil se elimina ese dígito antes de buscar el área.
    """
    digits = phone_digits(number)
    if len(digits) < 6:
        return None
    international = number.strip().startswith(("+", "00"))
    if international:
        prefix, country, rest = _split_country(number)
        national = rest or digits
        if prefix == "54" and national.startswith("9") and len(national) > 1:
            national = national[1:]
        country_iso = {"Argentina": "AR"}.get(country, "")
    else:
        # Sin prefijo internacional se prioriza la base argentina: hay códigos
        # de área (3544) que coinciden con prefijos de país (354, Islandia).
        country_iso = "AR"
        national = digits
    if not country_iso:
        return None
    areas = [
        area for area in _phone_area_codes_data()
        if str(area.get("country", "")).upper() == country_iso
    ]
    for size in (5, 4, 3, 2):
        code = national[:size]
        for area in areas:
            if str(area.get("code", "")) == code:
                return {
                    "country": country_iso,
                    "code": code,
                    "city": str(area.get("city") or ""),
                    "province": str(area.get("province") or ""),
                }
    return None


def _area_findings(number: str, geo_description: str = "") -> list[Finding]:
    """Hallazgos de código de área y ciudad para el resumen final."""
    findings: list[Finding] = []
    area = infer_area(number)
    if area:
        findings.append(
            f(
                "Código de área",
                f"+{area['country']} {area['code']}",
                "info",
                country=area["country"],
                area_code=area["code"],
                source="phone_area_codes",
            )
        )
    if geo_description:
        extra: dict[str, Any] = {"source": "phonenumbers", "geocoded": True}
        if area:
            extra["area_code"] = area["code"]
            extra["country"] = area["country"]
        findings.append(f("Ciudad", geo_description, "good", **extra))
    elif area and area["city"]:
        value = area["city"]
        if area["province"]:
            value = f"{value} · {area['province']}"
        findings.append(
            f(
                "Ciudad",
                value,
                "good",
                country=area["country"],
                area_code=area["code"],
                source="phone_area_codes",
            )
        )
    return findings


def _confirmation_finding(
    provider: str,
    data: dict[str, Any],
    fields: tuple[str, ...] = ("valid", "phone_valid", "is_valid", "active"),
) -> Finding | None:
    """Marca una fuente que devolvió el número como válido o activo.

    No implica que exista una cuenta en una red social: documenta que el
    proveedor confirmó la existencia/actividad del número.
    """
    for field in fields:
        if _is_true(data.get(field)):
            return f(
                provider,
                f"confirmó que el número existe y está activo ({field})",
                "good",
                registration_confirmed=True,
                provider=provider,
                field=field,
            )
    return None


def _phone_variants(number: str) -> list[str]:
    """Formatos habituales de un número para ampliar las búsquedas pasivas.

    Se incluyen el texto original, E.164 sin espacios, solo dígitos y el formato
    nacional cuando el objetivo trae prefijo internacional. No se inventan
    variantes para números nacionales sin prefijo para evitar falsos positivos.
    """
    raw = number.strip()
    digits = phone_digits(raw)
    international = raw.startswith("+") or raw.startswith("00")
    intl_digits = digits[2:] if raw.startswith("00") else digits
    values = [raw]
    if international and intl_digits:
        values.extend((f"+{intl_digits}", intl_digits))
    else:
        values.append(digits)
    if international and intl_digits:
        prefix, _country, rest = _split_country(f"+{intl_digits}")
        if prefix and rest:
            values.extend((rest, f"+{prefix} {rest}", f"{prefix} {rest}"))
            if len(rest) == 9:
                national = f"{rest[:3]} {rest[3:6]} {rest[6:]}"
                values.extend((national, f"+{prefix} {national}"))
    return dedupe(values)


@module("phone_info")
def phone_info(ctx: Context, tool: Any) -> list[Finding]:
    raw = ctx.target.strip()
    findings: list[Finding] = [f("Entrada", raw, "info")]
    try:
        import phonenumbers  # type: ignore

        parsed = phonenumbers.parse(raw, None)
        valid = phonenumbers.is_valid_number(parsed)
        e164 = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)
        national = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.NATIONAL)
        region = phonenumbers.region_code_for_number(parsed) or ""
        carrier = phonenumbers.carrier.name_for_number(parsed, "en") if hasattr(phonenumbers, "carrier") else ""
        line_type = ""
        try:
            from phonenumbers import number_type as _nt
            mapping = {
                _nt.MOBILE: "móvil", _nt.FIXED_LINE: "fijo", _nt.FIXED_LINE_OR_MOBILE: "fijo o móvil",
                _nt.TOLL_FREE: "gratuito", _nt.VOIP: "VoIP", _nt.PREMIUM_RATE: "tarifa premium",
                _nt.SHARED_COST: "costo compartido", _nt.PERSONAL_NUMBER: "personal",
                _nt.PAGER: "buscapersonas", _nt.UAN: "UAN", _nt.VOICEMAIL: "voicemail",
                _nt.UNKNOWN: "desconocido",
            }
            line_type = mapping.get(phonenumbers.number_type(parsed), "")
        except Exception:  # noqa: BLE001
            pass
        findings += [
            f("Formato E.164", e164, "good", data={"provider": "phonenumbers"}),
            f("Formato nacional", national, "info"),
            f("Válido", "sí" if valid else "no", "good" if valid else "warn"),
            f("Región", region or "—", "info"),
            f("Tipo de línea", line_type or "—", "info"),
            f("Operador", carrier or "—", "info"),
        ]
        geo_description = ""
        try:
            from phonenumbers import geocoder  # type: ignore

            geo_description = geocoder.description_for_number(parsed, "es") or ""
        except Exception:  # noqa: BLE001
            pass
        findings.extend(_area_findings(raw, geo_description))
        return findings
    except ImportError:
        findings.append(f("phonenumbers", "no instalado; se usa detección básica", "info"))
    except Exception as exc:  # noqa: BLE001
        findings.append(f("phonenumbers", f"error: {exc}", "warn"))

    digits = phone_digits(raw)
    area = infer_area(raw)
    international = raw.startswith(("+", "00"))
    if not international and area:
        prefix, country, rest = "54", "Argentina", digits
        e164_approx = f"+54{digits}"
    else:
        prefix, country, rest = _split_country(raw)
        e164_approx = f"+{digits}"
    if prefix:
        findings.append(f("Código de país", f"+{prefix} · {country}", "info"))
        findings.append(f("Número nacional", rest, "info"))
        findings.append(f("E.164 aproximado", e164_approx, "good"))
    else:
        findings.append(f("Código de país", "no detectado", "warn"))
    findings.append(f("Dígitos", str(len(digits)), "info"))
    findings.extend(_area_findings(raw))
    if raw.startswith("00"):
        findings.append(f("Formato", "prefijo internacional 00 detectado", "info"))
    if "@" in raw:
        findings.append(f("Aviso", "esto parece un email, no un teléfono", "warn"))
    recommendations = [
        "Instalá phonenumbers para validación y operador: pipx install phonenumbers",
    ]
    for recommendation in recommendations:
        findings.append(f("Sugerencia", recommendation, "info"))
    return findings


@module("phone_dork")
def phone_dork(ctx: Context, tool: Any) -> list[Finding]:
    """Busca el número y devuelve enlaces directos a perfiles o menciones."""
    number = ctx.target.strip()
    digits = phone_digits(number)
    variants = _phone_variants(number)
    quoted = " OR ".join(f'"{value}"' for value in variants[:5])
    compact = digits or number
    queries = [
        f'({quoted}) (site:facebook.com OR site:linkedin.com OR '
        f'site:instagram.com OR site:tiktok.com OR site:x.com OR site:twitter.com '
        f'OR site:vk.com OR site:ok.ru)',
        f'"{compact}" (site:wa.me OR site:truecaller.com OR site:sync.me '
        f'OR site:callapp.com OR site:t.me OR site:telegram.me OR site:signal.me)',
        f'({quoted}) (site:whitepages.com OR site:spokeo.com OR '
        f'site:zabasearch.com OR site:anywho.com OR site:411.com OR '
        f'site:fastpeoplesearch.com OR site:yellowpages.com)',
        f'({quoted}) (site:tellows.com OR site:whocallsme.com OR '
        f'site:800notes.com OR site:shouldianswer.net OR site:callercenter.com '
        f'OR site:whocalld.com)',
        f'({quoted}) (site:pastebin.com OR site:rentry.co OR '
        f'site:ghostbin.co OR site:telegra.ph OR site:justpaste.it)',
        f'({quoted})',
    ]
    hits = resolve_direct(ctx, queries, terms=variants, limit=50)
    findings: list[Finding] = []
    for hit in hits:
        direct = is_profile_url(hit.url)
        label = profile_label(hit.url)
        title = label if direct else f"{label} · resultado directo"
        findings.append(
            f(
                title,
                truncate(hit.snippet or hit.url, 240),
                "good" if direct else "link",
                url=hit.url,
                data={"engine": hit.engine, "query": hit.query, "direct_profile": direct},
            )
        )
    if findings:
        findings.insert(0, f("Perfiles directos", str(len(findings)), "good"))
    else:
        findings.append(
            f("Perfiles directos", f"no se encontraron coincidencias públicas para {number}", "info")
        )
        if digits:
            findings.append(
                f(
                    "WhatsApp · contacto directo",
                    "abre el chat; WhatsApp no permite verificar la cuenta sin iniciar sesión",
                    "link",
                    url=f"https://wa.me/{digits}",
                    contact_link=True,
                )
            )
        findings.append(
            f(
                "Búsqueda manual",
                "no se encontraron perfiles directos; abre la búsqueda solo para revisar más resultados",
                "info",
                url=search_url(queries[0]),
            )
        )
    return findings


@module("phone_numverify")
def phone_numverify(ctx: Context, tool: Any) -> list[Finding]:
    try:
        response = ctx.http.get(
            "http://apilayer.net/api/validate",
            params={
                "access_key": ctx.key("NUMVERIFY_API_KEY"),
                "number": ctx.target,
                "format": "1",
            },
            timeout=30,
            retries=1,
        )
    except (NetworkError, HttpError) as exc:
        return [f("Numverify", str(exc), "warn")]
    if response.status in (401, 403):
        return [f("Numverify", "clave inválida", "warn")]
    if not response.ok:
        return [f("Numverify", f"HTTP {response.status}", "warn")]
    try:
        data = response.json()
    except ValueError:
        return [f("Numverify", "respuesta no JSON", "warn")]
    if isinstance(data, dict) and data.get("error"):
        return [f("Numverify", str(data.get("error")), "warn")]
    findings: list[Finding] = [f("Válido", str(data.get("valid")), "good" if data.get("valid") else "warn")]
    confirmation = _confirmation_finding("Numverify", data, ("valid",))
    if confirmation:
        findings.append(confirmation)
    for key, label in (("number", "Número"), ("local_format", "Formato local"),
                       ("international_format", "E.164"), ("country_prefix", "Prefijo"),
                       ("country_code", "País"), ("country_name", "Nombre del país"),
                       ("location", "Ubicación"), ("carrier", "Operador"), ("line_type", "Tipo")):
        if data.get(key) not in (None, ""):
            findings.append(f(f"{label}", str(data[key]), "info"))
    return findings


@module("phone_ipqualityscore")
def phone_ipqualityscore(ctx: Context, tool: Any) -> list[Finding]:
    key = ctx.key("IPQUALITYSCORE_API_KEY")
    try:
        response = ctx.http.get(
            f"https://ipqualityscore.com/api/json/phone/{key}/{quote_plus(ctx.target)}",
            timeout=30,
            retries=1,
        )
    except (NetworkError, HttpError) as exc:
        return [f("IPQualityScore", str(exc), "warn")]
    if response.status in (401, 403):
        return [f("IPQualityScore", "clave inválida", "warn")]
    if not response.ok:
        return [f("IPQualityScore", f"HTTP {response.status}", "warn")]
    try:
        data = response.json()
    except ValueError:
        return [f("IPQualityScore", "respuesta no JSON", "warn")]
    findings: list[Finding] = []
    for key_name, label, warn in (
        ("fraud_score", "Score de fraude", True), ("active", "Activo", False),
        ("carrier", "Operador", False), ("line_type", "Tipo de línea", False),
        ("country", "País", False), ("city", "Ciudad", False), ("zip_code", "CP", False),
        ("spammer", "Spammer", True), ("recent_abuse", "Abuso reciente", True),
        ("risky", "Riesgoso", True), ("leaked", "Filtrado", True),
        ("do_not_call", "No llamar", True), ("name", "Nombre", False),
    ):
        value = data.get(key_name)
        if value in (None, "", 0, False) and key_name not in ("fraud_score",):
            continue
        level = "bad" if warn and value else "info"
        findings.append(f(f"{label}", str(value), level))
    confirmation = _confirmation_finding("IPQualityScore", data, ("active",))
    if confirmation:
        findings.append(confirmation)
    return findings or [f("IPQualityScore", "sin datos", "info")]


@module("phone_sources")
def phone_sources(ctx: Context, tool: Any) -> list[Finding]:
    """Devuelve los directorios y buscadores de teléfono incluidos."""
    sources = _phone_source_data()
    if not sources:
        return [f("Directorio de teléfono", "no se encontró phone_sources.json", "bad")]

    findings: list[Finding] = [
        f(
            "Fuentes disponibles",
            f"{len(sources)} directorios y buscadores de {ctx.target}",
            "info",
        )
    ]
    for source in sources:
        name = str(source.get("name") or "Fuente")
        template = str(source.get("url") or "")
        if not template:
            continue
        region = str(source.get("region") or "Global")
        description = str(source.get("description") or "")
        tags = source.get("tags") if isinstance(source.get("tags"), list) else []
        tag_text = ", ".join(str(tag) for tag in tags)
        detail = " · ".join(part for part in (region, description, tag_text) if part)
        findings.append(
            f(
                name,
                detail or "consulta manual",
                "link",
                url=render_template(template, ctx.target, ctx.kind),
                region=region,
                tags=tags,
                source_directory=True,
            )
        )
    return findings


@module("phone_veriphone")
def phone_veriphone(ctx: Context, tool: Any) -> list[Finding]:
    try:
        response = ctx.http.get(
            "https://api.veriphone.io/v2/verify",
            params={"phone": ctx.target, "key": ctx.key("VERIPHONE_API_KEY")},
            timeout=25,
            retries=1,
        )
    except (NetworkError, HttpError) as exc:
        return [f("Veriphone", str(exc), "warn")]
    if response.status in (401, 403):
        return [f("Veriphone", "clave inválida", "warn")]
    if not response.ok:
        return [f("Veriphone", f"HTTP {response.status}", "warn")]
    try:
        data = response.json()
    except ValueError:
        return [f("Veriphone", "respuesta no JSON", "warn")]
    if not isinstance(data, dict):
        return [f("Veriphone", "respuesta inesperada", "warn")]
    findings: list[Finding] = [
        f("Válido", str(data.get("phone_valid", data.get("valid", "—"))), "info")
    ]
    confirmation = _confirmation_finding("Veriphone", data, ("phone_valid", "valid"))
    if confirmation:
        findings.append(confirmation)
    for key, label in (
        ("phone", "Número"),
        ("phone_type", "Tipo"),
        ("country", "País"),
        ("country_code", "Código de país"),
        ("carrier", "Operador"),
        ("region", "Región"),
        ("timezone", "Zona horaria"),
    ):
        if data.get(key) not in (None, ""):
            findings.append(f(label, str(data[key]), "info"))
    return findings


@module("phone_abstract")
def phone_abstract(ctx: Context, tool: Any) -> list[Finding]:
    try:
        response = ctx.http.get(
            "https://phonevalidation.abstractapi.com/v1/",
            params={
                "api_key": ctx.key("ABSTRACT_PHONE_API_KEY"),
                "phone": ctx.target,
            },
            timeout=25,
            retries=1,
        )
    except (NetworkError, HttpError) as exc:
        return [f("Abstract Phone", str(exc), "warn")]
    if response.status in (401, 403):
        return [f("Abstract Phone", "clave inválida", "warn")]
    if not response.ok:
        return [f("Abstract Phone", f"HTTP {response.status}", "warn")]
    try:
        data = response.json()
    except ValueError:
        return [f("Abstract Phone", "respuesta no JSON", "warn")]
    if not isinstance(data, dict):
        return [f("Abstract Phone", "respuesta inesperada", "warn")]
    if data.get("error"):
        return [f("Abstract Phone", str(data["error"]), "warn")]
    findings: list[Finding] = [
        f("Válido", str(data.get("valid", "—")), "info")
    ]
    confirmation = _confirmation_finding("Abstract Phone", data, ("valid",))
    if confirmation:
        findings.append(confirmation)
    country = data.get("country") if isinstance(data.get("country"), dict) else {}
    for key, label in (
        ("format", "Formato"),
        ("local_format", "Formato local"),
        ("location", "Ubicación"),
        ("type", "Tipo"),
    ):
        if data.get(key) not in (None, ""):
            findings.append(f(label, str(data[key]), "info"))
    for key, label in (("name", "País"), ("prefix", "Prefijo"), ("code", "Código")):
        if country.get(key) not in (None, ""):
            findings.append(f(label, str(country[key]), "info"))
    return findings


@module("phone_twilio")
def phone_twilio(ctx: Context, tool: Any) -> list[Finding]:
    sid = ctx.key("TWILIO_ACCOUNT_SID")
    token = ctx.key("TWILIO_AUTH_TOKEN")
    auth = base64.b64encode(f"{sid}:{token}".encode("utf-8")).decode("ascii")
    number = quote(ctx.target.strip(), safe="")
    try:
        response = ctx.http.get(
            f"https://lookups.twilio.com/v1/PhoneNumbers/{number}",
            params={"Type": ["carrier", "caller-name"]},
            headers={"Authorization": f"Basic {auth}"},
            timeout=25,
            retries=1,
        )
    except (NetworkError, HttpError) as exc:
        return [f("Twilio Lookup", str(exc), "warn")]
    if response.status in (401, 403):
        return [f("Twilio Lookup", "credenciales inválidas", "warn")]
    if response.status == 404:
        return [f("Twilio Lookup", "número no encontrado", "info")]
    if not response.ok:
        return [f("Twilio Lookup", f"HTTP {response.status}", "warn")]
    try:
        data = response.json()
    except ValueError:
        return [f("Twilio Lookup", "respuesta no JSON", "warn")]
    if not isinstance(data, dict):
        return [f("Twilio Lookup", "respuesta inesperada", "warn")]
    findings: list[Finding] = []
    for key, label in (
        ("phone_number", "Número"),
        ("national_format", "Formato nacional"),
        ("country_code", "País"),
        ("valid", "Válido"),
        ("caller_name", "Nombre del titular"),
    ):
        value = data.get(key)
        if isinstance(value, dict):
            value = value.get("caller_name") or value.get("name")
        if value not in (None, ""):
            level = "good" if key == "valid" and value else "info"
            findings.append(f(label, str(value), level))
    confirmation = _confirmation_finding("Twilio Lookup", data, ("valid",))
    if confirmation:
        findings.append(confirmation)
    carrier = data.get("carrier")
    if isinstance(carrier, dict):
        for key, label in (("name", "Operador"), ("type", "Tipo de línea"), ("mobile_country_code", "MCC"), ("mobile_network_code", "MNC")):
            if carrier.get(key) not in (None, ""):
                findings.append(f(label, str(carrier[key]), "info"))
    return findings or [f("Twilio Lookup", "sin datos", "info")]
