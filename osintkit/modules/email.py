"""Módulos de email: validación, PGP, Gravatar, brechas y perfiles directos."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Any
from urllib.parse import quote_plus

from ..core import Context, Finding, module
from ..http import HttpError, NetworkError
from ..util import days_until, is_email, truncate
from .base import doh_txt, doh_values, f, join_limited, safe_get
from .websearch import is_profile_url, profile_label, resolve_direct, search_url

ROLE_ACCOUNTS = {
    "admin", "administrator", "billing", "contact", "hello", "help", "info",
    "it", "jobs", "legal", "mail", "marketing", "media", "noreply", "no-reply",
    "office", "postmaster", "press", "privacy", "root", "sales", "security",
    "support", "team", "webmaster", "abuse", "careers", "accounts", "finance",
}


def _disposable_domains() -> set[str]:
    path = Path(__file__).resolve().parent.parent / "data" / "disposable.txt"
    try:
        return {
            line.strip().lower()
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.startswith("#")
        }
    except OSError:
        return set()


@module("email_validate")
def email_validate(ctx: Context, tool: Any) -> list[Finding]:
    email = ctx.target.strip()
    findings: list[Finding] = []
    valid = is_email(email)
    findings.append(f("Sintaxis", "válida" if valid else "inválida", "good" if valid else "bad"))
    if not valid:
        return findings
    local, domain = email.rsplit("@", 1)
    domain = domain.lower()
    findings.append(f("Parte local", local, "info"))
    findings.append(f("Dominio", domain, "info"))
    if local.lower() in ROLE_ACCOUNTS or re.match(r"^(info|admin|support|sales|contact)[+-]", local.lower()):
        findings.append(f("Cuenta de rol", "probablemente no es personal", "warn"))
    if domain in _disposable_domains():
        findings.append(f("Desechable", f"{domain} figura en la lista de temporales", "warn"))
    mx = doh_values(ctx, domain, "MX")
    if mx:
        findings.append(f("MX", join_limited(mx, 10), "good"))
    else:
        a = doh_values(ctx, domain, "A")
        if a:
            findings.append(f("MX", "sin MX; el dominio tiene A (puede aceptar correo por fallback)", "warn"))
        else:
            findings.append(f("MX", "el dominio no resuelve ni tiene MX", "bad"))
    if "google" in " ".join(mx).lower():
        findings.append(f("Proveedor", "Google Workspace / Gmail", "info"))
    elif "outlook" in " ".join(mx).lower() or "protection.outlook" in " ".join(mx).lower():
        findings.append(f("Proveedor", "Microsoft 365", "info"))
    elif "proton" in " ".join(mx).lower():
        findings.append(f("Proveedor", "Proton Mail", "info"))
    return findings


@module("email_gravatar")
def email_gravatar(ctx: Context, tool: Any) -> list[Finding]:
    email = ctx.target.strip().lower()
    digest = hashlib.md5(email.encode("utf-8")).hexdigest()
    findings: list[Finding] = []
    response = safe_get(ctx, f"https://gravatar.com/avatar/{digest}?d=404", timeout=20)
    if response and response.status == 200:
        findings.append(
            f("Gravatar", "existe un avatar público para este email", "warn",
              url=f"https://gravatar.com/{digest}", data={"hash": digest})
        )
        profile = safe_get(ctx, f"https://www.gravatar.com/{digest}.json", timeout=20)
        if profile and profile.ok:
            try:
                data = profile.json().get("entry") or []
                if data and isinstance(data, list):
                    entry = data[0]
                    for key, label in (("displayName", "Nombre"), ("aboutMe", "Bio"), ("currentLocation", "Ubicación"),
                                       ("profileUrl", "Perfil"), ("preferredUsername", "Usuario")):
                        if entry.get(key):
                            findings.append(f(f"{label}", str(entry[key]), "info",
                                            url=str(entry[key]) if key == "profileUrl" else ""))
                    for account in (entry.get("accounts") or [])[:20]:
                        if isinstance(account, dict):
                            findings.append(
                                f("Cuenta vinculada", f"{account.get('shortname')}: {account.get('url')}", "link",
                                url=str(account.get("url", ""))
                            ))
            except ValueError:
                pass
    elif response and response.status == 404:
        findings.append(f("Gravatar", "no hay avatar público", "good"))
    else:
        findings.append(f("Gravatar", f"no se pudo verificar ({response.status if response else 'sin respuesta'})", "warn"))
    return findings


@module("email_pgp")
def email_pgp(ctx: Context, tool: Any) -> list[Finding]:
    email = ctx.target
    response = safe_get(ctx, f"https://keys.openpgp.org/vks/v1/by-email/{quote_plus(email)}", timeout=20)
    if not response:
        return [f("OpenPGP", "keys.openpgp.org no respondió", "warn")]
    if response.status == 404:
        return [f("OpenPGP", "no hay clave pública publicada", "info")]
    if not response.ok:
        return [f("OpenPGP", f"HTTP {response.status}", "warn")]
    text = response.text
    if "BEGIN PGP PUBLIC KEY BLOCK" not in text:
        return [f("OpenPGP", "respuesta inesperada", "warn")]
    findings: list[Finding] = [
        f("Clave pública", "encontrada en keys.openpgp.org", "good", url=f"https://keys.openpgp.org/search?q={quote_plus(email)}"),
        f("Tamaño", f"{len(text)} bytes", "info"),
    ]
    fingerprints = re.findall(r"-----BEGIN PGP PUBLIC KEY BLOCK-----", text)
    findings.append(f("Bloques", str(len(fingerprints)), "info"))
    return findings


@module("hibp")
def hibp(ctx: Context, tool: Any) -> list[Finding]:
    email = ctx.target
    headers = {
        "hibp-api-key": ctx.key("HIBP_API_KEY"),
        "User-Agent": "osintkit/1.0",
        "Accept": "application/json",
    }
    try:
        response = ctx.http.get(
            f"https://haveibeenpwned.com/api/v3/breachedaccount/{quote_plus(email)}",
            params={"truncateResponse": "false"},
            headers=headers,
            timeout=30,
            retries=1,
        )
    except (NetworkError, HttpError) as exc:
        return [f("HIBP", str(exc), "warn")]
    if response.status == 404:
        return [f("HIBP", "sin brechas conocidas", "good")]
    if response.status == 401:
        return [f("HIBP", "clave API inválida", "warn")]
    if response.status == 429:
        return [f("HIBP", "límite de tasa alcanzado", "warn")]
    if not response.ok:
        return [f("HIBP", f"HTTP {response.status}", "warn")]
    try:
        breaches = response.json()
    except ValueError:
        return [f("HIBP", "respuesta no JSON", "warn")]
    findings: list[Finding] = []
    for breach in breaches:
        if not isinstance(breach, dict):
            continue
        findings.append(
            f("Brecha", f"{breach.get('Name')} · {breach.get('BreachDate')} · {breach.get('PwnCount')} cuentas",
            "bad", url=f"https://haveibeenpwned.com/PwnedWebsites#{breach.get('Name')}",
            data={"data_classes": breach.get("DataClasses"), "verified": breach.get("IsVerified")}
        ))
    findings.insert(0, f("Brechas", str(len(breaches)), "bad" if breaches else "good"))
    return findings


@module("email_hunter")
def email_hunter(ctx: Context, tool: Any) -> list[Finding]:
    if ctx.kind == "domain":
        url = "https://api.hunter.io/v2/domain-search"
        params = {"domain": ctx.target, "api_key": ctx.key("HUNTER_API_KEY"), "limit": "10"}
    else:
        url = "https://api.hunter.io/v2/email-verifier"
        params = {"email": ctx.target, "api_key": ctx.key("HUNTER_API_KEY")}
    try:
        response = ctx.http.get(url, params=params, timeout=30, retries=1)
    except (NetworkError, HttpError) as exc:
        return [f("Hunter.io", str(exc), "warn")]
    if response.status in (401, 403):
        return [f("Hunter.io", "clave inválida o sin permisos", "warn")]
    if response.status == 429:
        return [f("Hunter.io", "límite alcanzado", "warn")]
    if not response.ok:
        return [f("Hunter.io", f"HTTP {response.status}", "warn")]
    try:
        payload = response.json().get("data") or {}
    except ValueError:
        return [f("Hunter.io", "respuesta no JSON", "warn")]
    findings: list[Finding] = []
    if ctx.kind == "domain":
        findings.append(f("Emails", str(len(payload.get("emails") or [])), "info"))
        findings.append(f("Patrón", str(payload.get("pattern") or "—"), "info"))
        for item in (payload.get("emails") or [])[:10]:
            if isinstance(item, dict):
                findings.append(f("Email", f"{item.get('value')} · {item.get('position') or ''}", "info"))
    else:
        for key, label in (
            ("result", "Resultado"), ("score", "Score"), ("regexp", "Regex"),
            ("gibberish", "Sin sentido"), ("disposable", "Desechable"),
            ("webmail", "Webmail"), ("accept_all", "Acepta todo"),
            ("smtp_check", "Chequeo SMTP"), ("mx_records", "MX"),
        ):
            value = payload.get(key)
            if value not in (None, "", []):
                level = "warn" if key in ("gibberish", "disposable") and value else "info"
                findings.append(f(f"{label}", str(value), level))
        for source in (payload.get("sources") or [])[:10]:
            if isinstance(source, dict):
                findings.append(f("Fuente", f"{source.get('domain')} · {source.get('uri')}", "link",
                                url=str(source.get("uri", ""))))
    return findings


@module("emailrep")
def emailrep(ctx: Context, tool: Any) -> list[Finding]:
    headers = {"Key": ctx.key("EMAILREP_API_KEY"), "Accept": "application/json"}
    try:
        response = ctx.http.get(f"https://emailrep.io/{quote_plus(ctx.target)}", headers=headers, timeout=25, retries=1)
    except (NetworkError, HttpError) as exc:
        return [f("EmailRep", str(exc), "warn")]
    if response.status in (401, 403):
        return [f("EmailRep", "clave inválida", "warn")]
    if response.status == 429:
        return [f("EmailRep", "límite alcanzado", "warn")]
    if not response.ok:
        return [f("EmailRep", f"HTTP {response.status}", "warn")]
    try:
        data = response.json()
    except ValueError:
        return [f("EmailRep", "respuesta no JSON", "warn")]
    findings: list[Finding] = [f("Reputación", str(data.get("reputation", "?")), "info")]
    if data.get("suspicious"):
        findings.append(f("Sospechoso", "sí", "warn"))
    details = data.get("details") or {}
    for key, label in (
        ("credentials_leaked", "Credenciales filtradas"),
        ("data_breach", "Brecha de datos"),
        ("domain_exists", "Dominio existe"),
        ("domain_reputation", "Reputación del dominio"),
        ("new_domain", "Dominio nuevo"),
        ("days_since_domain_creation", "Días desde creación"),
        ("spam", "Spam"),
        ("free_provider", "Proveedor gratuito"),
        ("disposable", "Desechable"),
        ("accept_all", "Acepta todo"),
        ("valid_mx", "MX válido"),
        ("spoofable", "Suplantable"),
        ("profiles", "Perfiles"),
    ):
        value = details.get(key)
        if value in (None, "", [], {}):
            continue
        level = "warn" if key in ("credentials_leaked", "data_breach", "spam", "spoofable") and value else "info"
        findings.append(f(f"{label}", str(value), level))
    return findings


def _github_email_profiles(ctx: Context, email: str) -> list[Finding]:
    """Perfiles de GitHub vinculados al email mediante API pública."""
    findings: list[Finding] = []
    seen: set[str] = set()
    headers = {"Accept": "application/vnd.github+json"}
    endpoints = (
        (
            "https://api.github.com/search/users",
            {"q": f"{email} in:email", "per_page": 10},
            "perfil asociado al email",
        ),
        (
            "https://api.github.com/search/commits",
            {"q": f"author-email:{email}", "per_page": 10},
            "autor de commits con este email",
        ),
    )
    for url, params, detail in endpoints:
        try:
            response = ctx.http.get(url, params=params, headers=headers, timeout=25, retries=1)
        except (NetworkError, HttpError):
            continue
        if not response.ok:
            continue
        try:
            data = response.json()
        except ValueError:
            continue
        if not isinstance(data, dict):
            continue
        items = data.get("items") or []
        if not isinstance(items, list):
            continue
        for item in items:
            if not isinstance(item, dict):
                continue
            if "login" in item:
                login = item.get("login")
                profile_url = item.get("html_url") or f"https://github.com/{login}"
                label = str(login or "GitHub")
            else:
                author = item.get("author") or {}
                if not isinstance(author, dict):
                    continue
                login = author.get("login")
                profile_url = author.get("html_url") or (f"https://github.com/{login}" if login else "")
                label = str(login or "GitHub")
            if not profile_url or profile_url in seen:
                continue
            seen.add(profile_url)
            findings.append(
                f(
                    "GitHub",
                    f"{detail} · {label}" if label else detail,
                    "good",
                    url=profile_url,
                    data={"source": "api.github.com", "query": params.get("q")},
                )
            )
    return findings


@module("email_dork")
def email_dork(ctx: Context, tool: Any) -> list[Finding]:
    """Busca menciones del email y devuelve enlaces directos, no buscadores."""
    email = ctx.target.strip()
    findings: list[Finding] = _github_email_profiles(ctx, email)
    seen: set[str] = {finding.url for finding in findings if finding.url}
    queries = [
        f'"{email}" (site:facebook.com OR site:linkedin.com OR site:instagram.com '
        f'OR site:x.com OR site:twitter.com OR site:tiktok.com OR site:github.com '
        f'OR site:gitlab.com OR site:keybase.io OR site:about.me OR site:gravatar.com)',
        f'"{email}" (site:pastebin.com OR site:rentry.co OR site:ghostbin.co)',
    ]
    hits = resolve_direct(ctx, queries, terms=[email], limit=15)
    for hit in hits:
        if hit.url in seen:
            continue
        seen.add(hit.url)
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
            f("Perfiles directos", f"no se encontraron coincidencias públicas para {email}", "info")
        )
        findings.append(
            f(
                "Búsqueda manual",
                "no se encontraron enlaces directos; abre la búsqueda solo para revisar más resultados",
                "info",
                url=search_url(queries[0]),
            )
        )
    return findings
