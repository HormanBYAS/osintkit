"""Búsqueda web reutilizable y resolución de enlaces directos.

Los módulos de perfiles no deben devolver únicamente una URL de buscador. Este
helper consulta DuckDuckGo (con Bing de respaldo), extrae los resultados y
permite filtrar páginas de perfil reales (GitHub, Facebook, LinkedIn, etc.)
para enlazarlas directamente.
"""

from __future__ import annotations

import base64
import html
import re
from dataclasses import dataclass
from urllib.parse import parse_qs, quote_plus, urlsplit

from ..core import Context
from ..http import HttpError, NetworkError
from .base import strip_tags


@dataclass(frozen=True)
class SearchHit:
    title: str
    url: str
    snippet: str = ""
    engine: str = ""
    query: str = ""


_DDG_RESULT = re.compile(
    r'<a[^>]+class="[^"]*result__a[^"]*"[^>]+href="([^"]+)"[^>]*>(.*?)</a>',
    re.I | re.S,
)
_DDG_ANY_LINK = re.compile(r'<a[^>]+href="(https?://[^"]+)"[^>]*>(.*?)</a>', re.I | re.S)
_DDG_SNIPPET = re.compile(
    r'<a[^>]+class="[^"]*result__snippet[^"]*"[^>]*>(.*?)</a>', re.I | re.S
)
_BING_BLOCK = re.compile(r'<li class="b_algo".*?</li>', re.I | re.S)
_BING_HEAD = re.compile(
    r'<h2[^>]*>.*?<a[^>]+href="([^"]+)"[^>]*>(.*?)</a>', re.I | re.S
)
_BING_SNIPPET = re.compile(r'<p[^>]*>(.*?)</p>', re.I | re.S)

_SEARCH_DOMAINS = {
    "duckduckgo.com",
    "google.com",
    "bing.com",
    "search.brave.com",
    "search.yahoo.com",
    "yandex.com",
    "yandex.ru",
    "startpage.com",
    "mojeek.com",
    "searx.be",
}
_SEARCH_PATHS = {
    "facebook.com": ("/search", "/public", "/login", "/help", "/policies"),
    "instagram.com": ("/explore", "/accounts/login", "/directory"),
    "x.com": ("/search", "/i/", "/home", "/explore"),
    "twitter.com": ("/search", "/i/", "/home", "/explore"),
    "linkedin.com": ("/search", "/login", "/help", "/feed"),
    "tiktok.com": ("/search", "/login", "/foryou"),
    "reddit.com": ("/search", "/login", "/explore"),
    "youtube.com": ("/results", "/feed"),
    "github.com": ("/search",),
    "gitlab.com": ("/search",),
    "truecaller.com": ("/search", "/login"),
    "sync.me": ("/search", "/login"),
}


def search_url(query: str) -> str:
    return "https://duckduckgo.com/?q=" + quote_plus(query)


def _decode_ddg(href: str) -> str:
    href = html.unescape(href)
    if href.startswith("//"):
        href = "https:" + href
    parsed = urlsplit(href)
    params = parse_qs(parsed.query)
    if params.get("uddg"):
        return params["uddg"][0]
    return href


def _decode_bing(href: str) -> str:
    href = html.unescape(href)
    match = re.search(r"[?&]u=a1([^&]+)", href)
    if not match:
        return href
    raw = match.group(1)
    raw += "=" * (-len(raw) % 4)
    try:
        return base64.urlsafe_b64decode(raw).decode("utf-8", "replace")
    except (ValueError, UnicodeDecodeError):
        return href


def _parse_bing(text: str, query: str) -> list[SearchHit]:
    hits: list[SearchHit] = []
    seen: set[str] = set()
    for block in _BING_BLOCK.findall(text):
        match = _BING_HEAD.search(block)
        if not match:
            continue
        href = _decode_bing(match.group(1))
        title = strip_tags(match.group(2))
        if not href.startswith(("http://", "https://")) or href in seen:
            continue
        seen.add(href)
        snippet_match = _BING_SNIPPET.search(block)
        snippet = strip_tags(snippet_match.group(1)) if snippet_match else ""
        hits.append(SearchHit(title=title, url=href, snippet=snippet, engine="Bing", query=query))
    return hits


def _parse_ddg(text: str, engine: str, query: str) -> list[SearchHit]:
    raw: list[tuple[str, str]] = []
    for match in _DDG_RESULT.finditer(text):
        raw.append((_decode_ddg(match.group(1)), strip_tags(match.group(2))))
    if not raw:
        for match in _DDG_ANY_LINK.finditer(text):
            href = html.unescape(match.group(1))
            title = strip_tags(match.group(2))
            if "duckduckgo.com" in href or len(title) < 3:
                continue
            raw.append((href, title))
    snippets = [strip_tags(item) for item in _DDG_SNIPPET.findall(text)]

    hits: list[SearchHit] = []
    seen: set[str] = set()
    for index, (href, title) in enumerate(raw):
        if not href.startswith(("http://", "https://")):
            continue
        if "duckduckgo.com/y.js" in href or "ad_provider=" in href:
            continue
        if href in seen:
            continue
        seen.add(href)
        snippet = snippets[index] if index < len(snippets) else ""
        hits.append(SearchHit(title=title, url=href, snippet=snippet, engine=engine, query=query))
    return hits


def bing(
    ctx: Context,
    query: str,
    *,
    limit: int = 10,
    timeout: float = 25,
) -> list[SearchHit]:
    """Consulta Bing HTML y decodifica sus redirecciones."""
    try:
        response = ctx.http.get(
            "https://www.bing.com/search",
            params={"q": query, "setlang": "en", "cc": "us"},
            timeout=timeout,
            retries=1,
        )
    except (NetworkError, HttpError):
        return []
    if not response or not response.ok:
        return []
    return _parse_bing(response.text, query)[:limit]


def duckduckgo(
    ctx: Context,
    query: str,
    *,
    limit: int = 10,
    timeout: float = 25,
) -> list[SearchHit]:
    """Consulta DuckDuckGo y, si no hay resultados, usa Bing como respaldo."""
    endpoints = [
        ("https://html.duckduckgo.com/html/", "DuckDuckGo"),
        ("https://lite.duckduckgo.com/lite/", "DuckDuckGo Lite"),
    ]
    for url, name in endpoints:
        try:
            response = ctx.http.get(
                url,
                params={"q": query, "kl": "wt-wt"},
                timeout=timeout,
                retries=1,
            )
        except (NetworkError, HttpError):
            response = None
        if not response or not response.ok:
            continue
        hits = _parse_ddg(response.text, name, query)
        if hits:
            return hits[:limit]
    return bing(ctx, query, limit=limit, timeout=timeout)


def is_search_page(url: str) -> bool:
    """Devuelve True para buscadores y páginas de resultados, no perfiles."""
    parsed = urlsplit(url)
    host = parsed.netloc.lower().split(":")[0]
    if host.startswith("www."):
        host = host[4:]
    path = parsed.path.lower()
    if not host:
        return True
    if host in _SEARCH_DOMAINS or any(host.endswith("." + item) for item in _SEARCH_DOMAINS):
        return True
    for domain, prefixes in _SEARCH_PATHS.items():
        if host == domain or host.endswith("." + domain):
            if any(path.startswith(prefix) for prefix in prefixes):
                return True
    if path in ("", "/"):
        return True
    return False


def profile_label(url: str) -> str:
    """Nombre corto de la plataforma para un enlace directo."""
    host = urlsplit(url).netloc.lower().split(":")[0]
    if host.startswith("www."):
        host = host[4:]
    labels = {
        "github.com": "GitHub",
        "gist.github.com": "GitHub Gist",
        "gitlab.com": "GitLab",
        "facebook.com": "Facebook",
        "instagram.com": "Instagram",
        "linkedin.com": "LinkedIn",
        "x.com": "X/Twitter",
        "twitter.com": "X/Twitter",
        "tiktok.com": "TikTok",
        "reddit.com": "Reddit",
        "keybase.io": "Keybase",
        "about.me": "About.me",
        "linktr.ee": "Linktree",
        "gravatar.com": "Gravatar",
        "wa.me": "WhatsApp",
        "t.me": "Telegram",
        "telegram.me": "Telegram",
        "pastebin.com": "Pastebin",
        "rentry.co": "Rentry",
        "ghostbin.co": "Ghostbin",
        "truecaller.com": "Truecaller",
        "sync.me": "Sync.me",
        "youtube.com": "YouTube",
    }
    for domain, label in labels.items():
        if host == domain:
            return label
    for domain, label in labels.items():
        if host.endswith("." + domain):
            return label
    return host


def is_profile_url(url: str) -> bool:
    """Heurística conservadora: página de perfil, no de búsqueda ni portada."""
    if is_search_page(url):
        return False
    parsed = urlsplit(url)
    host = parsed.netloc.lower().split(":")[0]
    if host.startswith("www."):
        host = host[4:]
    if host.startswith(("m.", "mobile.")):
        base = host.split(".", 1)[1]
        if base in {"facebook.com", "twitter.com", "linkedin.com", "instagram.com"}:
            host = base
    path = parsed.path.rstrip("/")
    parts = [part for part in path.split("/") if part]

    if host == "github.com" or host == "gitlab.com":
        return len(parts) == 1
    if host == "gist.github.com":
        return len(parts) == 1
    if host == "facebook.com":
        if parts and parts[0] == "profile.php":
            return True
        if parts and parts[0] == "people" and len(parts) >= 2:
            return True
        return len(parts) == 1 and parts[0] != "public"
    if host == "instagram.com":
        return len(parts) == 1
    if host == "linkedin.com":
        return len(parts) >= 2 and parts[0] in {"in", "pub"}
    if host in {"x.com", "twitter.com"}:
        return len(parts) == 1 and parts[0] not in {"home", "explore", "i"}
    if host == "tiktok.com":
        return len(parts) == 1 and parts[0].startswith("@")
    if host == "reddit.com":
        return len(parts) >= 2 and parts[0] == "user"
    if host in {"keybase.io", "about.me", "linktr.ee", "gravatar.com"}:
        return bool(parts)
    if host == "wa.me":
        return bool(parts) and parts[0].isdigit()
    if host in {"t.me", "telegram.me"}:
        return bool(parts) and not parts[0].startswith(("joinchat", "s/"))
    if host == "youtube.com":
        return bool(parts) and (parts[0].startswith("@") or parts[0] in {"c", "channel", "user"})
    if host == "pastebin.com":
        return bool(parts) and parts[0] not in {"search", "login", "signup"}
    if host in {"rentry.co", "ghostbin.co"}:
        return bool(parts)
    return False


def resolve_direct(
    ctx: Context,
    queries: list[str],
    *,
    terms: list[str] | tuple[str, ...] = (),
    limit: int = 12,
    profiles_only: bool = False,
    timeout: float = 25,
) -> list[SearchHit]:
    """Ejecuta varias consultas y acumula únicamente enlaces directos.

    Descarta buscadores, páginas de resultados y enlaces que no contienen
    ninguno de los términos esperados. Con ``profiles_only`` conserva además
    solo las URLs que parezcan perfiles directos.
    """
    needles = [item.strip().lower() for item in terms if item and item.strip()]
    hits: list[SearchHit] = []
    seen: set[str] = set()
    for query in queries:
        for hit in duckduckgo(ctx, query, limit=limit * 2, timeout=timeout):
            if hit.url in seen or is_search_page(hit.url):
                continue
            direct = is_profile_url(hit.url)
            if profiles_only and not direct:
                continue
            haystack = f"{hit.title} {hit.snippet} {hit.url}".lower()
            if needles and not any(needle in haystack for needle in needles):
                continue
            seen.add(hit.url)
            hits.append(hit)
            if len(hits) >= limit:
                return hits
    return hits
