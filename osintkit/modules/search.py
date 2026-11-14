"""Módulos de búsqueda: motores, repositorios, foros y archivos."""

from __future__ import annotations

import html
import re
import urllib.parse
from typing import Any

from ..core import Context, Finding, module
from ..http import HttpError, NetworkError
from ..util import collapse_ws, dedupe, truncate
from .base import f, join_limited, q, safe_get, safe_json, strip_tags


def _query(ctx: Context) -> str:
    return ctx.target.strip()


def _decode_ddg(href: str) -> str:
    href = html.unescape(href)
    if href.startswith("//"):
        href = "https:" + href
    parsed = urllib.parse.urlsplit(href)
    params = urllib.parse.parse_qs(parsed.query)
    if params.get("uddg"):
        return params["uddg"][0]
    return href


@module("ddg_search")
def ddg_search(ctx: Context, tool: Any) -> list[Finding]:
    query = _query(ctx)
    findings: list[Finding] = []
    endpoints = [
        ("https://html.duckduckgo.com/html/", "DuckDuckGo"),
        ("https://lite.duckduckgo.com/lite/", "DuckDuckGo Lite"),
    ]
    text = ""
    source = ""
    for url, name in endpoints:
        try:
            response = ctx.http.get(
                url,
                params={"q": query, "kl": "wt-wt"},
                timeout=25,
                retries=1,
            )
        except (NetworkError, HttpError):
            response = None
        if response and response.ok and response.text:
            text = response.text
            source = name
            break
    if not text:
        return [
            f(
                "DuckDuckGo",
                "no se pudo consultar el motor; usa el enlace manual",
                "warn",
                url=f"https://duckduckgo.com/?q={q(query)}",
            )
        ]

    findings.append(f("Consulta", query, "info", url=f"https://duckduckgo.com/?q={q(query)}"))
    results: list[tuple[str, str, str]] = []
    pattern = re.compile(
        r'<a[^>]+class="[^"]*result__a[^"]*"[^>]+href="([^"]+)"[^>]*>(.*?)</a>',
        re.I | re.S,
    )
    for match in pattern.finditer(text):
        href = _decode_ddg(match.group(1))
        title = strip_tags(match.group(2))
        if href and title:
            results.append((title, href, ""))
    if not results:
        pattern = re.compile(
            r'<a[^>]+href="(https?://[^"]+)"[^>]*>(.*?)</a>', re.I | re.S
        )
        for match in pattern.finditer(text):
            href = html.unescape(match.group(1))
            title = strip_tags(match.group(2))
            if "duckduckgo.com" in href or not title or len(title) < 3:
                continue
            results.append((title, href, ""))
    snippets = re.findall(
        r'<a[^>]+class="[^"]*result__snippet[^"]*"[^>]*>(.*?)</a>', text, re.I | re.S
    )
    seen: set[str] = set()
    for index, (title, href, _) in enumerate(results[:25]):
        if href in seen:
            continue
        if "duckduckgo.com/y.js" in href or "ad_provider=" in href:
            continue
        seen.add(href)
        snippet = strip_tags(snippets[index]) if index < len(snippets) else ""
        findings.append(
            f(
                title,
                truncate(snippet, 240) if snippet else href,
                "link",
                url=href,
                data={"engine": source},
            )
        )
    if len(findings) <= 1:
        findings.append(f("Resultados", "el motor no devolvió enlaces parseables", "warn"))
    return findings


@module("github_search")
def github_search(ctx: Context, tool: Any) -> list[Finding]:
    query = _query(ctx)
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    token = ctx.key("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"

    findings: list[Finding] = []
    modes: list[tuple[str, str]] = []
    if ctx.kind in ("username", "email", "org"):
        modes.append(("users", query))
        modes.append(("repositories", query))
    else:
        modes.append(("repositories", query))
        modes.append(("users", query))

    for mode, term in modes:
        try:
            response = ctx.http.get(
                f"https://api.github.com/search/{mode}",
                params={"q": term, "per_page": 15},
                headers=headers,
                timeout=30,
                retries=1,
            )
        except (NetworkError, HttpError) as exc:
            findings.append(f("GitHub", str(exc), "warn"))
            continue
        if response.status == 403:
            findings.append(f("GitHub", "límite de la API o token inválido (403)", "warn"))
            continue
        if response.status == 422:
            findings.append(f("GitHub", "consulta rechazada (422)", "warn"))
            continue
        if not response.ok:
            findings.append(f("GitHub", f"HTTP {response.status}", "warn"))
            continue
        try:
            data = response.json()
        except ValueError:
            findings.append(f("GitHub", "respuesta no JSON", "warn"))
            continue
        items = data.get("items") or []
        findings.append(
            f(
                f"GitHub {mode}",
                f"{data.get('total_count', len(items))} resultados para «{term}»",
                "info",
                url=f"https://github.com/search?q={q(term)}&type={mode}",
            )
        )
        for item in items[:15]:
            if not isinstance(item, dict):
                continue
            if mode == "users":
                login = str(item.get("login") or "")
                findings.append(
                    f(
                        login,
                        f"{item.get('type') or 'usuario'} · {item.get('public_repos', 0)} repos · "
                        f"{item.get('followers', 0)} seguidores",
                        "good",
                        url=str(item.get("html_url") or f"https://github.com/{login}"),
                    )
                )
            else:
                full = str(item.get("full_name") or "")
                findings.append(
                    f(
                        full,
                        f"{item.get('language') or '—'} · ⭐{item.get('stargazers_count', 0)} · "
                        f"{truncate(str(item.get('description') or ''), 160)}",
                        "link",
                        url=str(item.get("html_url") or ""),
                        data={"owner": (item.get("owner") or {}).get("login")},
                    )
                )
    return findings


@module("reddit_search")
def reddit_search(ctx: Context, tool: Any) -> list[Finding]:
    query = _query(ctx)
    headers = {"User-Agent": "osintkit/1.0 (OSINT research)"}
    endpoints: list[str] = []
    if ctx.kind == "username" and re.fullmatch(r"[A-Za-z0-9_-]{2,32}", query):
        endpoints.append(f"https://www.reddit.com/user/{query}/about.json")
    endpoints.append("https://www.reddit.com/search.json")

    findings: list[Finding] = []
    blocked = False
    for endpoint in endpoints:
        try:
            response = ctx.http.get(
                endpoint,
                params=None if endpoint.endswith("about.json") else {"q": query, "limit": 20, "sort": "relevance"},
                headers=headers,
                timeout=25,
                retries=1,
            )
        except (NetworkError, HttpError):
            continue
        if response.status in (403, 429):
            blocked = True
            continue
        if not response.ok:
            continue
        try:
            payload = response.json()
        except ValueError:
            continue
        if endpoint.endswith("about.json"):
            data = payload.get("data") or {}
            if data:
                findings.append(
                    f(
                        f"u/{data.get('name') or query}",
                        f"karma {data.get('link_karma', 0)}/{data.get('comment_karma', 0)} · "
                        f"creado {data.get('created_utc', '—')}",
                        "good",
                        url=f"https://www.reddit.com/user/{data.get('name') or query}",
                    )
                )
            continue
        children = ((payload.get("data") or {}).get("children") or [])
        for child in children[:20]:
            post = child.get("data") if isinstance(child, dict) else None
            if not isinstance(post, dict):
                continue
            title = str(post.get("title") or "publicación")
            sub = str(post.get("subreddit") or "")
            findings.append(
                f(
                    title,
                    f"r/{sub} · {post.get('score', 0)} puntos · {post.get('num_comments', 0)} comentarios",
                    "link",
                    url=f"https://www.reddit.com{post.get('permalink') or ''}",
                )
            )
    if not findings:
        if blocked:
            findings.append(
                f(
                    "Reddit",
                    "la API bloqueó la consulta (403/429); abre la búsqueda manual",
                    "warn",
                    url=f"https://www.reddit.com/search/?q={q(query)}",
                )
            )
        else:
            findings.append(
                f(
                    "Reddit",
                    "sin resultados o API no disponible",
                    "info",
                    url=f"https://www.reddit.com/search/?q={q(query)}",
                )
            )
    return findings


@module("hn_search")
def hn_search(ctx: Context, tool: Any) -> list[Finding]:
    query = _query(ctx)
    try:
        data = ctx.http.get_json(
            "https://hn.algolia.com/api/v1/search",
            params={"query": query, "tags": "(story,comment)", "hitsPerPage": 25},
            timeout=25,
            retries=1,
        )
    except (NetworkError, HttpError, ValueError) as exc:
        return [
            f(
                "Hacker News",
                str(exc),
                "warn",
                url=f"https://hn.algolia.com/?q={q(query)}",
            )
        ]
    hits = (data or {}).get("hits") or []
    findings: list[Finding] = [
        f(
            "Hacker News",
            f"{data.get('nbHits', len(hits))} resultados para «{query}»",
            "info",
            url=f"https://hn.algolia.com/?q={q(query)}",
        )
    ]
    seen: set[str] = set()
    for hit in hits[:25]:
        if not isinstance(hit, dict):
            continue
        title = strip_tags(str(hit.get("title") or hit.get("story_title") or ""))
        object_id = str(hit.get("objectID") or "")
        if not title or object_id in seen:
            continue
        seen.add(object_id)
        points = hit.get("points")
        comments = hit.get("num_comments")
        value = f"{points if points is not None else '—'} puntos · {comments if comments is not None else '—'} comentarios"
        if hit.get("author"):
            value += f" · {hit['author']}"
        findings.append(
            f(
                title,
                value,
                "link",
                url=f"https://news.ycombinator.com/item?id={object_id}",
                data={"created_at": hit.get("created_at")},
            )
        )
    return findings


@module("stackexchange_search")
def stackexchange_search(ctx: Context, tool: Any) -> list[Finding]:
    query = _query(ctx)
    try:
        data = ctx.http.get_json(
            "https://api.stackexchange.com/2.3/search/advanced",
            params={
                "order": "desc",
                "sort": "relevance",
                "q": query,
                "site": "stackoverflow",
                "pagesize": 20,
                "filter": "default",
            },
            timeout=30,
            retries=1,
        )
    except (NetworkError, HttpError, ValueError) as exc:
        return [
            f(
                "Stack Overflow",
                str(exc),
                "warn",
                url=f"https://stackoverflow.com/search?q={q(query)}",
            )
        ]
    items = (data or {}).get("items") or []
    findings: list[Finding] = [
        f(
            "Stack Overflow",
            f"{len(items)} resultados para «{query}»",
            "info",
            url=f"https://stackoverflow.com/search?q={q(query)}",
        )
    ]
    for item in items[:20]:
        if not isinstance(item, dict):
            continue
        title = html.unescape(str(item.get("title") or ""))
        findings.append(
            f(
                title,
                f"puntuación {item.get('score', 0)} · {item.get('answer_count', 0)} respuestas · "
                f"{'resuelta' if item.get('is_answered') else 'sin resolver'}",
                "link",
                url=str(item.get("link") or ""),
                data={"tags": item.get("tags")},
            )
        )
    return findings


@module("archive_org_search")
def archive_org_search(ctx: Context, tool: Any) -> list[Finding]:
    query = _query(ctx)
    try:
        response = ctx.http.get(
            "https://archive.org/advancedsearch.php",
            params={
                "q": query,
                "fl[]": ["identifier", "title", "mediatype", "year", "creator"],
                "rows": 20,
                "page": 1,
                "output": "json",
            },
            timeout=30,
            retries=1,
        )
    except (NetworkError, HttpError) as exc:
        return [f("Internet Archive", str(exc), "warn", url=f"https://archive.org/search?query={q(query)}")]
    if not response.ok:
        return [f("Internet Archive", f"HTTP {response.status}", "warn")]
    try:
        payload = response.json()
    except ValueError:
        return [f("Internet Archive", "respuesta no JSON", "warn")]
    body = payload.get("response") or {}
    docs = body.get("docs") or []
    findings: list[Finding] = [
        f(
            "Internet Archive",
            f"{body.get('numFound', len(docs))} resultados para «{query}»",
            "info",
            url=f"https://archive.org/search?query={q(query)}",
        )
    ]
    for doc in docs[:20]:
        if not isinstance(doc, dict):
            continue
        identifier = str(doc.get("identifier") or "")
        creator = doc.get("creator")
        if isinstance(creator, list):
            creator = join_limited(creator, 3)
        findings.append(
            f(
                str(doc.get("title") or identifier),
                f"{doc.get('mediatype') or '—'} · {doc.get('year') or 's/f'} · {creator or '—'}",
                "link",
                url=f"https://archive.org/details/{identifier}" if identifier else "",
            )
        )
    return findings
