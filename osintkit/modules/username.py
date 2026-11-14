"""Módulos de usuario: presencia multi-sitio y perfiles por plataforma."""

from __future__ import annotations

import concurrent.futures
import html as html_lib
import json
import re
from typing import Any
from urllib.parse import quote, quote_plus

from ..core import Context, Finding, module
from ..http import HttpError, NetworkError
from ..util import collapse_ws, dedupe, truncate
from .base import f, fetch_title, join_limited, safe_get, safe_json, strip_tags

# (nombre, plantilla, marcadores de "no existe")
PRESENCE_SITES: list[tuple[str, str, tuple[str, ...]]] = [
    ("GitHub", "https://github.com/{u}", ("Not Found",)),
    ("GitLab", "https://gitlab.com/{u}", ("404", "Not Found")),
    ("Bitbucket", "https://bitbucket.org/{u}/", ("Page not found",)),
    ("Codeberg", "https://codeberg.org/{u}", ("404", "not found")),
    ("SourceHut", "https://sr.ht/~{u}/", ("not found",)),
    ("Reddit", "https://www.reddit.com/user/{u}", ("nobody on Reddit goes by that name", "page not found")),
    ("Hacker News", "https://news.ycombinator.com/user?id={u}", ("No such user",)),
    ("Keybase", "https://keybase.io/{u}", ("not found",)),
    ("Mastodon", "https://mastodon.social/@{u}", ("not found",)),
    ("Telegram", "https://t.me/{u}", ()),
    ("PyPI", "https://pypi.org/user/{u}/", ("404",)),
    ("npm", "https://www.npmjs.com/~{u}", ("404",)),
    ("Docker Hub", "https://hub.docker.com/u/{u}", ("404",)),
    ("Dev.to", "https://dev.to/{u}", ("404",)),
    ("Hashnode", "https://hashnode.com/@{u}", ("404",)),
    ("Medium", "https://medium.com/@{u}", ("404",)),
    ("Tumblr", "https://{u}.tumblr.com/", ("not found", "doesn't exist")),
    ("Pinterest", "https://www.pinterest.com/{u}/", ("404",)),
    ("Flickr", "https://www.flickr.com/people/{u}/", ("not found",)),
    ("Vimeo", "https://vimeo.com/{u}", ("404",)),
    ("SoundCloud", "https://soundcloud.com/{u}", ("404",)),
    ("Spotify", "https://open.spotify.com/user/{u}", ("404",)),
    ("Last.fm", "https://www.last.fm/user/{u}", ("404",)),
    ("Goodreads", "https://www.goodreads.com/{u}", ("404",)),
    ("Letterboxd", "https://letterboxd.com/{u}/", ("404",)),
    ("Twitch", "https://www.twitch.tv/{u}", ("404",)),
    ("Steam", "https://steamcommunity.com/id/{u}", ("could not be found",)),
    ("Kaggle", "https://www.kaggle.com/{u}", ("404",)),
    ("Hugging Face", "https://huggingface.co/{u}", ("404",)),
    ("Replit", "https://replit.com/@{u}", ("404",)),
    ("CodePen", "https://codepen.io/{u}", ("404",)),
    ("JSFiddle", "https://jsfiddle.net/user/{u}/", ("404",)),
    ("Behance", "https://www.behance.net/{u}", ("404",)),
    ("Dribbble", "https://dribbble.com/{u}", ("404",)),
    ("Trello", "https://trello.com/{u}", ("404",)),
    ("Linktree", "https://linktr.ee/{u}", ("404",)),
    ("About.me", "https://about.me/{u}", ("404",)),
    ("Gravatar", "https://gravatar.com/{u}", ("404",)),
    ("YouTube", "https://www.youtube.com/@{u}", ("404",)),
    ("Blogspot", "https://{u}.blogspot.com/", ("not found", "doesn't exist")),
    ("WordPress", "https://{u}.wordpress.com/", ("doesn’t exist", "doesn't exist", "not found")),
    ("GitBook", "https://{u}.gitbook.io/", ("not found",)),
    ("Read the Docs", "https://{u}.readthedocs.io/", ("404",)),
    ("Surge", "https://{u}.surge.sh/", ("not found", "404")),
]

LOGIN_MARKERS = (
    "sign in",
    "sign up",
    "log in",
    "login",
    "create account",
    "join now",
    "enable javascript",
    "access denied",
    "captcha",
)
GLOBAL_NEGATIVES = (
    "user not found",
    "usuario no encontrado",
    "profile not found",
    "perfil no encontrado",
    "page not found",
    "no such user",
    "could not be found",
    "doesn't exist",
    "does not exist",
    "nobody on reddit goes by that name",
)
TITLE_REQUIRED = {"Spotify", "Twitch"}


@module("username_presence")
def username_presence(ctx: Context, tool: Any) -> list[Finding]:
    username = ctx.target.strip().lstrip("@")
    findings: list[Finding] = []
    found: list[tuple[str, str]] = []
    unknown: list[str] = []
    checked = 0

    def check(entry: tuple[str, str, tuple[str, ...]]) -> tuple[str, str, str, str]:
        name, template, negatives = entry
        url = template.format(u=quote(username, safe=""))
        try:
            response = ctx.http.get(url, timeout=12, retries=0, allow_cache=True)
        except (NetworkError, HttpError):
            return name, url, "unknown", "sin respuesta"
        if response.status == 404:
            return name, url, "no", "404"
        if response.status in (401, 403, 429):
            return name, url, "unknown", f"HTTP {response.status}"
        if not response.ok:
            return name, url, "no", f"HTTP {response.status}"
        final_url = str(response.url or url).lower()
        if any(
            part in final_url
            for part in ("/login", "/signin", "/signup", "/search", "/explore")
        ):
            return name, url, "unknown", "redirigido a login/búsqueda"
        lower = response.text[:20000].lower()
        markers = tuple(negatives) + GLOBAL_NEGATIVES
        if any(marker.lower() in lower for marker in markers):
            return name, url, "no", "marcador de no encontrado"
        if name == "Telegram":
            if "tgme_page_title" in response.text or "tgme_page_extra" in response.text:
                return name, url, "yes", fetch_title(response.text)
            return name, url, "unknown", "página sin perfil"
        title = fetch_title(response.text)
        if name in TITLE_REQUIRED and username.lower() not in title.lower():
            return name, url, "unknown", "página genérica sin datos del perfil"
        if any(marker in lower for marker in LOGIN_MARKERS) and len(response.text) < 25000:
            return name, url, "unknown", "muro de login/JS"
        return name, url, "yes", title

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        futures = [pool.submit(check, entry) for entry in PRESENCE_SITES]
        for future in concurrent.futures.as_completed(futures):
            name, url, state, detail = future.result()
            checked += 1
            if state == "yes":
                found.append((name, url))
                findings.append(f(f"{name}", detail or url, "good", url=url))
            elif state == "unknown":
                unknown.append(name)
    findings.insert(0, f("Sitios comprobados", str(checked), "info"))
    findings.insert(1, f("Cuentas encontradas", str(len(found)), "good" if found else "info"))
    if unknown:
        findings.append(f("Sin verificar", join_limited(unknown, 30), "warn"))
    if not found:
        findings.append(f("Resultado", f"no se encontró '{username}' en las fuentes comprobadas", "info"))
    return findings


def _api(ctx: Context, url: str, headers: dict[str, str] | None = None) -> Any:
    try:
        response = ctx.http.get(url, headers=headers, timeout=25, retries=1)
    except (NetworkError, HttpError):
        return None
    if not response.ok:
        return None
    try:
        return response.json()
    except ValueError:
        return None


def _github(ctx: Context, username: str) -> list[Finding]:
    headers = {}
    if ctx.has_key("GITHUB_TOKEN"):
        headers["Authorization"] = "Bearer " + ctx.key("GITHUB_TOKEN")
    data = _api(ctx, f"https://api.github.com/users/{quote(username, safe='')}", headers)
    if not isinstance(data, dict):
        return [f("GitHub", "usuario no encontrado o API sin acceso", "info", url=f"https://github.com/{username}")]
    findings: list[Finding] = [
        f("Perfil", data.get("html_url", ""), "good", url=data.get("html_url", "")),
        f("Nombre", data.get("name") or "—", "info"),
        f("Bio", data.get("bio") or "—", "info"),
        f("Empresa", data.get("company") or "—", "info"),
        f("Ubicación", data.get("location") or "—", "info"),
        f("Blog", data.get("blog") or "—", "link", url=data.get("blog") or ""),
        f("Twitter", data.get("twitter_username") or "—", "info"),
        f("Repositorios públicos", str(data.get("public_repos", 0)), "info"),
        f("Seguidores", f"{data.get('followers', 0)} / siguiendo {data.get('following', 0)}", "info"),
        f("Creado", str(data.get("created_at", "")), "info"),
        f("Actualizado", str(data.get("updated_at", "")), "info"),
    ]
    repos = _api(ctx, f"https://api.github.com/users/{quote(username, safe='')}/repos?per_page=100&sort=updated", headers)
    if isinstance(repos, list) and repos:
        langs: dict[str, int] = {}
        for repo in repos:
            if isinstance(repo, dict):
                lang = repo.get("language")
                if lang:
                    langs[lang] = langs.get(lang, 0) + 1
        findings.append(f("Lenguajes", join_limited([f"{k} ({v})" for k, v in sorted(langs.items(), key=lambda x: x[1], reverse=True)], 10), "info"))
        for repo in repos[:10]:
            if isinstance(repo, dict):
                findings.append(
                    f("Repo", f"{repo.get('name')} · ⭐{repo.get('stargazers_count', 0)} · {repo.get('language') or ''}",
                    "info", url=str(repo.get("html_url", "")), data={"description": repo.get("description")}
                ))
    events = _api(ctx, f"https://api.github.com/users/{quote(username, safe='')}/events/public?per_page=10", headers)
    if isinstance(events, list) and events:
        types: dict[str, int] = {}
        for event in events:
            if isinstance(event, dict):
                types[event.get("type", "?")] = types.get(event.get("type", "?"), 0) + 1
        findings.append(f("Actividad reciente", join_limited([f"{k}: {v}" for k, v in types.items()], 10), "info"))
    return findings


def _gitlab(ctx: Context, username: str) -> list[Finding]:
    users = _api(ctx, f"https://gitlab.com/api/v4/users?username={quote(username, safe='')}")
    if not isinstance(users, list) or not users:
        return [f("GitLab", "usuario no encontrado", "info", url=f"https://gitlab.com/{username}")]
    user = users[0]
    findings: list[Finding] = [
        f("Perfil", user.get("web_url", ""), "good", url=user.get("web_url", "")),
        f("Nombre", user.get("name") or "—", "info"),
        f("Estado", user.get("state") or "—", "info"),
        f("Bio", user.get("bio") or "—", "info"),
        f("Ubicación", user.get("location") or "—", "info"),
        f("Email público", user.get("public_email") or "—", "info"),
        f("Creado", str(user.get("created_at", "")), "info"),
    ]
    uid = user.get("id")
    if uid:
        projects = _api(ctx, f"https://gitlab.com/api/v4/users/{uid}/projects?per_page=100")
        if isinstance(projects, list):
            findings.append(f("Proyectos públicos", str(len(projects)), "info"))
            for project in projects[:10]:
                if isinstance(project, dict):
                    findings.append(f("Proyecto", str(project.get("name", "")), "info", url=str(project.get("web_url", ""))))
    return findings


def _reddit(ctx: Context, username: str) -> list[Finding]:
    data = None
    for host in ("www.reddit.com", "old.reddit.com"):
        try:
            response = ctx.http.get(
                f"https://{host}/user/{quote(username, safe='')}/about.json",
                timeout=20,
                retries=0,
                headers={"User-Agent": "osintkit/1.0 by u/osintkit"},
            )
        except (NetworkError, HttpError):
            continue
        if response.ok:
            try:
                data = response.json()
                if isinstance(data, dict) and data.get("data"):
                    break
                data = None
            except (ValueError, HttpError):
                data = None
            continue
        if response.status == 403:
            continue
    if not isinstance(data, dict):
        return [
            f("Reddit", "la API bloqueó la consulta; abrí el perfil manualmente", "warn",
              url=f"https://www.reddit.com/user/{username}")
        ]
    payload = data.get("data") or {}
    return [
        f("Perfil", f"https://www.reddit.com/user/{username}", "good", url=f"https://www.reddit.com/user/{username}"),
        f("Karma", f"{payload.get('link_karma', 0)} link / {payload.get('comment_karma', 0)} comentario", "info"),
        f("Creado", str(payload.get("created_utc", "")), "info"),
        f("Verificado", str(payload.get("verified", False)), "info"),
        f("Moderador", str(payload.get("is_mod", False)), "info"),
    ]


def _keybase(ctx: Context, username: str) -> list[Finding]:
    data = _api(ctx, f"https://keybase.io/_/api/1.0/user/lookup.json?username={quote(username, safe='')}&fields=basics,profile,proofs,public_keys")
    if not isinstance(data, dict) or not data.get("them"):
        return [f("Keybase", "usuario no encontrado", "info", url=f"https://keybase.io/{username}")]
    them = data["them"]
    basics = them.get("basics") or {}
    profile = them.get("profile") or {}
    findings: list[Finding] = [
        f("Perfil", f"https://keybase.io/{basics.get('username', username)}", "good",
          url=f"https://keybase.io/{basics.get('username', username)}"),
        f("Nombre", str(profile.get("full_name") or "—"), "info"),
        f("Ubicación", str(profile.get("location") or "—"), "info"),
        f("Bio", str(profile.get("bio") or "—"), "info"),
    ]
    for proof in (them.get("proofs") or [])[:20]:
        if isinstance(proof, dict):
            findings.append(
                f("Prueba", f"{proof.get('proof_type')}: {proof.get('nametag')}", "link",
                url=str(proof.get("service_url", ""))
            ))
    keys = them.get("public_keys") or []
    if keys:
        findings.append(f("Claves públicas", str(len(keys)), "info"))
    return findings


def _hackernews(ctx: Context, username: str) -> list[Finding]:
    data = _api(ctx, f"https://hacker-news.firebaseio.com/v0/user/{quote(username, safe='')}.json")
    if not isinstance(data, dict):
        return [f("Hacker News", "usuario no encontrado", "info", url=f"https://news.ycombinator.com/user?id={username}")]
    findings: list[Finding] = [
        f("Perfil", f"https://news.ycombinator.com/user?id={username}", "good",
          url=f"https://news.ycombinator.com/user?id={username}"),
        f("Karma", str(data.get("karma", 0)), "info"),
        f("Creado", str(data.get("created", "")), "info"),
        f("Acerca de", strip_tags(str(data.get("about", ""))) or "—", "info"),
    ]
    search = _api(ctx, f"https://hn.algolia.com/api/v1/search?tags=author_{quote(username, safe='')}&hitsPerPage=5")
    if isinstance(search, dict) and search.get("hits"):
        findings.append(f("Contribuciones indexadas", str(search.get("nbHits", len(search["hits"]))), "info"))
        for hit in search["hits"][:5]:
            if isinstance(hit, dict):
                title = hit.get("title") or hit.get("story_title") or hit.get("comment_text") or ""
                findings.append(f("Actividad", truncate(strip_tags(str(title)), 160), "info",
                                url=f"https://news.ycombinator.com/item?id={hit.get('objectID')}"))
    return findings


def _mastodon(ctx: Context, username: str) -> list[Finding]:
    data = _api(ctx, f"https://mastodon.social/api/v2/search?q={quote(username, safe='')}&type=accounts&limit=5")
    accounts = (data or {}).get("accounts") if isinstance(data, dict) else None
    if not accounts:
        return [f("Mastodon", "sin coincidencias en mastodon.social", "info")]
    findings: list[Finding] = []
    for account in accounts[:5]:
        if not isinstance(account, dict):
            continue
        if str(account.get("username", "")).lower() != username.lower() and str(account.get("acct", "")).split("@")[0].lower() != username.lower():
            continue
        findings.append(
            f("Cuenta", f"@{account.get('acct')} · {account.get('display_name') or ''}", "good",
            url=str(account.get("url", "")),
            data={"followers": account.get("followers_count"), "statuses": account.get("statuses_count"),
                  "created": account.get("created_at"), "note": truncate(strip_tags(str(account.get("note", ""))), 200)}
        ))
    return findings or [f("Mastodon", "sin coincidencias exactas", "info")]


def _telegram(ctx: Context, username: str) -> list[Finding]:
    url = f"https://t.me/{quote(username, safe='')}"
    response = safe_get(ctx, url, timeout=20)
    if not response or not response.ok:
        return [f("Telegram", "no se pudo consultar", "warn", url=url)]
    title = ""
    desc = ""
    match = re.search(r'<meta[^>]+property=["\']og:title["\'][^>]+content=["\'](.*?)["\']', response.text, re.I | re.S)
    if match:
        title = html_lib.unescape(match.group(1))
    match = re.search(r'<meta[^>]+property=["\']og:description["\'][^>]+content=["\'](.*?)["\']', response.text, re.I | re.S)
    if match:
        desc = html_lib.unescape(match.group(1))
    if "tgme_page_title" not in response.text and not title:
        return [f("Telegram", "el alias no parece existir", "info", url=url)]
    findings: list[Finding] = [
        f("Perfil", title or f"@{username}", "good", url=url),
        f("Descripción", desc or "—", "info"),
    ]
    extra = re.search(r'tgme_page_extra["\'][^>]*>(.*?)<', response.text, re.S)
    if extra:
        findings.append(f("Detalle", collapse_ws(strip_tags(extra.group(1))), "info"))
    return findings


def _pypi(ctx: Context, username: str) -> list[Finding]:
    url = f"https://pypi.org/user/{quote(username, safe='')}/"
    response = safe_get(ctx, url, timeout=20)
    if not response or not response.ok:
        return [f("PyPI", "perfil no encontrado", "info", url=url)]
    projects = dedupe(re.findall(r'/project/([A-Za-z0-9_.-]+)/', response.text))
    findings: list[Finding] = [f("Perfil", url, "good", url=url), f("Proyectos", str(len(projects)), "info")]
    for project in projects[:20]:
        findings.append(f("Paquete", project, "link", url=f"https://pypi.org/project/{project}/"))
    return findings


def _npm(ctx: Context, username: str) -> list[Finding]:
    url = f"https://registry.npmjs.org/-/user/org.couchdb.user:{quote(username, safe='')}"
    data = _api(ctx, url)
    if not isinstance(data, dict):
        return [f("npm", "perfil no encontrado", "info", url=f"https://www.npmjs.com/~{username}")]
    return [
        f("Perfil", f"https://www.npmjs.com/~{username}", "good", url=f"https://www.npmjs.com/~{username}"),
        f("Nombre", str(data.get("name", username)), "info"),
        f("Email", str(data.get("email") or "—"), "info"),
        f("URL", str(data.get("url") or "—"), "info"),
    ]


def _dockerhub(ctx: Context, username: str) -> list[Finding]:
    data = _api(ctx, f"https://hub.docker.com/v2/users/{quote(username, safe='')}/")
    if not isinstance(data, dict):
        return [f("Docker Hub", "perfil no encontrado", "info", url=f"https://hub.docker.com/u/{username}")]
    findings: list[Finding] = [
        f("Perfil", f"https://hub.docker.com/u/{username}", "good", url=f"https://hub.docker.com/u/{username}"),
        f("Nombre", str(data.get("full_name") or "—"), "info"),
        f("Empresa", str(data.get("company") or "—"), "info"),
        f("Ubicación", str(data.get("location") or "—"), "info"),
        f("Alta", str(data.get("date_joined", "")), "info"),
    ]
    repos = _api(ctx, f"https://hub.docker.com/v2/repositories/{quote(username, safe='')}/?page_size=10")
    if isinstance(repos, dict):
        findings.append(f("Repositorios", str(repos.get("count", 0)), "info"))
        for repo in (repos.get("results") or [])[:10]:
            if isinstance(repo, dict):
                findings.append(f("Repo", f"{repo.get('name')} · {repo.get('pull_count', 0)} pulls", "info",
                                url=f"https://hub.docker.com/r/{username}/{repo.get('name')}"))
    return findings


def _stackoverflow(ctx: Context, username: str) -> list[Finding]:
    data = _api(
        ctx,
        f"https://api.stackexchange.com/2.3/users?order=desc&sort=reputation&inname={quote(username, safe='')}&site=stackoverflow&pagesize=10",
    )
    items = (data or {}).get("items") if isinstance(data, dict) else None
    if not items:
        return [f("Stack Overflow", "usuario no encontrado", "info")]
    findings: list[Finding] = []
    for user in items[:5]:
        if not isinstance(user, dict):
            continue
        if str(user.get("display_name", "")).lower() != username.lower():
            continue
        badges = user.get("badge_counts") or {}
        findings.append(
            f("Perfil", f"{user.get('display_name')} · reputación {user.get('reputation')}", "good",
            url=str(user.get("link", "")),
            data={"badges": badges, "created": user.get("creation_date"), "location": user.get("location")}
        ))
    return findings or [f("Stack Overflow", "sin coincidencia exacta", "info")]


def _twitch(ctx: Context, username: str) -> list[Finding]:
    try:
        token_response = ctx.http.post_form(
            "https://id.twitch.tv/oauth2/token",
            {
                "client_id": ctx.key("TWITCH_CLIENT_ID"),
                "client_secret": ctx.key("TWITCH_CLIENT_SECRET"),
                "grant_type": "client_credentials",
            },
            timeout=20,
        )
        token = (token_response.json() or {}).get("access_token") if token_response.ok else None
    except (NetworkError, HttpError, ValueError):
        token = None
    if not token:
        return [f("Twitch", "no se pudo obtener token de API", "warn")]
    data = _api(
        ctx,
        f"https://api.twitch.tv/helix/users?login={quote(username, safe='')}",
        headers={"Client-Id": ctx.key("TWITCH_CLIENT_ID"), "Authorization": "Bearer " + token},
    )
    users = (data or {}).get("data") if isinstance(data, dict) else None
    if not users:
        return [f("Twitch", "canal no encontrado", "info", url=f"https://www.twitch.tv/{username}")]
    user = users[0]
    return [
        f("Perfil", f"https://www.twitch.tv/{user.get('login')}", "good", url=f"https://www.twitch.tv/{user.get('login')}"),
        f("Nombre", str(user.get("display_name", "")), "info"),
        f("Descripción", str(user.get("description", "")) or "—", "info"),
        f("Creado", str(user.get("created_at", "")), "info"),
        f("Tipo", str(user.get("type", "")), "info"),
    ]


def _steam(ctx: Context, username: str) -> list[Finding]:
    try:
        response = ctx.http.get(
            "https://api.steampowered.com/ISteamUser/ResolveVanityURL/v1/",
            params={"key": ctx.key("STEAM_API_KEY"), "vanityurl": username},
            timeout=20,
        )
        resolved = response.json() if response.ok else {}
    except (NetworkError, HttpError, ValueError):
        resolved = {}
    steam_id = (resolved.get("response") or {}).get("steamid") if isinstance(resolved, dict) else None
    if not steam_id:
        return [f("Steam", "vanity URL no encontrada", "info", url=f"https://steamcommunity.com/id/{username}")]
    try:
        response = ctx.http.get(
            "https://api.steampowered.com/ISteamUser/GetPlayerSummaries/v2/",
            params={"key": ctx.key("STEAM_API_KEY"), "steamids": steam_id},
            timeout=20,
        )
        players = (response.json().get("response") or {}).get("players") if response.ok else []
    except (NetworkError, HttpError, ValueError):
        players = []
    findings: list[Finding] = [
        f("SteamID64", steam_id, "good", url=f"https://steamcommunity.com/profiles/{steam_id}"),
    ]
    for player in players or []:
        if isinstance(player, dict):
            findings.append(f("Nombre", str(player.get("personaname", "")), "info"))
            findings.append(f("Perfil", str(player.get("profileurl", "")), "link", url=str(player.get("profileurl", ""))))
            findings.append(f("País", str(player.get("loccountrycode", "")), "info"))
            if player.get("realname"):
                findings.append(f("Nombre real", str(player["realname"]), "warn"))
    return findings


@module("username_site")
def username_site(ctx: Context, tool: Any) -> list[Finding]:
    site = str(tool.options.get("site", ""))
    username = ctx.target.strip().lstrip("@")
    handlers = {
        "github": _github,
        "gitlab": _gitlab,
        "reddit": _reddit,
        "keybase": _keybase,
        "hackernews": _hackernews,
        "mastodon": _mastodon,
        "telegram": _telegram,
        "pypi": _pypi,
        "npm": _npm,
        "dockerhub": _dockerhub,
        "stackoverflow": _stackoverflow,
        "twitch": _twitch,
        "steam": _steam,
    }
    handler = handlers.get(site)
    if not handler:
        return [f("Usuario", f"sitio no implementado: {site}", "warn")]
    return handler(ctx, username)
