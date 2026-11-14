"""Helpers compartidos por los módulos internos."""

from __future__ import annotations

import html
import json
import re
import socket
from typing import Any, Iterable
from urllib.parse import quote, quote_plus

from ..core import Context, Finding
from ..http import HttpError, NetworkError, Response
from ..util import (
    collapse_ws,
    extract_host,
    is_domain,
    is_ip,
    normalize_domain,
    reverse_ip,
    truncate,
)


def f(
    title: str,
    value: str = "",
    level: str = "info",
    url: str = "",
    **data: Any,
) -> Finding:
    return Finding(title=title, value=str(value), level=level, url=url, data=data)


def domain_for(ctx: Context) -> str:
    if ctx.kind == "url":
        return normalize_domain(extract_host(ctx.target))
    if ctx.kind == "email":
        return ctx.target.rsplit("@", 1)[-1].lower()
    return normalize_domain(ctx.target)


def ip_for(ctx: Context) -> str | None:
    if ctx.kind == "ip":
        return ctx.target
    host = extract_host(ctx.target) if ctx.kind == "url" else domain_for(ctx)
    ips = resolve_ips(ctx, host)
    return ips[0] if ips else None


def web_url(ctx: Context) -> str:
    if ctx.target.startswith(("http://", "https://")):
        return ctx.target
    return f"https://{ctx.target}"


def doh(ctx: Context, name: str, rtype: str = "A", timeout: float = 15) -> dict[str, Any]:
    """Consulta DNS-over-HTTPS con fallback Google -> Cloudflare."""
    endpoints = [
        "https://dns.google/resolve",
        "https://cloudflare-dns.com/dns-query",
    ]
    last_error: Exception | None = None
    for endpoint in endpoints:
        try:
            params = {"name": name, "type": rtype}
            headers = {"Accept": "application/dns-json"}
            if "cloudflare" in endpoint:
                params["ct"] = "application/dns-json"
            response = ctx.http.get(
                endpoint,
                params=params,
                headers=headers,
                timeout=timeout,
                retries=1,
            )
            if response.ok:
                data = response.json()
                if isinstance(data, dict):
                    if data.get("Status") in (0, 3, None) or data.get("Answer"):
                        return data
            last_error = HttpError(response.status, endpoint, response.text[:200])
        except (NetworkError, HttpError, ValueError) as exc:
            last_error = exc
            continue
    raise NetworkError(f"DNS-over-HTTPS falló para {name} ({rtype}): {last_error}")


def doh_answers(ctx: Context, name: str, rtype: str = "A") -> list[dict[str, Any]]:
    try:
        data = doh(ctx, name, rtype)
    except NetworkError:
        return []
    answers = data.get("Answer") or []
    return [a for a in answers if isinstance(a, dict)]


def doh_values(ctx: Context, name: str, rtype: str = "A") -> list[str]:
    return [str(a.get("data", "")).strip() for a in doh_answers(ctx, name, rtype) if a.get("data")]


def doh_txt(ctx: Context, name: str) -> list[str]:
    values = []
    for raw in doh_values(ctx, name, "TXT"):
        # DoH puede devolver varios strings entre comillas en un mismo registro.
        parts = re.findall(r'"([^"]*)"', raw)
        text = "".join(parts) if parts else raw.strip('"')
        if text:
            values.append(text)
    return values


def resolve_ips(ctx: Context, domain: str) -> list[str]:
    if is_ip(domain):
        return [domain]
    ips: list[str] = []
    for rtype in ("A", "AAAA"):
        for value in doh_values(ctx, domain, rtype):
            if is_ip(value) and value not in ips:
                ips.append(value)
    return ips


def resolve_cname(ctx: Context, name: str) -> list[str]:
    return [v.rstrip(".") for v in doh_values(ctx, name, "CNAME")]


def reverse_dns_name(ip: str) -> str | None:
    rev = reverse_ip(ip)
    if not rev:
        return None
    if ":" in ip:
        return f"{rev}.ip6.arpa"
    return f"{rev}.in-addr.arpa"


def safe_get(
    ctx: Context,
    url: str,
    *,
    timeout: float | None = None,
    headers: dict[str, str] | None = None,
    retries: int = 1,
) -> Response | None:
    try:
        return ctx.http.get(url, timeout=timeout or ctx.timeout, headers=headers, retries=retries)
    except (NetworkError, HttpError):
        return None


def safe_json(
    ctx: Context,
    url: str,
    *,
    timeout: float | None = None,
    headers: dict[str, str] | None = None,
    retries: int = 1,
) -> Any:
    response = safe_get(ctx, url, timeout=timeout, headers=headers, retries=retries)
    if not response or not response.ok:
        return None
    try:
        return response.json()
    except (ValueError, json.JSONDecodeError):
        return None


def fetch_title(html_text: str) -> str:
    match = re.search(r"<title[^>]*>(.*?)</title>", html_text, re.I | re.S)
    if not match:
        return ""
    return collapse_ws(html.unescape(re.sub(r"<[^>]+>", " ", match.group(1))))


def strip_tags(value: str) -> str:
    return collapse_ws(html.unescape(re.sub(r"<[^>]+>", " ", value)))


def meta_content(html_text: str, name: str) -> str:
    pattern = (
        r'<meta[^>]+(?:name|property)=["\']'
        + re.escape(name)
        + r'["\'][^>]+content=["\'](.*?)["\']'
    )
    match = re.search(pattern, html_text, re.I | re.S)
    if not match:
        pattern2 = (
            r'<meta[^>]+content=["\'](.*?)["\'][^>]+(?:name|property)=["\']'
            + re.escape(name)
            + r'["\']'
        )
        match = re.search(pattern2, html_text, re.I | re.S)
    return collapse_ws(html.unescape(match.group(1))) if match else ""


def host_ip(host: str) -> str | None:
    try:
        infos = socket.getaddrinfo(host, None)
    except OSError:
        return None
    for info in infos:
        addr = info[4][0]
        if addr and not addr.startswith("127."):
            return addr
    return infos[0][4][0] if infos else None


def q(value: str) -> str:
    return quote_plus(value)


def urlquote(value: str) -> str:
    return quote(value, safe="")


def vt_url_id(url: str) -> str:
    import base64

    return base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii").rstrip("=")


def as_list(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    if value is None:
        return []
    return [value]


def join_limited(values: Iterable[Any], limit: int = 20, sep: str = ", ") -> str:
    items = [truncate(str(v), 120) for v in values if str(v).strip()]
    if len(items) > limit:
        return sep.join(items[:limit]) + f" … (+{len(items) - limit})"
    return sep.join(items)


def cve_id(value: str) -> str | None:
    match = re.search(r"CVE-\d{4}-\d{4,}", value, re.I)
    return match.group(0).upper() if match else None
