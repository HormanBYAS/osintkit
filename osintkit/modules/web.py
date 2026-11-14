"""Módulos de superficie web, TLS, archivado y dorks."""

from __future__ import annotations

import concurrent.futures
import html
import re
import socket
import ssl
import xml.etree.ElementTree as ET
from typing import Any
from urllib.parse import quote_plus, urlsplit

from ..core import Context, Finding, module
from ..http import HttpError, NetworkError
from ..util import (
    collapse_ws,
    days_until,
    dedupe,
    extract_host,
    normalize_domain,
    truncate,
)
from .base import (
    domain_for,
    f,
    fetch_title,
    host_ip,
    join_limited,
    meta_content,
    q,
    resolve_ips,
    safe_get,
    safe_json,
    strip_tags,
    web_url,
)


@module("http_probe")
def http_probe(ctx: Context, tool: Any) -> list[Finding]:
    findings: list[Finding] = []
    url = web_url(ctx)
    response = None
    used_url = url
    try:
        response = ctx.http.get(url, timeout=25, retries=1, max_bytes=3_000_000)
    except (NetworkError, HttpError) as exc:
        findings.append(f("HTTPS", f"falló: {exc}", "warn"))
    if not response or response.status >= 400:
        if used_url.startswith("https://"):
            alt = "http://" + used_url[8:]
            try:
                response = ctx.http.get(alt, timeout=25, retries=1, max_bytes=3_000_000)
                used_url = alt
                findings.append(f("HTTPS", "falló; el sitio responde por HTTP sin cifrar", "warn"))
            except (NetworkError, HttpError):
                pass
    if not response:
        return findings + [f("HTTP", "el sitio no respondió", "bad")]
    findings.append(f("Estado HTTP", str(response.status), "good" if response.ok else "warn"))
    findings.append(f("URL final", response.url or used_url, "info", url=response.url or used_url))
    server = response.header("server")
    if server:
        findings.append(f("Servidor", server, "info"))
    powered = response.header("x-powered-by")
    if powered:
        findings.append(f("X-Powered-By", powered, "info"))
    for header in ("via", "cf-ray", "x-cache", "x-served-by", "x-vercel-id", "x-amz-cf-id"):
        value = response.header(header)
        if value:
            findings.append(f(f"Cabecera {header}", value, "info"))
    content_type = response.header("content-type")
    if content_type:
        findings.append(f("Content-Type", content_type, "info"))
    if response.raw_length:
        findings.append(f("Tamaño de respuesta", f"{response.raw_length} bytes", "info"))
    title = fetch_title(response.text)
    if title:
        findings.append(f("Título", title, "info"))
    cookies = response.headers.get("set-cookie", "")
    if cookies:
        names = dedupe(re.findall(r"(?:^|,)\s*([A-Za-z0-9_.-]+)=", cookies))
        flags = []
        lower = cookies.lower()
        if "httponly" in lower:
            flags.append("HttpOnly")
        if "secure" in lower:
            flags.append("Secure")
        if "samesite" in lower:
            flags.append("SameSite")
        findings.append(f("Cookies", f"{join_limited(names, 15) or 'presentes'} · {', '.join(flags) or 'sin flags visibles'}", "info"))
    security_headers = {
        "strict-transport-security": "HSTS",
        "content-security-policy": "CSP",
        "x-frame-options": "X-Frame-Options",
        "x-content-type-options": "X-Content-Type-Options",
        "referrer-policy": "Referrer-Policy",
        "permissions-policy": "Permissions-Policy",
    }
    missing = []
    for header, label in security_headers.items():
        value = response.header(header)
        if value:
            findings.append(f(f"Seguridad: {label}", truncate(value, 300), "good"))
        else:
            missing.append(label)
    if missing:
        findings.append(f("Cabeceras ausentes", ", ".join(missing), "warn"))
    ip = host_ip(extract_host(response.url or used_url))
    if ip:
        findings.append(f("IP de destino", ip, "info"))
    server_header = response.header("server").lower()
    if "cloudflare" in server_header or response.header("cf-ray"):
        findings.append(f("CDN/WAF", "Cloudflare", "info"))
    return findings


@module("tls_certificate")
def tls_certificate(ctx: Context, tool: Any) -> list[Finding]:
    parsed = urlsplit(web_url(ctx))
    host = parsed.hostname or extract_host(ctx.target)
    port = parsed.port or 443
    if port == 80:
        port = 443
    findings: list[Finding] = []
    context = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=15) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert()
                version = tls.version()
                cipher = tls.cipher()
    except ssl.SSLCertVerificationError as exc:
        findings.append(f("Validación TLS", f"certificado no válido: {exc.verify_message}", "bad"))
        try:
            context = ssl._create_unverified_context()
            with socket.create_connection((host, port), timeout=15) as sock:
                with context.wrap_socket(sock, server_hostname=host) as tls:
                    cert = tls.getpeercert()
                    version = tls.version()
                    cipher = tls.cipher()
        except Exception as exc2:  # noqa: BLE001
            return findings + [f("TLS", f"no se pudo conectar: {exc2}", "bad")]
    except (OSError, ssl.SSLError) as exc:
        return findings + [f("TLS", f"no se pudo conectar a {host}:{port}: {exc}", "bad")]

    subject = {k: v for item in cert.get("subject", []) for k, v in item}
    issuer = {k: v for item in cert.get("issuer", []) for k, v in item}
    findings.append(f("Versión TLS", str(version), "good" if version in ("TLSv1.3", "TLSv1.2") else "warn"))
    if cipher:
        findings.append(f("Cifrado", f"{cipher[0]} ({cipher[1]})", "info"))
    if subject:
        findings.append(f("Sujeto", ", ".join(f"{k}={v}" for k, v in subject.items()), "info"))
    if issuer:
        findings.append(f("Emisor", ", ".join(f"{k}={v}" for k, v in issuer.items()), "info"))
    sans = [value for kind, value in cert.get("subjectAltName", []) if kind in ("DNS", "IP Address")]
    if sans:
        findings.append(f("SANs", join_limited(sans, 30), "info"))
    not_before = cert.get("notBefore", "")
    not_after = cert.get("notAfter", "")
    days = days_until(not_after)
    level = "good"
    if days is not None:
        if days < 0:
            level = "bad"
        elif days < 14:
            level = "bad"
        elif days < 30:
            level = "warn"
        findings.append(f("Vigencia", f"{not_before} → {not_after} ({days} días)", level))
    else:
        findings.append(f("Vigencia", f"{not_before} → {not_after}", "info"))
    if cert.get("serialNumber"):
        findings.append(f("Serial", cert["serialNumber"], "info"))
    return findings


@module("robots_txt")
def robots_txt(ctx: Context, tool: Any) -> list[Finding]:
    url = web_url(ctx).rstrip("/") + "/robots.txt"
    response = safe_get(ctx, url, timeout=20)
    if not response:
        return [f("robots.txt", "no se pudo consultar", "warn")]
    if response.status == 404:
        return [f("robots.txt", "no existe (404)", "info", url=url)]
    if not response.ok:
        return [f("robots.txt", f"HTTP {response.status}", "warn", url=url)]
    findings: list[Finding] = [f("robots.txt", f"HTTP {response.status} · {len(response.text)} bytes", "good", url=url)]
    disallow: list[str] = []
    allow: list[str] = []
    sitemaps: list[str] = []
    agents: list[str] = []
    for line in response.text.splitlines():
        line = line.split("#", 1)[0].strip()
        if ":" not in line:
            continue
        key, value = [x.strip() for x in line.split(":", 1)]
        key = key.lower()
        if key == "disallow" and value:
            disallow.append(value)
        elif key == "allow" and value:
            allow.append(value)
        elif key == "sitemap" and value:
            sitemaps.append(value)
        elif key == "user-agent" and value:
            agents.append(value)
    if agents:
        findings.append(f("User-agents", join_limited(dedupe(agents), 10), "info"))
    if disallow:
        findings.append(f("Rutas bloqueadas", str(len(dedupe(disallow))), "warn"))
        for path in dedupe(disallow)[:80]:
            findings.append(f("Disallow", path, "info"))
    if allow:
        for path in dedupe(allow)[:30]:
            findings.append(f("Allow", path, "info"))
    if sitemaps:
        for sitemap in dedupe(sitemaps)[:10]:
            findings.append(f("Sitemap", sitemap, "link", url=sitemap))
    return findings


@module("sitemap_xml")
def sitemap_xml(ctx: Context, tool: Any) -> list[Finding]:
    base = web_url(ctx).rstrip("/")
    candidates = [base + "/sitemap.xml", base + "/sitemap_index.xml", base + "/sitemap-index.xml"]
    response = None
    used = ""
    for candidate in candidates:
        response = safe_get(ctx, candidate, timeout=20)
        if response and response.ok:
            used = candidate
            break
    if not response or not response.ok:
        return [f("Sitemap", "no se encontró sitemap.xml", "info")]
    findings: list[Finding] = [f("Sitemap", f"HTTP {response.status} · {used}", "good", url=used)]
    try:
        root = ET.fromstring(response.text)
    except ET.ParseError:
        return findings + [f("Sitemap", "XML inválido", "warn")]
    locs: list[str] = []
    for element in root.iter():
        tag = element.tag.split("}", 1)[-1].lower()
        if tag in ("loc", "href") and element.text and element.text.strip():
            locs.append(element.text.strip())
    locs = dedupe(locs)
    findings.append(f("URLs declaradas", str(len(locs)), "info"))
    for loc in locs[:200]:
        findings.append(f("URL", loc, "link", url=loc))
    if len(locs) > 200:
        findings.append(f("URLs (resto)", f"{len(locs) - 200} más", "info"))
    return findings


@module("security_txt")
def security_txt(ctx: Context, tool: Any) -> list[Finding]:
    base = web_url(ctx).rstrip("/")
    for candidate in (base + "/.well-known/security.txt", base + "/security.txt"):
        response = safe_get(ctx, candidate, timeout=20)
        if response and response.ok:
            findings: list[Finding] = [f("security.txt", f"HTTP {response.status} · {candidate}", "good", url=candidate)]
            values: dict[str, list[str]] = {}
            for line in response.text.splitlines():
                line = line.strip()
                if not line or line.startswith("#") or ":" not in line:
                    continue
                key, value = [x.strip() for x in line.split(":", 1)]
                values.setdefault(key.lower(), []).append(value)
            for key, items in values.items():
                for value in items[:8]:
                    level = "warn" if key == "expires" and days_until(value) is not None and days_until(value) < 0 else "info"  # type: ignore[operator]
                    findings.append(f(f"{key}", value, level, url=value if value.startswith("http") else ""))
            if "contact" not in values:
                findings.append(f("Contacto", "no declara contacto", "warn"))
            return findings
    return [f("security.txt", "no existe", "info")]


TECH_SIGNATURES = {
    "wordpress": "WordPress",
    "wp-content": "WordPress",
    "drupal": "Drupal",
    "joomla": "Joomla",
    "shopify": "Shopify",
    "wix.com": "Wix",
    "squarespace": "Squarespace",
    "ghost": "Ghost",
    "django": "Django",
    "laravel": "Laravel",
    "rails": "Ruby on Rails",
    "react": "React",
    "vue": "Vue.js",
    "angular": "Angular",
    "next.js": "Next.js",
    "nuxt": "Nuxt",
    "jquery": "jQuery",
    "bootstrap": "Bootstrap",
    "cloudflare": "Cloudflare",
    "akamai": "Akamai",
    "fastly": "Fastly",
    "nginx": "Nginx",
    "apache": "Apache",
    "iis": "Microsoft IIS",
    "google analytics": "Google Analytics",
    "gtag(": "Google Tag Manager",
    "googletagmanager": "Google Tag Manager",
    "facebook.net": "Meta Pixel",
    "hotjar": "Hotjar",
    "sentry": "Sentry",
    "stripe": "Stripe",
    "recaptcha": "reCAPTCHA",
}


@module("web_tech")
def web_tech(ctx: Context, tool: Any) -> list[Finding]:
    response = safe_get(ctx, web_url(ctx), timeout=25)
    if not response or not response.ok:
        return [f("Tecnologías", f"no se pudo obtener la página ({response.status if response else 'sin respuesta'})", "warn")]
    body = response.text
    lower = body.lower()
    headers_blob = " ".join(f"{k}: {v}" for k, v in response.headers.items()).lower()
    found: list[str] = []
    for needle, name in TECH_SIGNATURES.items():
        if needle in lower or needle in headers_blob:
            if name not in found:
                found.append(name)
    generator = meta_content(body, "generator")
    if generator:
        found.append("generator: " + generator)
    powered = response.header("x-powered-by")
    if powered:
        found.append("X-Powered-By: " + powered)
    server = response.header("server")
    if server:
        found.append("Server: " + server)
    findings: list[Finding] = [
        f("Tecnologías detectadas", str(len(found)), "good" if found else "info"),
    ]
    for name in found:
        findings.append(f("Tecnología", name, "info"))
    scripts = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', body, re.I)
    for src in dedupe(scripts)[:20]:
        findings.append(f("Script", src, "info"))
    forms = re.findall(r'<form[^>]*action=["\']([^"\']*)["\']', body, re.I)
    if forms:
        findings.append(f("Formularios", join_limited(dedupe(forms), 10), "info"))
    title = fetch_title(body)
    if title:
        findings.append(f("Título", title, "info"))
    return findings


TAKEOVER_FINGERPRINTS = {
    "github.io": "GitHub Pages",
    "herokuapp.com": "Heroku",
    "s3.amazonaws.com": "Amazon S3",
    "cloudfront.net": "CloudFront",
    "azurewebsites.net": "Azure App Service",
    "cloudapp.azure.com": "Azure",
    "trafficmanager.net": "Azure Traffic Manager",
    "blob.core.windows.net": "Azure Blob",
    "netlify.app": "Netlify",
    "vercel.app": "Vercel",
    "pages.dev": "Cloudflare Pages",
    "workers.dev": "Cloudflare Workers",
    "bitbucket.io": "Bitbucket",
    "wordpress.com": "WordPress.com",
    "tumblr.com": "Tumblr",
    "myshopify.com": "Shopify",
    "unbounce.com": "Unbounce",
    "surveygizmo.com": "SurveyGizmo",
    "readme.io": "ReadMe",
    "statuspage.io": "Statuspage",
    "freshdesk.com": "Freshdesk",
    "zendesk.com": "Zendesk",
    "helpscoutdocs.com": "Help Scout",
    "ghost.io": "Ghost",
    "fly.dev": "Fly.io",
    "onrender.com": "Render",
    "web.app": "Firebase",
    "firebaseapp.com": "Firebase",
    "appspot.com": "Google App Engine",
    "gitbook.io": "GitBook",
    "surge.sh": "Surge",
    "readthedocs.io": "Read the Docs",
}

TAKEOVER_MARKERS = (
    "no such app",
    "there isn't a github pages site here",
    "nosuchbucket",
    "the specified bucket does not exist",
    "repository not found",
    "this site is not configured",
    "project not found",
    "page not found",
    "unknown domain",
    "not found",
)


@module("subdomain_takeover")
def subdomain_takeover(ctx: Context, tool: Any) -> list[Finding]:
    domain = domain_for(ctx)
    candidates = [
        "www", "mail", "webmail", "blog", "shop", "store", "dev", "staging", "test",
        "api", "cdn", "static", "assets", "media", "app", "support", "docs", "status",
        "vpn", "ftp", "autodiscover", "portal", "admin", "secure", "my", "img", "files",
    ]
    findings: list[Finding] = []
    hits = 0

    def check(sub: str) -> list[Finding]:
        name = f"{sub}.{domain}"
        try:
            from .base import doh_values

            cnames = [v.rstrip(".") for v in doh_values(ctx, name, "CNAME")]
        except Exception:  # noqa: BLE001
            return []
        local: list[Finding] = []
        for cname in cnames:
            for suffix, service in TAKEOVER_FINGERPRINTS.items():
                if cname.endswith(suffix):
                    response = safe_get(ctx, f"https://{name}", timeout=12)
                    body = (response.text[:10000].lower() if response else "")
                    marker = next((m for m in TAKEOVER_MARKERS if m in body), "")
                    if marker:
                        local.append(
                            f("Posible takeover", f"{name} → {cname} ({service}) · marcador: {marker}",
                              "bad", url=f"https://{name}", data={"cname": cname, "service": service})
                        )
                    else:
                        local.append(
                            f("CNAME a servicio externo", f"{name} → {cname} ({service})",
                              "warn", url=f"https://{name}", data={"cname": cname, "service": service})
                        )
        return local

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        futures = {pool.submit(check, sub): sub for sub in candidates}
        for future in concurrent.futures.as_completed(futures):
            try:
                results = future.result()
            except Exception:  # noqa: BLE001
                continue
            for result in results:
                hits += 1
                findings.append(result)
    if not findings:
        findings.append(f("Subdomain takeover", f"sin CNAMEs de riesgo en {len(candidates)} subdominios comunes", "good"))
    else:
        findings.insert(0, f("Coincidencias", str(hits), "warn"))
    return findings


@module("urlscan_search")
def urlscan_search(ctx: Context, tool: Any) -> list[Finding]:
    if ctx.kind == "ip":
        query = f"ip:{ctx.target}"
    elif ctx.kind == "url":
        query = f'page.url:"{ctx.target}"'
    else:
        query = f"domain:{domain_for(ctx)}"
    try:
        response = ctx.http.get(
            "https://urlscan.io/api/v1/search/",
            params={"q": query, "size": "20"},
            timeout=25,
            retries=1,
        )
    except (NetworkError, HttpError) as exc:
        return [f("urlscan.io", str(exc), "warn")]
    if not response.ok:
        return [f("urlscan.io", f"HTTP {response.status}", "warn")]
    try:
        data = response.json()
    except ValueError:
        return [f("urlscan.io", "respuesta no JSON", "warn")]
    results = data.get("results") or []
    findings: list[Finding] = [f("Escaneos", str(data.get("total", len(results))), "info")]
    for item in results[:20]:
        if not isinstance(item, dict):
            continue
        page = item.get("page") or {}
        task = item.get("task") or {}
        url_value = str(page.get("url") or task.get("url") or "")
        title = str(page.get("title") or "")
        ip = str(page.get("ip") or "")
        server = str(page.get("server") or "")
        result_url = str(item.get("result") or "")
        findings.append(
            f("Escaneo", f"{url_value} · {title} · {ip} {server}".strip(" ·"), "info",
              url=result_url, data={"scan_id": item.get("_id")})
        )
    return findings


@module("wayback_availability")
def wayback_availability(ctx: Context, tool: Any) -> list[Finding]:
    target = ctx.target
    try:
        response = ctx.http.get(
            "https://archive.org/wayback/available",
            params={"url": target},
            timeout=25,
            retries=1,
        )
    except (NetworkError, HttpError) as exc:
        return [f("Wayback", str(exc), "warn")]
    if not response.ok:
        return [f("Wayback", f"HTTP {response.status}", "warn")]
    try:
        data = response.json()
    except ValueError:
        return [f("Wayback", "respuesta no JSON", "warn")]
    closest = ((data.get("archived_snapshots") or {}).get("closest") or {}) if isinstance(data, dict) else {}
    if closest.get("available"):
        return [
            f("Captura disponible", str(closest.get("url", "")), "good", url=str(closest.get("url", ""))),
            f("Timestamp", str(closest.get("timestamp", "")), "info"),
            f("Estado archivado", str(closest.get("status", "")), "info"),
        ]
    return [f("Wayback", "no hay capturas disponibles", "info")]


@module("wayback_cdx")
def wayback_cdx(ctx: Context, tool: Any) -> list[Finding]:
    if ctx.kind == "url":
        pattern = ctx.target
    else:
        pattern = f"{domain_for(ctx)}/*"
    try:
        response = ctx.http.get(
            "https://web.archive.org/cdx/search/cdx",
            params={
                "url": pattern,
                "output": "json",
                "limit": "200",
                "fl": "timestamp,original,statuscode,mimetype",
                "collapse": "urlkey",
            },
            timeout=45,
            retries=1,
            max_bytes=8_000_000,
        )
    except (NetworkError, HttpError) as exc:
        return [f("Wayback CDX", str(exc), "warn")]
    if not response.ok:
        return [f("Wayback CDX", f"HTTP {response.status}", "warn")]
    try:
        rows = response.json()
    except ValueError:
        return [f("Wayback CDX", "respuesta no JSON", "warn")]
    if not isinstance(rows, list) or len(rows) <= 1:
        return [f("Wayback CDX", "sin resultados", "info")]
    header = [str(x) for x in rows[0]]
    findings: list[Finding] = [f("Capturas", str(len(rows) - 1), "info")]
    seen = set()
    for row in rows[1:]:
        if not isinstance(row, list):
            continue
        record = dict(zip(header, row))
        original = str(record.get("original", ""))
        if not original or original in seen:
            continue
        seen.add(original)
        timestamp = str(record.get("timestamp", ""))
        status = str(record.get("statuscode", ""))
        mime = str(record.get("mimetype", ""))
        archive_url = f"https://web.archive.org/web/{timestamp}/{original}" if timestamp else ""
        findings.append(f("URL", f"{original} [{status} {mime}]", "info", url=archive_url, data={"timestamp": timestamp}))
    return findings


@module("urlhaus_host")
def urlhaus_host(ctx: Context, tool: Any) -> list[Finding]:
    key = ctx.key("ABUSECH_AUTH_KEY")
    host = ctx.target if ctx.kind == "ip" else domain_for(ctx)
    try:
        response = ctx.http.post(
            "https://urlhaus-api.abuse.ch/v1/host/",
            json_body={"host": host},
            headers={"Auth-Key": key},
            timeout=30,
            retries=1,
        )
    except (NetworkError, HttpError) as exc:
        return [f("URLhaus", str(exc), "warn")]
    if not response.ok:
        return [f("URLhaus", f"HTTP {response.status}: {truncate(response.text, 200)}", "warn")]
    try:
        data = response.json()
    except ValueError:
        return [f("URLhaus", "respuesta no JSON", "warn")]
    status = str(data.get("query_status", "?"))
    if status != "ok":
        return [f("URLhaus", f"estado: {status} (sin reportes para {host})", "info")]
    urls = data.get("urls") or []
    findings: list[Finding] = [f("Host reportado", host, "bad", data={"status": status})]
    for item in urls[:50]:
        if not isinstance(item, dict):
            continue
        findings.append(
            f("URL maliciosa", str(item.get("url", "")), "bad", url=str(item.get("url", "")),
              data={"threat": item.get("threat"), "tags": item.get("tags"), "date_added": item.get("date_added")})
        )
    return findings


DORK_TEMPLATES = {
    "domain": [
        'site:{t}',
        'site:{t} filetype:pdf',
        'site:{t} filetype:xlsx OR filetype:docx',
        'site:{t} inurl:admin OR inurl:login',
        'site:{t} intitle:"index of"',
        'site:{t} ext:sql OR ext:env OR ext:log OR ext:bak',
        'site:{t} intext:"password" OR intext:"api_key"',
        'site:pastebin.com "{t}"',
        'site:github.com "{t}"',
        'site:trello.com "{t}"',
        'site:docs.google.com "{t}"',
        '"{t}" -site:{t}',
        '"@{t}" email',
    ],
    "email": [
        '"{t}"',
        '"{t}" filetype:pdf',
        '"{t}" site:pastebin.com',
        '"{t}" password OR passwd OR credentials',
        '"{t}" site:github.com',
        '"{t}" -site:{d}',
    ],
    "username": [
        '"{t}"',
        '"{t}" site:github.com',
        '"{t}" site:reddit.com',
        '"{t}" site:medium.com',
        '"{t}" site:pastebin.com',
        '"{t}" email OR contact',
    ],
    "org": [
        '"{t}"',
        '"{t}" filetype:pdf',
        '"{t}" site:sec.gov',
        '"{t}" (address OR phone OR email)',
        '"{t}" lawsuit OR sanction OR investigation',
    ],
    "phone": [
        '"{t}"',
        '"{t}" whatsapp',
        '"{t}" site:facebook.com',
        '"{t}" site:linkedin.com',
        '"{t}" filetype:pdf',
        '"{t}" site:pastebin.com',
    ],
    "keyword": [
        '"{t}"',
        '"{t}" filetype:pdf',
        '"{t}" site:pastebin.com',
        '"{t}" -site:wikipedia.org',
    ],
}


@module("google_dorks")
def google_dorks(ctx: Context, tool: Any) -> list[Finding]:
    templates = DORK_TEMPLATES.get(ctx.kind, DORK_TEMPLATES["keyword"])
    domain = domain_for(ctx) if ctx.kind == "domain" else ""
    findings: list[Finding] = []
    for template in templates:
        dork = template.format(t=ctx.target, d=domain)
        google = "https://www.google.com/search?q=" + quote_plus(dork)
        ddg = "https://duckduckgo.com/?q=" + quote_plus(dork)
        findings.append(f("Dork", dork, "link", url=google, data={"duckduckgo": ddg}))
    findings.append(
        f(
            "Consejo",
            "Abrí los dorks manualmente; osintkit no automatiza scraping de Google.",
            "info",
        )
    )
    return findings
