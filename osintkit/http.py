"""Cliente HTTP sin dependencias, con caché, reintentos y límite de ritmo."""

from __future__ import annotations

import json
import random
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping

from .config import cache_dir
from .util import ensure_dir, hash_text, iso_now


class NetworkError(RuntimeError):
    """Fallo de red (DNS, timeout, TLS, conexión)."""


class HttpError(RuntimeError):
    """Respuesta HTTP no exitosa."""

    def __init__(self, status: int, url: str, body: str = "") -> None:
        super().__init__(f"HTTP {status} en {url}")
        self.status = status
        self.url = url
        self.body = body


@dataclass
class Response:
    status: int
    url: str
    headers: dict[str, str]
    text: str
    elapsed: float = 0.0
    from_cache: bool = False
    raw_length: int = 0

    def json(self) -> Any:
        try:
            return json.loads(self.text)
        except ValueError as exc:
            raise HttpError(self.status, self.url, "respuesta no es JSON") from exc

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 400

    def header(self, name: str, default: str = "") -> str:
        return self.headers.get(name.lower(), default)


class Cache:
    def __init__(self, directory: Path | None = None, ttl: int = 3600) -> None:
        self.directory = ensure_dir(directory or (cache_dir() / "http"))
        self.ttl = max(0, int(ttl))
        self._lock = threading.Lock()

    def _path(self, key: str) -> Path:
        return self.directory / (hash_text(key, "sha256") + ".json")

    def get(self, key: str) -> dict[str, Any] | None:
        if self.ttl <= 0:
            return None
        path = self._path(key)
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        if not isinstance(data, dict):
            return None
        if time.time() - float(data.get("ts", 0)) > self.ttl:
            try:
                path.unlink()
            except OSError:
                pass
            return None
        return data

    def set(self, key: str, value: dict[str, Any]) -> None:
        if self.ttl <= 0:
            return
        value = dict(value)
        value["ts"] = time.time()
        try:
            text = json.dumps(value, ensure_ascii=False)
        except (TypeError, ValueError):
            return
        path = self._path(key)
        with self._lock:
            try:
                tmp = path.with_suffix(".tmp")
                tmp.write_text(text, encoding="utf-8")
                tmp.replace(path)
            except OSError:
                pass

    def clear(self) -> int:
        count = 0
        for path in self.directory.glob("*.json"):
            try:
                path.unlink()
                count += 1
            except OSError:
                continue
        return count


class RateLimiter:
    """Separación mínima entre pedidos al mismo host."""

    def __init__(self, interval: float = 0.12) -> None:
        self.interval = max(0.0, float(interval))
        self._next: dict[str, float] = {}
        self._lock = threading.Lock()

    def wait(self, host: str) -> None:
        if self.interval <= 0:
            return
        with self._lock:
            now = time.monotonic()
            target = self._next.get(host, now)
            if target > now:
                delay = target - now
            else:
                delay = 0.0
            self._next[host] = max(now, target) + self.interval + random.uniform(0, 0.03)
        if delay:
            time.sleep(delay)


@dataclass
class HttpClient:
    timeout: float = 15.0
    user_agent: str = "osintkit/1.0 (+https://github.com/osintkit)"
    cache: Cache | None = None
    rate_limiter: RateLimiter = field(default_factory=RateLimiter)
    max_bytes: int = 2_500_000
    retries: int = 2
    verbose: bool = False

    def __post_init__(self) -> None:
        self._lock = threading.Lock()
        self.stats: dict[str, int] = {"requests": 0, "cache_hits": 0, "errors": 0}

    # ------------------------------------------------------------------
    def _headers(self, extra: Mapping[str, str] | None = None) -> dict[str, str]:
        headers = {
            "User-Agent": self.user_agent,
            "Accept": "application/json, text/plain, text/html, */*",
            "Accept-Language": "es,en;q=0.8",
            "Accept-Encoding": "identity",
            "Connection": "close",
        }
        if extra:
            headers.update({str(k): str(v) for k, v in extra.items()})
        return headers

    def request(
        self,
        method: str,
        url: str,
        *,
        params: Mapping[str, Any] | None = None,
        data: bytes | None = None,
        json_body: Any = None,
        headers: Mapping[str, str] | None = None,
        timeout: float | None = None,
        retries: int | None = None,
        allow_cache: bool = True,
        max_bytes: int | None = None,
    ) -> Response:
        method = method.upper()
        if params:
            query = urllib.parse.urlencode(params, doseq=True)
            url = url + ("&" if "?" in url else "?") + query
        if json_body is not None:
            data = json.dumps(json_body).encode("utf-8")
            headers = dict(headers or {})
            headers.setdefault("Content-Type", "application/json")
        if data is not None and method == "GET":
            method = "POST"

        host = urllib.parse.urlsplit(url).netloc.lower()
        cache_key = "|".join(
            [method, url, str((headers or {}).get("Accept", "")), hash_text(str(data or ""))]
        )
        if method == "GET" and allow_cache and self.cache:
            cached = self.cache.get(cache_key)
            if cached:
                with self._lock:
                    self.stats["cache_hits"] += 1
                return Response(
                    status=int(cached.get("status", 200)),
                    url=str(cached.get("url", url)),
                    headers={str(k): str(v) for k, v in (cached.get("headers") or {}).items()},
                    text=str(cached.get("text", "")),
                    from_cache=True,
                    raw_length=int(cached.get("raw_length", 0)),
                )

        attempts = self.retries if retries is None else max(0, retries)
        last_error: Exception | None = None
        for attempt in range(attempts + 1):
            if attempt:
                time.sleep(0.6 * (2 ** (attempt - 1)) + random.random() * 0.3)
            self.rate_limiter.wait(host)
            req = urllib.request.Request(url, data=data, method=method, headers=self._headers(headers))
            started = time.monotonic()
            try:
                with urllib.request.urlopen(req, timeout=timeout or self.timeout) as resp:
                    body = resp.read(max_bytes or self.max_bytes)
                    elapsed = time.monotonic() - started
                    text = self._decode(body, resp.headers.get("Content-Type", ""))
                    response = Response(
                        status=int(resp.status),
                        url=resp.geturl(),
                        headers={k.lower(): v for k, v in resp.headers.items()},
                        text=text,
                        elapsed=elapsed,
                        raw_length=len(body),
                    )
                    with self._lock:
                        self.stats["requests"] += 1
                    if method == "GET" and allow_cache and self.cache and response.ok:
                        self.cache.set(
                            cache_key,
                            {
                                "status": response.status,
                                "url": response.url,
                                "headers": response.headers,
                                "text": response.text,
                                "raw_length": response.raw_length,
                            },
                        )
                    return response
            except urllib.error.HTTPError as exc:
                body = b""
                try:
                    body = exc.read(200_000)
                except Exception:
                    pass
                text = self._decode(body, exc.headers.get("Content-Type", "") if exc.headers else "")
                response = Response(
                    status=int(exc.code),
                    url=url,
                    headers={k.lower(): v for k, v in (exc.headers.items() if exc.headers else [])},
                    text=text,
                    elapsed=time.monotonic() - started,
                    raw_length=len(body),
                )
                with self._lock:
                    self.stats["requests"] += 1
                # 429 y 5xx se reintentan; 4xx restantes se devuelven tal cual.
                if response.status == 429 or response.status >= 500:
                    last_error = HttpError(response.status, url, text[:200])
                    if attempt < attempts:
                        retry_after = response.header("retry-after")
                        if retry_after.isdigit():
                            time.sleep(min(20, int(retry_after)))
                        continue
                return response
            except (urllib.error.URLError, TimeoutError, OSError) as exc:
                last_error = exc
                with self._lock:
                    self.stats["errors"] += 1
                if attempt >= attempts:
                    break
                continue
        raise NetworkError(f"No se pudo conectar con {url}: {last_error}")

    # ------------------------------------------------------------------
    @staticmethod
    def _decode(body: bytes, content_type: str) -> str:
        charset = "utf-8"
        for part in content_type.split(";"):
            part = part.strip()
            if part.lower().startswith("charset="):
                charset = part.split("=", 1)[1].strip("\"' ") or "utf-8"
                break
        try:
            return body.decode(charset, errors="replace")
        except (LookupError, UnicodeError):
            return body.decode("utf-8", errors="replace")

    def get(self, url: str, **kwargs: Any) -> Response:
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs: Any) -> Response:
        return self.request("POST", url, **kwargs)

    def post_form(self, url: str, form: Mapping[str, Any], **kwargs: Any) -> Response:
        data = urllib.parse.urlencode(form).encode("utf-8")
        headers = dict(kwargs.pop("headers", {}) or {})
        headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
        return self.request("POST", url, data=data, headers=headers, **kwargs)

    def get_json(self, url: str, **kwargs: Any) -> Any:
        response = self.get(url, **kwargs)
        if not response.ok:
            raise HttpError(response.status, response.url, response.text[:300])
        return response.json()

    def post_json(self, url: str, body: Any, **kwargs: Any) -> Any:
        response = self.post(url, json_body=body, **kwargs)
        if not response.ok:
            raise HttpError(response.status, response.url, response.text[:300])
        return response.json()


def new_http(cfg: Any, no_cache: bool = False) -> HttpClient:
    ttl = 0 if no_cache else cfg.int("cache_ttl", 3600)
    cache = Cache(ttl=ttl)
    return HttpClient(
        timeout=cfg.float("timeout", 15.0),
        user_agent=str(cfg.get("user_agent", "osintkit/1.0")),
        cache=cache,
        rate_limiter=RateLimiter(cfg.float("rate_interval", 0.12)),
    )


def cache_info() -> dict[str, Any]:
    directory = cache_dir() / "http"
    count = 0
    size = 0
    if directory.exists():
        for path in directory.glob("*.json"):
            count += 1
            try:
                size += path.stat().st_size
            except OSError:
                pass
    return {"directory": str(directory), "files": count, "bytes": size, "checked_at": iso_now()}
