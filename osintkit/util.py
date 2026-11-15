"""Utilidades pequeñas y sin dependencias externas para osintkit."""

from __future__ import annotations

import hashlib
import html
import ipaddress
import json
import os
import re
import shutil
import tempfile
import unicodedata
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Iterator

from .devices import looks_like_device
from .plates import compact_plate, split_plate_country

# ---------------------------------------------------------------------------
# Tiempo / texto
# ---------------------------------------------------------------------------

def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def iso_now() -> str:
    return utcnow().replace(microsecond=0).isoformat()


def stamp() -> str:
    return utcnow().strftime("%Y%m%d-%H%M%S")


def format_duration(seconds: float) -> str:
    if seconds < 1:
        return f"{seconds * 1000:.0f} ms"
    if seconds < 60:
        return f"{seconds:.1f} s"
    minutes, rest = divmod(seconds, 60)
    return f"{int(minutes)}m {rest:.0f}s"


def strip_ansi(text: str) -> str:
    return re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", text)


def collapse_ws(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def truncate(text: str, length: int = 160, ellipsis: str = "…") -> str:
    text = collapse_ws(text)
    if len(text) <= length:
        return text
    return text[: max(0, length - 1)].rstrip() + ellipsis


def slugify(text: str, max_len: int = 80) -> str:
    text = unicodedata.normalize("NFKD", text)
    text = "".join(c for c in text if not unicodedata.combining(c))
    text = re.sub(r"[^A-Za-z0-9._-]+", "-", text).strip("-._")
    return (text or "objetivo")[:max_len]


def safe_filename(text: str) -> str:
    return slugify(text, 120)


def mask_secret(value: str, show: int = 4) -> str:
    if not value:
        return "(vacío)"
    if len(value) <= show * 2:
        return value[:1] + "…" + value[-1:]
    return value[:show] + "…" + value[-show:]


def human_bytes(num: int | float) -> str:
    num = float(num)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(num) < 1024 or unit == "TB":
            return f"{num:.0f} {unit}" if unit == "B" else f"{num:.1f} {unit}"
        num /= 1024
    return f"{num:.1f} TB"


def html_escape(value: Any) -> str:
    return html.escape(str(value), quote=True)


def json_dumps(value: Any, **kwargs: Any) -> str:
    kwargs.setdefault("ensure_ascii", False)
    kwargs.setdefault("indent", 2)
    return json.dumps(value, **kwargs)


# ---------------------------------------------------------------------------
# Archivos
# ---------------------------------------------------------------------------

def ensure_dir(path: str | os.PathLike[str]) -> Path:
    p = Path(path).expanduser()
    p.mkdir(parents=True, exist_ok=True)
    return p


def atomic_write(path: str | os.PathLike[str], text: str, encoding: str = "utf-8") -> Path:
    p = Path(path).expanduser()
    ensure_dir(p.parent)
    fd, tmp = tempfile.mkstemp(prefix=".osintkit-", dir=str(p.parent))
    try:
        with os.fdopen(fd, "w", encoding=encoding) as fh:
            fh.write(text)
        os.replace(tmp, p)
    finally:
        if os.path.exists(tmp):
            try:
                os.unlink(tmp)
            except OSError:
                pass
    return p


def which(name: str) -> str | None:
    return shutil.which(name)


# ---------------------------------------------------------------------------
# Detección de tipo de objetivo
# ---------------------------------------------------------------------------

_DOMAIN_LABEL = r"(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
_DOMAIN_RE = re.compile(rf"^(?:{_DOMAIN_LABEL}\.)+[A-Za-z]{{2,63}}\.?$")
_IPV4_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
_EMAIL_RE = re.compile(
    r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$"
)
_PHONE_RE = re.compile(r"^\+?[0-9][0-9 ()./-]{5,20}$")
_BTC_RE = re.compile(r"^(?:bc1[a-zA-HJ-NP-Z0-9]{25,62}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})$")
_ETH_RE = re.compile(r"^0x[a-fA-F0-9]{40}$")
_XMR_RE = re.compile(r"^4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}$")
_LTC_RE = re.compile(r"^(?:[LM3][a-km-zA-HJ-NP-Z1-9]{26,33}|ltc1[a-z0-9]{25,62})$")
_TRX_RE = re.compile(r"^T[a-zA-Z0-9]{33}$")
_HASH_RE = re.compile(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$|^[a-fA-F0-9]{128}$")

CRYPTO_NETWORKS = {
    "btc": _BTC_RE,
    "eth": _ETH_RE,
    "xmr": _XMR_RE,
    "ltc": _LTC_RE,
    "trx": _TRX_RE,
}


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def is_ipv6(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).version == 6
    except ValueError:
        return False


def is_domain(value: str) -> bool:
    value = value.rstrip(".")
    if not _DOMAIN_RE.match(value):
        return False
    # Un IPv4 también matchea el regex de dominio: descartarlo.
    if _IPV4_RE.match(value):
        return False
    return True


def is_email(value: str) -> bool:
    return bool(_EMAIL_RE.match(value))


def is_phone(value: str) -> bool:
    if not _PHONE_RE.match(value):
        return False
    digits = re.sub(r"\D", "", value)
    return 7 <= len(digits) <= 15


def is_hash(value: str) -> bool:
    return bool(_HASH_RE.match(value))


def is_url(value: str) -> bool:
    return value.lower().startswith(("http://", "https://")) and "://" in value


def crypto_network(value: str) -> str | None:
    for network, regex in CRYPTO_NETWORKS.items():
        if regex.match(value):
            return network
    return None


def normalize_domain(value: str) -> str:
    value = value.strip().lower()
    value = re.sub(r"^[a-z][a-z0-9+.-]*://", "", value)
    value = value.split("/", 1)[0].split("@")[-1]
    value = value.split(":", 1)[0].rstrip(".")
    try:
        value = value.encode("idna").decode("ascii")
    except UnicodeError:
        pass
    return value


def extract_host(url: str) -> str:
    url = url.strip()
    url = re.sub(r"^[a-z][a-z0-9+.-]*://", "", url, flags=re.I)
    host = url.split("/", 1)[0].split("@")[-1]
    if host.startswith("["):
        host = host[1:].split("]", 1)[0]
    else:
        host = host.split(":", 1)[0]
    return host.lower().rstrip(".")


def normalize_target(value: str) -> str:
    value = value.strip()
    if is_url(value):
        return value
    if is_email(value) or is_ip(value) or crypto_network(value) or is_hash(value):
        return value
    if is_phone(value):
        return value
    if is_domain(value):
        return normalize_domain(value)
    return value


def detect_kind(value: str) -> str:
    value = value.strip()
    if not value:
        return "keyword"
    if Path(value).expanduser().is_file():
        return "file"
    if is_url(value):
        return "url"
    if is_email(value):
        return "email"
    if is_ip(value):
        return "ip"
    network = crypto_network(value)
    if network:
        return "crypto"
    if is_hash(value):
        return "hash"
    if is_phone(value) and not _IPV4_RE.match(value):
        return "phone"
    if is_domain(value):
        return "domain"
    plate, country = split_plate_country(value)
    if country and len(compact_plate(plate)) >= 4:
        return "plate"
    if looks_like_device(value):
        return "device"
    if " " in value:
        return "keyword"
    return "username"


def reverse_ip(value: str) -> str | None:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return None
    if ip.version == 4:
        return ".".join(reversed(str(ip).split(".")))
    return ".".join(reversed(ip.exploded.replace(":", "")))


def phone_digits(value: str) -> str:
    return re.sub(r"\D", "", value)


# ---------------------------------------------------------------------------
# Hashing / deduplicación
# ---------------------------------------------------------------------------

def hash_text(value: str, algorithm: str = "sha256") -> str:
    return hashlib.new(algorithm, value.encode("utf-8", "replace")).hexdigest()


def file_hashes(path: str | os.PathLike[str]) -> dict[str, str]:
    algorithms = ("md5", "sha1", "sha256", "sha512")
    hashes = {name: hashlib.new(name) for name in algorithms}
    size = 0
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            size += len(chunk)
            for h in hashes.values():
                h.update(chunk)
    result = {name: h.hexdigest() for name, h in hashes.items()}
    result["size"] = str(size)
    return result


def dedupe(values: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        key = value.strip()
        if key and key not in seen:
            seen.add(key)
            out.append(key)
    return out


def chunked(values: list[Any], size: int) -> Iterator[list[Any]]:
    for i in range(0, len(values), size):
        yield values[i : i + size]


# ---------------------------------------------------------------------------
# Parseo de fechas / utilidades de red
# ---------------------------------------------------------------------------

def parse_datetime(value: str | None) -> datetime | None:
    if not value:
        return None
    text = value.strip().replace("Z", "+00:00")
    # whois: 2024-01-02T03:04:05-07:00 o 2024-01-02 03:04:05
    for fmt in (None, "%Y-%m-%d %H:%M:%S", "%Y-%m-%d", "%d-%b-%Y", "%Y.%m.%d"):
        try:
            if fmt is None:
                return datetime.fromisoformat(text)
            return datetime.strptime(text, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def days_until(value: str | datetime | None) -> int | None:
    dt = value if isinstance(value, datetime) else parse_datetime(value)
    if not dt:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return (dt - utcnow()).days


def valid_port(value: Any) -> int | None:
    try:
        port = int(value)
    except (TypeError, ValueError):
        return None
    return port if 0 < port < 65536 else None


def unique_sorted(values: Iterable[str]) -> list[str]:
    return sorted(set(v for v in values if v))
