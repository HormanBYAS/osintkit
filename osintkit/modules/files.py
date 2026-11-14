"""Módulos de archivos: hashes, metadatos, PDF y cadenas."""

from __future__ import annotations

import os
import re
import struct
from pathlib import Path
from typing import Any

from ..core import Context, Finding, module
from ..util import file_hashes, human_bytes, is_email, is_ip, truncate
from .base import f, join_limited

EXIF_TAGS = {
    0x0100: "Ancho",
    0x0101: "Alto",
    0x010E: "Descripción",
    0x010F: "Fabricante",
    0x0110: "Modelo",
    0x0112: "Orientación",
    0x011A: "Resolución X",
    0x011B: "Resolución Y",
    0x0128: "Unidad de resolución",
    0x0131: "Software",
    0x0132: "Fecha y hora",
    0x013B: "Artista",
    0x8298: "Copyright",
    0x9003: "Fecha original",
    0x9004: "Fecha de digitalización",
    0x8825: "GPS",
    0xA002: "Ancho (píxeles)",
    0xA003: "Alto (píxeles)",
    0x9286: "Comentario de usuario",
}

GPS_TAGS = {
    0: "Versión GPS",
    1: "Latitud (ref)",
    2: "Latitud",
    3: "Longitud (ref)",
    4: "Longitud",
    5: "Altitud (ref)",
    6: "Altitud",
    7: "Hora GPS",
    12: "Velocidad",
    13: "Dirección",
    29: "Fecha GPS",
}

SUSPICIOUS_STRINGS = {
    "clave privada": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----"),
    "token AWS": re.compile(r"AKIA[0-9A-Z]{16}"),
    "token GitHub": re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}"),
    "token Slack": re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"),
    "clave Google": re.compile(r"AIza[0-9A-Za-z_-]{35}"),
    "clave Stripe": re.compile(r"sk_live_[0-9A-Za-z]{20,}"),
    "JWT": re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
    "contraseña": re.compile(r"(?i)\b(?:password|passwd|pwd|secret|api[_-]?key)\s*[:=]\s*\S{4,}"),
    "URL con credenciales": re.compile(r"[a-z][a-z0-9+.-]*://[^/\s:@]+:[^/\s@]+@[^/\s]+", re.I),
}


def _path(ctx: Context) -> Path | None:
    path = Path(ctx.target).expanduser()
    if not path.exists():
        return None
    if not path.is_file():
        return None
    return path


def _missing(ctx: Context) -> list[Finding]:
    return [f("Archivo", f"no existe o no es un archivo: {ctx.target}", "warn")]


def _magic(path: Path) -> str:
    try:
        head = path.read_bytes()[:64]
    except OSError:
        return "desconocido"
    signatures = [
        (b"\x89PNG\r\n\x1a\n", "PNG"),
        (b"\xff\xd8\xff", "JPEG"),
        (b"GIF87a", "GIF"),
        (b"GIF89a", "GIF"),
        (b"%PDF-", "PDF"),
        (b"PK\x03\x04", "ZIP / Office / JAR"),
        (b"7z\xbc\xaf\x27\x1c", "7-Zip"),
        (b"Rar!\x1a\x07", "RAR"),
        (b"\x1f\x8b", "GZIP"),
        (b"BZh", "BZIP2"),
        (b"\x7fELF", "ELF"),
        (b"MZ", "PE / DOS"),
        (b"SQLite format 3\x00", "SQLite"),
        (b"\x00\x00\x00\x18ftyp", "MP4 / ISO BMFF"),
        (b"ID3", "MP3"),
        (b"OggS", "OGG"),
        (b"RIFF", "RIFF (WAV/AVI/WebP)"),
    ]
    for signature, label in signatures:
        if head.startswith(signature):
            return label
    if head[:4] == b"\x00\x00\x01\x00":
        return "ICO"
    if head[:4] == b"\x00\x00\x02\x00":
        return "CUR"
    try:
        text = head.decode("utf-8")
        if text and all((ch.isprintable() or ch in "\r\n\t") for ch in text):
            return "texto"
    except UnicodeDecodeError:
        pass
    return "desconocido"


def _human_ts(timestamp: float) -> str:
    from datetime import datetime, timezone

    return datetime.fromtimestamp(timestamp, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


# ---------------------------------------------------------------------------
# Hashes
# ---------------------------------------------------------------------------

@module("file_hash")
def file_hash(ctx: Context, tool: Any) -> list[Finding]:
    path = _path(ctx)
    if not path:
        return _missing(ctx)
    try:
        hashes = file_hashes(path)
        stat = path.stat()
    except OSError as exc:
        return [f("Archivo", str(exc), "warn")]
    return [
        f("Archivo", path.name, "info", data={"ruta": str(path)}),
        f("Ruta", str(path.resolve()), "info"),
        f("Tamaño", human_bytes(stat.st_size), "info", data={"bytes": stat.st_size}),
        f("Tipo (firma)", _magic(path), "info"),
        f("SHA-256", hashes["sha256"], "good"),
        f("SHA-1", hashes["sha1"], "info"),
        f("MD5", hashes["md5"], "info"),
        f("Modificado", _human_ts(stat.st_mtime), "info"),
        f(
            "Búsqueda VirusTotal",
            f"https://www.virustotal.com/gui/file/{hashes['sha256']}",
            "link",
            url=f"https://www.virustotal.com/gui/file/{hashes['sha256']}",
        ),
    ]


# ---------------------------------------------------------------------------
# EXIF / metadatos de imagen
# ---------------------------------------------------------------------------

def _read_exif(path: Path) -> dict[str, Any]:
    """Lector EXIF mínimo para JPEG/TIFF, sin dependencias externas."""
    data = path.read_bytes()
    offset = 0
    if data[:2] == b"\xff\xd8":
        pos = 2
        while pos + 4 <= len(data):
            if data[pos] != 0xFF:
                pos += 1
                continue
            marker = data[pos + 1]
            if marker in (0xD8, 0xD9):
                pos += 2
                continue
            if pos + 4 > len(data):
                break
            length = struct.unpack(">H", data[pos + 2:pos + 4])[0]
            if marker == 0xE1 and data[pos + 4:pos + 10] == b"Exif\x00\x00":
                offset = pos + 10
                break
            pos += 2 + length
        if not offset:
            return {}
    elif data[:4] in (b"II*\x00", b"MM\x00*"):
        offset = 0
    else:
        return {}

    endian = "<" if data[offset:offset + 2] == b"II" else ">"
    if data[offset + 2:offset + 4] != b"\x2a\x00"[::1] and data[offset + 2:offset + 4] != b"\x00\x2a":
        return {}
    try:
        ifd_offset = struct.unpack(endian + "I", data[offset + 4:offset + 8])[0]
    except struct.error:
        return {}

    def read_ifd(base: int, tags: dict[int, str], result: dict[str, Any]) -> int | None:
        pointer = None
        try:
            count = struct.unpack(endian + "H", data[base:base + 2])[0]
        except struct.error:
            return None
        for index in range(min(count, 200)):
            entry = base + 2 + index * 12
            if entry + 12 > len(data):
                break
            tag, fmt = struct.unpack(endian + "HH", data[entry:entry + 4])
            number = struct.unpack(endian + "I", data[entry + 4:entry + 8])[0]
            raw = data[entry + 8:entry + 12]
            name = tags.get(tag)
            if tag == 0x8825:
                try:
                    pointer = struct.unpack(endian + "I", raw)[0]
                except struct.error:
                    pointer = None
            if not name:
                continue
            value = _exif_value(data, raw, fmt, number, endian)
            if value not in (None, ""):
                result[name] = value
        return pointer

    result: dict[str, Any] = {}
    gps_pointer = read_ifd(offset + ifd_offset, EXIF_TAGS, result)
    if gps_pointer:
        gps: dict[str, Any] = {}
        read_ifd(offset + gps_pointer, GPS_TAGS, gps)
        if gps:
            result["GPS"] = gps
    return result


def _exif_value(data: bytes, raw: bytes, fmt: int, number: int, endian: str) -> Any:
    sizes = {1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 7: 1, 9: 4, 10: 8}
    size = sizes.get(fmt, 1) * max(1, number)
    payload = raw
    if size > 4:
        try:
            pointer = struct.unpack(endian + "I", raw)[0]
        except struct.error:
            return None
        payload = data[pointer:pointer + size]
    if fmt == 2:  # ASCII
        return payload.split(b"\x00", 1)[0].decode("utf-8", errors="replace").strip()
    if fmt in (3, 4):
        width = 2 if fmt == 3 else 4
        code = endian + ("H" if fmt == 3 else "I") * max(1, number)
        try:
            values = struct.unpack(code, payload[:width * number])
        except struct.error:
            return None
        return values[0] if len(values) == 1 else list(values)
    if fmt in (5, 10):
        width = 4 if fmt == 5 else 8
        code = endian + ("II" if fmt == 5 else "ii") * max(1, number)
        try:
            values = struct.unpack(code, payload[:width * number])
        except struct.error:
            return None
        pairs = [
            (values[i], values[i + 1]) for i in range(0, len(values) - 1, 2)
        ]
        return [a / b if b else a for a, b in pairs]
    if fmt == 7:
        return truncate(payload, 120)
    return None


def _png_text(path: Path) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    try:
        data = path.read_bytes()
    except OSError:
        return out
    pos = 8
    while pos + 8 <= len(data):
        length = struct.unpack(">I", data[pos:pos + 4])[0]
        chunk_type = data[pos + 4:pos + 8]
        payload = data[pos + 8:pos + 8 + length]
        if chunk_type == b"tEXt":
            key, _, value = payload.partition(b"\x00")
            out.append((key.decode("latin-1", "replace"), value.decode("latin-1", "replace")))
        elif chunk_type == b"iTXt":
            key, _, rest = payload.partition(b"\x00")
            out.append((key.decode("latin-1", "replace"), truncate(rest, 200)))
        elif chunk_type in (b"IEND", b"IDAT"):
            if chunk_type == b"IEND":
                break
        pos += 12 + length
    return out


@module("exif_metadata")
def exif_metadata(ctx: Context, tool: Any) -> list[Finding]:
    path = _path(ctx)
    if not path:
        return _missing(ctx)
    try:
        stat = path.stat()
    except OSError as exc:
        return [f("Archivo", str(exc), "warn")]

    findings: list[Finding] = [
        f("Archivo", path.name, "info"),
        f("Tipo (firma)", _magic(path), "info"),
        f("Tamaño", human_bytes(stat.st_size), "info"),
        f("Modificado", _human_ts(stat.st_mtime), "info"),
    ]
    metadata = _read_exif(path)
    if metadata:
        for key, value in metadata.items():
            if key == "GPS" and isinstance(value, dict):
                findings.append(f("GPS", str(value), "warn", data=value))
            else:
                level = "warn" if key in ("Fabricante", "Modelo", "Software", "Artista", "Copyright", "Comentario de usuario") else "info"
                findings.append(f(key, str(value), level))
    else:
        findings.append(f("EXIF", "sin bloque EXIF detectable", "info"))

    for key, value in _png_text(path):
        findings.append(f(f"PNG · {key}", truncate(value, 300), "info"))
    if not metadata:
        findings.append(
            f(
                "Pista",
                "si `exiftool` está instalado puedes ampliar metadatos con la herramienta externa homónima",
                "info",
            )
        )
    return findings


# ---------------------------------------------------------------------------
# PDF
# ---------------------------------------------------------------------------

def _pdf_text(data: bytes, key: str) -> str:
    match = re.search(rb"/" + key.encode() + rb"\s*\((.*?)\)", data, re.S)
    if not match:
        match = re.search(rb"/" + key.encode() + rb"\s*<([0-9A-Fa-f\s]+)>", data, re.S)
        if match:
            try:
                raw = bytes.fromhex(re.sub(rb"\s+", b"", match.group(1)).decode())
            except ValueError:
                return ""
        else:
            return ""
    else:
        raw = match.group(1)
    if raw.startswith(b"\xfe\xff"):
        try:
            return raw[2:].decode("utf-16-be", errors="replace").strip()
        except UnicodeDecodeError:
            pass
    text = raw.decode("latin-1", errors="replace")
    text = text.replace("\\(", "(").replace("\\)", ")").replace("\\\\", "\\")
    return text.strip()


@module("pdf_info")
def pdf_info(ctx: Context, tool: Any) -> list[Finding]:
    path = _path(ctx)
    if not path:
        return _missing(ctx)
    if _magic(path) != "PDF":
        return [f("PDF", "el archivo no parece un PDF (falta la firma %PDF)", "warn")]
    try:
        data = path.read_bytes()
    except OSError as exc:
        return [f("PDF", str(exc), "warn")]

    findings: list[Finding] = [
        f("Archivo", path.name, "info"),
        f("Tamaño", human_bytes(len(data)), "info"),
    ]
    version = re.match(rb"%PDF-(\d\.\d)", data[:16])
    if version:
        findings.append(f("Versión", version.group(1).decode(), "info"))
    for key, label in (
        ("Title", "Título"),
        ("Author", "Autor"),
        ("Subject", "Asunto"),
        ("Keywords", "Palabras clave"),
        ("Creator", "Creador"),
        ("Producer", "Productor"),
        ("CreationDate", "Creado"),
        ("ModDate", "Modificado"),
    ):
        value = _pdf_text(data, key)
        if value:
            findings.append(f(label, truncate(value, 300), "info"))

    pages = len(re.findall(rb"/Type\s*/Page(?!s)", data))
    if pages:
        findings.append(f("Páginas", str(pages), "info"))
    encrypted = b"/Encrypt" in data
    findings.append(f("Cifrado", "sí" if encrypted else "no", "warn" if encrypted else "good"))
    if b"/JavaScript" in data or b"/JS" in data:
        findings.append(f("JavaScript embebido", "sí", "bad"))
    if b"/Launch" in data:
        findings.append(f("Acción /Launch", "sí (puede ejecutar programas)", "bad"))
    if b"/OpenAction" in data:
        findings.append(f("Acción al abrir", "sí", "warn"))
    if b"/EmbeddedFile" in data:
        findings.append(f("Archivos embebidos", "sí", "warn"))
    uris = dedupe_uris(data)
    if uris:
        findings.append(f("URI", f"{len(uris)} enlaces detectados", "info"))
        for uri in uris[:15]:
            findings.append(f("Enlace", uri, "link", url=uri))
    return findings


def dedupe_uris(data: bytes) -> list[str]:
    found = re.findall(rb"/(?:URI|F)\s*\(([^)]{3,500})\)", data)
    values: list[str] = []
    for raw in found:
        try:
            value = raw.decode("latin-1", errors="replace").strip()
        except UnicodeDecodeError:
            continue
        if value.startswith(("http://", "https://", "mailto:", "file:")):
            if value not in values:
                values.append(value)
    return values


# ---------------------------------------------------------------------------
# Strings y secretos
# ---------------------------------------------------------------------------

@module("strings_extract")
def strings_extract(ctx: Context, tool: Any) -> list[Finding]:
    path = _path(ctx)
    if not path:
        return _missing(ctx)
    try:
        data = path.read_bytes()
    except OSError as exc:
        return [f("Archivo", str(exc), "warn")]

    text_runs = re.findall(rb"[\x20-\x7e]{4,}", data)
    strings = [run.decode("ascii", errors="replace") for run in text_runs]
    joined = "\n".join(strings)
    findings: list[Finding] = [
        f("Archivo", path.name, "info"),
        f("Tamaño", human_bytes(len(data)), "info"),
        f("Cadenas ASCII", str(len(strings)), "info"),
    ]

    urls = []
    emails = []
    ips = []
    for value in re.findall(r"https?://[^\s\"'<>]{4,300}", joined):
        if value not in urls:
            urls.append(value)
    for value in re.findall(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", joined):
        if value not in emails and is_email(value):
            emails.append(value)
    for value in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", joined):
        if value not in ips and is_ip(value):
            ips.append(value)

    if urls:
        findings.append(f("URLs", f"{len(urls)} encontradas", "info"))
        for value in urls[:15]:
            findings.append(f("URL", truncate(value, 240), "link", url=value))
    if emails:
        findings.append(f("Emails", join_limited(emails, 15), "warn"))
    if ips:
        findings.append(f("IPs", join_limited(ips, 20), "info"))

    hits: dict[str, list[str]] = {}
    for label, pattern in SUSPICIOUS_STRINGS.items():
        for match in pattern.finditer(joined):
            value = match.group(0)
            bucket = hits.setdefault(label, [])
            if value not in bucket and len(bucket) < 10:
                bucket.append(value)
    for label, values in hits.items():
        level = "bad" if label in ("clave privada", "token AWS", "token GitHub", "clave Stripe") else "warn"
        findings.append(f(f"Posible secreto · {label}", join_limited(values, 5), level, data={"count": len(values)}))

    interesting = [
        s for s in strings
        if re.search(r"(?i)(password|passwd|secret|token|apikey|api_key|BEGIN .*KEY|ssh-rsa|ssh-ed25519)", s)
    ]
    for value in dedupe(interesting)[:20]:
        findings.append(f("Cadena sensible", truncate(value, 240), "warn"))

    if len(findings) <= 3:
        findings.append(f("Cadenas", "no se detectaron URLs, emails, IPs ni secretos evidentes", "good"))
    return findings


# Reexport local para evitar import extra en el encabezado.
def dedupe(values: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        out.append(value)
    return out
