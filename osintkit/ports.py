"""Nombres de puertos y etiquetado de servicios.

Centraliza la traducción de números de puerto a nombres legibles para que los
módulos internos (Shodan, Censys, etc.) y las herramientas externas (nmap,
naabu, masscan) muestren siempre algo como ``22: SSH``.
"""

from __future__ import annotations

import re
from typing import Any, Iterable


# Puertos TCP/UDP habituales. No pretende ser exhaustivo: la idea es que los
# servicios más frecuentes se entiendan de un vistazo en la terminal.
PORT_SERVICES: dict[int, str] = {
    20: "FTP-data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP",
    68: "DHCP",
    69: "TFTP",
    80: "HTTP",
    88: "Kerberos",
    110: "POP3",
    111: "rpcbind",
    119: "NNTP",
    123: "NTP",
    135: "MS RPC",
    137: "NetBIOS-NS",
    138: "NetBIOS-DGM",
    139: "NetBIOS-SSN",
    143: "IMAP",
    161: "SNMP",
    162: "SNMP-trap",
    179: "BGP",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    500: "IKE",
    514: "Syslog",
    515: "LPD",
    587: "SMTP-submission",
    631: "IPP",
    636: "LDAPS",
    853: "DNS-over-TLS",
    873: "rsync",
    993: "IMAPS",
    995: "POP3S",
    1080: "SOCKS",
    1194: "OpenVPN",
    1433: "MSSQL",
    1521: "Oracle",
    1723: "PPTP",
    2049: "NFS",
    2052: "HTTP-alt",
    2053: "HTTPS-alt",
    2080: "HTTP-alt",
    2082: "cPanel",
    2083: "cPanel SSL",
    2086: "WHM",
    2087: "WHM SSL",
    2095: "Webmail",
    2096: "Webmail SSL",
    2375: "Docker API",
    2376: "Docker TLS",
    3000: "Grafana/Node",
    3128: "Squid",
    3260: "iSCSI",
    3306: "MySQL",
    3389: "RDP",
    4444: "Metasploit",
    5000: "HTTP-alt",
    5432: "PostgreSQL",
    5601: "Kibana",
    5672: "AMQP",
    5900: "VNC",
    5984: "CouchDB",
    6379: "Redis",
    6443: "Kubernetes API",
    8000: "HTTP-alt",
    8008: "HTTP-alt",
    8080: "HTTP-alt",
    8081: "HTTP-alt",
    8443: "HTTPS-alt",
    8880: "HTTP-alt",
    8888: "HTTP-alt",
    9000: "HTTP-alt",
    9090: "Prometheus",
    9200: "Elasticsearch",
    9300: "Elasticsearch",
    10000: "Webmin",
    11211: "Memcached",
    27017: "MongoDB",
    50000: "SAP",
}

# Alias que devuelven algunas APIs o nmap. Se normalizan a mayúsculas cuando
# coincide con un nombre conocido.
_SERVICE_ALIASES = {name.lower(): name for name in PORT_SERVICES.values()}
_SERVICE_ALIASES.update(
    {
        "www": "HTTP",
        "www-http": "HTTP",
        "https-alt": "HTTPS-alt",
        "http-alt": "HTTP-alt",
        "ssl/http": "HTTPS",
        "ssl/https": "HTTPS",
        "msrpc": "MS RPC",
        "microsoft-ds": "SMB",
        "netbios-ssn": "NetBIOS-SSN",
        "postgres": "PostgreSQL",
        "postgresql": "PostgreSQL",
        "redis": "Redis",
        "mongodb": "MongoDB",
        "memcached": "Memcached",
        "amqp": "AMQP",
        "rdp": "RDP",
        "vnc": "VNC",
        "smb": "SMB",
        "dns": "DNS",
        "ntp": "NTP",
        "snmp": "SNMP",
        "ldap": "LDAP",
        "ldaps": "LDAPS",
        "imap": "IMAP",
        "imaps": "IMAPS",
        "pop3": "POP3",
        "pop3s": "POP3S",
        "smtp": "SMTP",
        "smtps": "SMTPS",
        "ssh": "SSH",
        "telnet": "Telnet",
        "ftp": "FTP",
        "tftp": "TFTP",
        "kerberos": "Kerberos",
        "rpcbind": "rpcbind",
    }
)
_GENERIC_SERVICES = {"", "?", "-", "unknown", "tcpwrapped", "unidentified"}

_NMAP_LINE = re.compile(
    r"^(?P<port>\d{1,5})/(?P<proto>tcp|udp)\s+"
    r"(?P<state>\S+)\s+"
    r"(?P<service>\S+)"
    r"(?:\s+(?P<version>.*))?$",
    re.I,
)
_MASSCAN_LINE = re.compile(r"\bport\s+(?P<port>\d{1,5})/(?P<proto>tcp|udp)\b", re.I)
_NAABU_LINE = re.compile(
    r"^(?P<host>\[[0-9a-fA-F:.]+\]|(?:\d{1,3}\.){3}\d{1,3}|[A-Za-z0-9_.-]+):"
    r"(?P<port>\d{1,5})(?:/(?P<proto>tcp|udp))?$"
)
_BARE_PORT = re.compile(r"^\d{1,5}$")


def as_port(value: Any) -> int | None:
    """Convierte un puerto (int, str, ``22/tcp``) a entero si es posible."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        port = value
    else:
        text = str(value or "").strip()
        if not text:
            return None
        text = text.split("/", 1)[0].strip()
        if not text.isdigit():
            return None
        port = int(text)
    if 0 < port <= 65535:
        return port
    return None


def service_name(port: Any, proto: str = "tcp", fallback: str = "") -> str:
    """Devuelve el nombre legible de un puerto.

    El mapa local tiene prioridad sobre el nombre que devuelve una API, para
    que ``22`` sea siempre ``SSH`` aunque el servicio venga como ``ssh`` o
    ``tcpwrapped``. Si el puerto no está en el mapa se usa ``fallback``.
    """
    port_number = as_port(port)
    if port_number is not None:
        known = PORT_SERVICES.get(port_number)
        if known:
            return known
    text = str(fallback or "").strip()
    if text and text.lower() not in _GENERIC_SERVICES:
        return _SERVICE_ALIASES.get(text.lower(), text)
    if port_number is None:
        return "desconocido"
    return "desconocido"


def describe_port(
    port: Any,
    proto: str = "tcp",
    service: str = "",
    product: str = "",
    state: str = "",
) -> str:
    """Formatea un puerto como ``22: SSH``, opcionalmente con producto/estado."""
    port_number = as_port(port)
    label_port = str(port_number) if port_number is not None else str(port or "?").strip()
    protocol = str(proto or "tcp").strip().lower()
    if protocol and protocol != "tcp":
        label_port = f"{label_port}/{protocol}"

    name = service_name(port_number, protocol, service)
    label = f"{label_port}: {name}"

    product_text = str(product or "").strip()
    if product_text and product_text.lower() != name.lower():
        label += f" ({product_text})"

    state_text = str(state or "").strip()
    if state_text:
        label += f" · {state_text.lower()}"
    return label


def describe_ports(
    ports: Iterable[Any],
    proto: str = "tcp",
    *,
    limit: int = 0,
) -> str:
    """Formatea una lista de puertos; ``limit`` recorta con un aviso."""
    values = list(ports)
    shown = values[:limit] if limit and limit > 0 else values
    parts = [describe_port(port, proto) for port in shown]
    if limit and limit > 0 and len(values) > limit:
        parts.append(f"… (+{len(values) - limit} más)")
    return ", ".join(parts)


def annotate_port_line(line: str) -> str:
    """Añade el nombre del servicio a una línea de nmap, naabu o masscan.

    No toca líneas que no parezcan de puertos, de modo que se puede aplicar a
    toda la salida de una herramienta etiquetada como ``puertos``.
    """
    text = str(line or "").strip()
    if not text:
        return line

    match = _NMAP_LINE.match(text)
    if match:
        return describe_port(
            match.group("port"),
            match.group("proto"),
            match.group("service"),
            match.group("version") or "",
            match.group("state"),
        )

    match = _NAABU_LINE.match(text)
    if match:
        port = match.group("port")
        proto = match.group("proto") or "tcp"
        return f"{text} ({service_name(port, proto)})"

    match = _MASSCAN_LINE.search(text)
    if match:
        port = match.group("port")
        proto = match.group("proto")
        return f"{text} · {describe_port(port, proto)}"

    if _BARE_PORT.match(text):
        return describe_port(text)

    return line
