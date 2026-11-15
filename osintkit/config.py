"""Configuración persistente y rutas XDG de osintkit."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from .util import atomic_write, ensure_dir, mask_secret

APP_NAME = "osintkit"
VERSION = "1.4.0"
CONFIG_VERSION = 1

DEFAULT_SETTINGS: dict[str, Any] = {
    "timeout": 15,
    "external_timeout": 240,
    "concurrency": 8,
    "cache_ttl": 3600,
    "rate_interval": 0.12,
    "max_findings": 500,
    "username_mass_limit": 0,
    "username_mass_workers": 40,
    "username_mass_timeout": 6.0,
    "email_mass_limit": 0,
    "email_mass_workers": 40,
    "email_mass_timeout": 6.0,
    "report_dir": "",
    "user_agent": (
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/124.0 Safari/537.36 osintkit/1.0"
    ),
    "wordlist": "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "color": True,
}

# Claves conocidas. Se pueden agregar más desde el archivo de configuración.
KNOWN_KEYS: dict[str, str] = {
    "VIRUSTOTAL_API_KEY": "VirusTotal",
    "SHODAN_API_KEY": "Shodan",
    "CENSYS_API_ID": "Censys (ID)",
    "CENSYS_API_SECRET": "Censys (secret)",
    "HIBP_API_KEY": "Have I Been Pwned",
    "ABUSECH_AUTH_KEY": "abuse.ch (URLhaus/MalwareBazaar/ThreatFox)",
    "ABUSEIPDB_API_KEY": "AbuseIPDB",
    "GREYNOISE_API_KEY": "GreyNoise",
    "HUNTER_API_KEY": "Hunter.io",
    "EMAILREP_API_KEY": "EmailRep",
    "NUMVERIFY_API_KEY": "Numverify",
    "VERIPHONE_API_KEY": "Veriphone",
    "ABSTRACT_PHONE_API_KEY": "Abstract Phone",
    "TWILIO_ACCOUNT_SID": "Twilio (SID)",
    "TWILIO_AUTH_TOKEN": "Twilio (token)",
    "IPQUALITYSCORE_API_KEY": "IPQualityScore",
    "OPENCORPORATES_API_KEY": "OpenCorporates",
    "COMPANIES_HOUSE_API_KEY": "Companies House (UK)",
    "OPENSANCTIONS_API_KEY": "OpenSanctions",
    "GITHUB_TOKEN": "GitHub (token)",
    "NVD_API_KEY": "NVD (opcional)",
    "DVLA_API_KEY": "DVLA Vehicle Enquiry (Reino Unido)",
    "GOOGLE_SAFEBROWSING_API_KEY": "Google Safe Browsing",
    "DEHASHED_API_KEY": "Dehashed",
    "INTELX_API_KEY": "Intelligence X",
    "LEAKCHECK_API_KEY": "LeakCheck",
    "TWITCH_CLIENT_ID": "Twitch",
    "TWITCH_CLIENT_SECRET": "Twitch (secret)",
    "STEAM_API_KEY": "Steam",
    "SEC_API_KEY": "SEC EDGAR (opcional)",
}


def _xdg(env: str, fallback: str) -> Path:
    base = os.environ.get(env)
    if base:
        return Path(base).expanduser()
    return Path.home() / fallback


def config_dir() -> Path:
    return _xdg("XDG_CONFIG_HOME", ".config") / APP_NAME


def data_dir() -> Path:
    return _xdg("XDG_DATA_HOME", ".local/share") / APP_NAME


def cache_dir() -> Path:
    return _xdg("XDG_CACHE_HOME", ".cache") / APP_NAME


def config_path() -> Path:
    return config_dir() / "config.json"


def reports_dir(cfg: "Config | None" = None) -> Path:
    configured = (cfg.settings.get("report_dir") if cfg else "") or ""
    if configured:
        return ensure_dir(Path(configured).expanduser())
    return ensure_dir(data_dir() / "reports")


class Config:
    """Configuración JSON sencilla, editable a mano.

    Las claves de API se leen primero del entorno y después del archivo. De ese
    modo se pueden usar variables de entorno sin guardar secretos en disco.
    """

    def __init__(self, path: Path | None = None) -> None:
        self.path = Path(path) if path else config_path()
        self.keys: dict[str, str] = {}
        self.settings: dict[str, Any] = dict(DEFAULT_SETTINGS)
        self.loaded = False
        self.load()

    # ------------------------------------------------------------------
    # Carga / guardado
    # ------------------------------------------------------------------
    def load(self) -> None:
        self.keys = {}
        self.settings = dict(DEFAULT_SETTINGS)
        if self.path.exists():
            try:
                raw = json.loads(self.path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                raw = {}
            if isinstance(raw, dict):
                keys = raw.get("keys", {})
                settings = raw.get("settings", {})
                if isinstance(keys, dict):
                    self.keys = {str(k): str(v) for k, v in keys.items() if v}
                if isinstance(settings, dict):
                    self.settings.update(settings)
        self.loaded = True

    def save(self) -> Path:
        payload = {
            "version": CONFIG_VERSION,
            "settings": self.settings,
            "keys": self.keys,
        }
        return atomic_write(self.path, json.dumps(payload, ensure_ascii=False, indent=2) + "\n")

    def ensure_file(self) -> Path:
        if not self.path.exists():
            self.save()
        return self.path

    # ------------------------------------------------------------------
    # Acceso
    # ------------------------------------------------------------------
    def get(self, name: str, default: Any = None) -> Any:
        return self.settings.get(name, default)

    def set(self, name: str, value: Any) -> None:
        self.settings[name] = value

    def key(self, name: str) -> str:
        env_value = os.environ.get(name, "").strip()
        if env_value:
            return env_value
        return str(self.keys.get(name, "") or "").strip()

    def has_key(self, name: str) -> bool:
        return bool(self.key(name))

    def set_key(self, name: str, value: str) -> None:
        self.keys[name] = value.strip()

    def key_source(self, name: str) -> str:
        if os.environ.get(name, "").strip():
            return "entorno"
        if str(self.keys.get(name, "") or "").strip():
            return "config"
        return "—"

    def masked_keys(self) -> dict[str, str]:
        names = sorted(set(KNOWN_KEYS) | set(self.keys))
        return {name: (mask_secret(self.key(name)) if self.key(name) else "—") for name in names}

    def api_key(self, name: str) -> str:
        return self.key(name)

    def int(self, name: str, default: int = 0) -> int:
        try:
            return int(self.settings.get(name, default))
        except (TypeError, ValueError):
            return default

    def float(self, name: str, default: float = 0.0) -> float:
        try:
            return float(self.settings.get(name, default))
        except (TypeError, ValueError):
            return default
