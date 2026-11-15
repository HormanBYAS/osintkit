"""Núcleo: registro de módulos, ejecución concurrente y resultados."""

from __future__ import annotations

import concurrent.futures
import importlib
import importlib.util
import shlex
import shutil
import subprocess
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable

from .catalog import Tool
from .config import VERSION, Config
from .http import HttpClient, NetworkError, new_http
from .ports import annotate_port_line
from .util import (
    dedupe,
    format_duration,
    iso_now,
    strip_ansi,
    truncate,
)

# ---------------------------------------------------------------------------
# Resultados
# ---------------------------------------------------------------------------

LEVELS = ("info", "good", "warn", "bad", "link")


@dataclass
class Finding:
    title: str
    value: str = ""
    level: str = "info"
    url: str = ""
    data: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.level not in LEVELS:
            self.level = "info"
        self.title = str(self.title)
        self.value = str(self.value)
        self.url = str(self.url or "")

    def as_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"title": self.title, "value": self.value, "level": self.level}
        if self.url:
            out["url"] = self.url
        if self.data:
            out["data"] = self.data
        return out


@dataclass
class ToolResult:
    tool_id: str
    name: str
    category: str
    status: str = "ok"  # ok | error | skipped | timeout | cancelled
    findings: list[Finding] = field(default_factory=list)
    error: str = ""
    duration: float = 0.0
    command: str = ""
    skipped_reason: str = ""

    @property
    def count(self) -> int:
        return len(self.findings)

    def as_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool_id,
            "name": self.name,
            "category": self.category,
            "status": self.status,
            "duration": round(self.duration, 3),
            "command": self.command,
            "error": self.error,
            "skipped_reason": self.skipped_reason,
            "findings": [f.as_dict() for f in self.findings],
        }


@dataclass
class ScanResult:
    target: str
    kind: str
    profile: str
    started_at: str = field(default_factory=iso_now)
    finished_at: str = ""
    duration: float = 0.0
    results: list[ToolResult] = field(default_factory=list)
    version: str = VERSION

    @property
    def ok_count(self) -> int:
        return sum(1 for r in self.results if r.status == "ok")

    @property
    def finding_count(self) -> int:
        return sum(r.count for r in self.results)

    @property
    def error_count(self) -> int:
        return sum(1 for r in self.results if r.status in ("error", "timeout"))

    @property
    def skipped_count(self) -> int:
        return sum(1 for r in self.results if r.status == "skipped")

    def as_dict(self) -> dict[str, Any]:
        return {
            "tool": "osintkit",
            "version": self.version,
            "target": self.target,
            "kind": self.kind,
            "profile": self.profile,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duration": round(self.duration, 3),
            "summary": {
                "tools": len(self.results),
                "ok": self.ok_count,
                "errors": self.error_count,
                "skipped": self.skipped_count,
                "findings": self.finding_count,
            },
            "results": [r.as_dict() for r in self.results],
        }


# ---------------------------------------------------------------------------
# Contexto para módulos
# ---------------------------------------------------------------------------

class Context:
    def __init__(
        self,
        cfg: Config,
        http: HttpClient,
        target: str,
        kind: str,
        *,
        options: dict[str, Any] | None = None,
        timeout: float = 30.0,
        cancel: threading.Event | None = None,
    ) -> None:
        self.cfg = cfg
        self.http = http
        self.target = target
        self.kind = kind
        self.options = options or {}
        self.timeout = timeout
        self.cancel = cancel or threading.Event()

    def key(self, name: str) -> str:
        return self.cfg.key(name)

    def has_key(self, name: str) -> bool:
        return self.cfg.has_key(name)

    def get(self, name: str, default: Any = None) -> Any:
        return self.options.get(name, default)

    @property
    def domain(self) -> str:
        return self.target

    @property
    def url(self) -> str:
        if self.target.startswith(("http://", "https://")):
            return self.target
        return f"https://{self.target}"

    def log(self, message: str) -> None:
        """El runner puede inyectar un logger; por defecto no hace nada."""
        logger = self.options.get("_logger")
        if callable(logger):
            logger(message)

    def check_cancel(self) -> None:
        if self.cancel.is_set():
            raise Cancelled("Cancelado por el usuario")


class Cancelled(RuntimeError):
    pass


# ---------------------------------------------------------------------------
# Registro de módulos internos
# ---------------------------------------------------------------------------

MODULES: dict[str, Callable[[Context, Tool], Iterable[Finding]]] = {}


def module(name: str) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        MODULES[name] = func
        return func

    return decorator


def load_builtin_modules() -> None:
    """Importa todos los módulos internos para poblar MODULES."""
    from . import modules as _modules  # noqa: F401


def load_plugins(cfg: Config) -> list[str]:
    """Carga plugins Python opcionales desde el directorio de configuración.

    Un plugin debe exponer ``register(api)``. El API permite ``api.tool(...)`` y
    ``api.module(name)(func)`` para ampliar el catálogo en tiempo de ejecución.
    """
    loaded: list[str] = []
    directories = [cfg.path.parent / "plugins"]
    for directory in directories:
        if not directory.is_dir():
            continue
        for path in sorted(directory.glob("*.py")):
            if path.name.startswith("_"):
                continue
            mod_name = f"osintkit_plugin_{path.stem}"
            try:
                spec = importlib.util.spec_from_file_location(mod_name, path)
                if not spec or not spec.loader:
                    continue
                module_obj = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module_obj)
                register = getattr(module_obj, "register", None)
                if callable(register):
                    register(PluginAPI())
                    loaded.append(path.name)
            except Exception:
                continue
    return loaded


class PluginAPI:
    """API mínima para plugins."""

    def tool(self, tool: Tool) -> None:
        from .catalog import register_tool

        register_tool(tool)

    def module(self, name: str) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        return module(name)


# ---------------------------------------------------------------------------
# Disponibilidad
# ---------------------------------------------------------------------------

def missing_requirements(tool: Tool, cfg: Config) -> list[str]:
    missing: list[str] = []
    for key in tool.keys:
        if not cfg.has_key(key):
            missing.append(f"clave {key}")
    for binary in tool.bins:
        if not shutil.which(binary):
            missing.append(f"binario {binary}")
    if tool.module and tool.module not in MODULES:
        missing.append(f"módulo {tool.module}")
    return missing


def tool_state(tool: Tool, cfg: Config) -> tuple[str, str]:
    """Devuelve (estado, detalle): listo, falta, enlace."""
    if tool.url and not tool.module and not tool.commands:
        return "enlace", "recurso web"
    missing = missing_requirements(tool, cfg)
    if missing:
        return "falta", ", ".join(missing)
    if tool.module:
        return "listo", "módulo interno"
    if tool.commands:
        return "listo", "comando externo"
    return "enlace", "recurso web"


def install_hint(tool: Tool) -> str:
    if tool.install:
        return tool.install.get("void") or tool.install.get("any") or ""
    if tool.bins:
        return f"sudo xbps-install -S {tool.bins[0]}"
    return ""


# ---------------------------------------------------------------------------
# Ejecución de un módulo
# ---------------------------------------------------------------------------

def run_tool(
    tool: Tool,
    ctx: Context,
    *,
    max_findings: int = 500,
) -> ToolResult:
    started = time.monotonic()
    result = ToolResult(tool_id=tool.id, name=tool.name, category=tool.category)
    try:
        if ctx.cancel.is_set():
            result.status = "cancelled"
            result.skipped_reason = "cancelado"
            return result

        missing = missing_requirements(tool, ctx.cfg)
        if missing:
            result.status = "skipped"
            result.skipped_reason = "faltan: " + ", ".join(missing)
            hint = install_hint(tool)
            if hint:
                result.skipped_reason += f" · instalar: {hint}"
            return result

        if tool.module:
            handler = MODULES[tool.module]
            raw = handler(ctx, tool)
            findings = list(raw or [])
            result.findings = _clean_findings(findings, max_findings)
            result.status = "ok"
        elif tool.commands:
            result = _run_external(tool, ctx, result)
        elif tool.url:
            result.findings = [
                Finding(
                    title=tool.name,
                    value="Abrir recurso web",
                    level="link",
                    url=render_template(tool.url, ctx.target, ctx.kind),
                )
            ]
            result.status = "ok"
        else:
            result.status = "error"
            result.error = "la herramienta no tiene implementación"
    except Cancelled:
        result.status = "cancelled"
        result.skipped_reason = "cancelado"
    except NetworkError as exc:
        result.status = "error"
        result.error = str(exc)
    except Exception as exc:  # noqa: BLE001 - un módulo no debe tumbar la app
        result.status = "error"
        result.error = f"{type(exc).__name__}: {exc}"
    finally:
        result.duration = time.monotonic() - started
    return result


def _clean_findings(findings: Iterable[Finding], limit: int) -> list[Finding]:
    out: list[Finding] = []
    seen: set[tuple[str, str, str]] = set()
    for item in findings:
        if not isinstance(item, Finding):
            item = Finding(title=str(item))
        key = (item.title, item.value, item.url)
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
        if len(out) >= limit:
            out.append(
                Finding(
                    title="Límite alcanzado",
                    value=f"Se muestran solo los primeros {limit} resultados.",
                    level="warn",
                )
            )
            break
    return out


def render_template(template: str, target: str, kind: str) -> str:
    from urllib.parse import quote, quote_plus

    from .util import extract_host, normalize_domain, phone_digits

    host = extract_host(target) if kind == "url" else target
    domain = normalize_domain(host) if kind in ("url", "domain", "email", "username") else host
    values = {
        "target": target,
        "domain": domain,
        "host": host,
        "url": target if target.startswith(("http://", "https://")) else f"https://{target}",
        "email": target,
        "email_q": quote(target, safe=""),
        "username": target,
        "username_q": quote(target, safe=""),
        "ip": target,
        "phone": target,
        "phone_q": quote_plus(target),
        "phone_digits": phone_digits(target),
        "file": target,
        "hash": target,
        "keyword": target,
    }
    out = template
    for key, value in values.items():
        out = out.replace("{" + key + "}", value)
    return out


def _run_external(tool: Tool, ctx: Context, result: ToolResult) -> ToolResult:
    command_template = tool.command_for(ctx.kind)
    if not command_template:
        result.status = "skipped"
        result.skipped_reason = f"no hay comando para el tipo {ctx.kind}"
        return result
    command = render_template(command_template, ctx.target, ctx.kind)
    result.command = command
    argv = shlex.split(command)
    if not argv:
        result.status = "error"
        result.error = "comando vacío"
        return result
    binary = argv[0]
    if not shutil.which(binary):
        result.status = "skipped"
        result.skipped_reason = f"falta el binario {binary}"
        hint = install_hint(tool)
        if hint:
            result.skipped_reason += f" · instalar: {hint}"
        return result
    timeout = tool.timeout or int(ctx.cfg.get("external_timeout", 240))
    try:
        proc = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        result.status = "timeout"
        result.error = f"el comando superó {timeout}s"
        return result
    except OSError as exc:
        result.status = "error"
        result.error = str(exc)
        return result

    stdout = strip_ansi(proc.stdout or "").strip()
    stderr = strip_ansi(proc.stderr or "").strip()
    lines = [line.rstrip() for line in stdout.splitlines() if line.strip()]
    port_output = "puertos" in tool.tags
    findings: list[Finding] = []
    for line in lines[: ctx.cfg.int("max_findings", 500)]:
        if port_output:
            line = annotate_port_line(line)
        findings.append(Finding(title=tool.name, value=truncate(line, 1000), level="info"))
    if len(lines) > len(findings):
        findings.append(
            Finding(
                title="Salida truncada",
                value=f"{len(lines) - len(findings)} líneas adicionales omitidas.",
                level="warn",
            )
        )
    if stderr:
        findings.append(Finding(title="stderr", value=truncate(stderr, 4000), level="warn"))
    result.findings = findings
    if proc.returncode != 0 and not stdout:
        result.status = "error"
        result.error = f"código de salida {proc.returncode}: {truncate(stderr, 500)}"
    else:
        result.status = "ok"
        if proc.returncode != 0:
            result.error = f"código de salida {proc.returncode}"
    return result


# ---------------------------------------------------------------------------
# Escaneo concurrente
# ---------------------------------------------------------------------------

EventCallback = Callable[[str, dict[str, Any]], None]


def run_scan(
    tools: Iterable[Tool],
    target: str,
    kind: str,
    cfg: Config,
    *,
    profile: str = "",
    options: dict[str, Any] | None = None,
    no_cache: bool = False,
    concurrency: int | None = None,
    cancel: threading.Event | None = None,
    on_event: EventCallback | None = None,
) -> ScanResult:
    started = time.monotonic()
    cancel = cancel or threading.Event()
    http = new_http(cfg, no_cache=no_cache)
    tools = list(tools)
    scan = ScanResult(target=target, kind=kind, profile=profile)
    base_options = dict(options or {})
    workers = max(1, int(concurrency or cfg.int("concurrency", 8)))
    max_findings = cfg.int("max_findings", 500)
    lock = threading.Lock()

    def emit(kind_event: str, payload: dict[str, Any]) -> None:
        if on_event:
            try:
                on_event(kind_event, payload)
            except Exception:
                pass

    def work(tool: Tool) -> ToolResult:
        if cancel.is_set():
            return ToolResult(
                tool_id=tool.id,
                name=tool.name,
                category=tool.category,
                status="cancelled",
                skipped_reason="cancelado",
            )
        scan_options = dict(base_options)
        scan_options["_logger"] = lambda msg: emit("log", {"tool": tool.id, "message": msg})
        ctx = Context(
            cfg,
            http,
            target,
            kind,
            options=scan_options,
            timeout=float(tool.timeout or cfg.get("tool_timeout", 90)),
            cancel=cancel,
        )
        emit("start", {"tool": tool.id, "name": tool.name})
        res = run_tool(tool, ctx, max_findings=max_findings)
        emit(
            "done",
            {
                "tool": tool.id,
                "name": tool.name,
                "status": res.status,
                "count": res.count,
                "duration": res.duration,
                "error": res.error,
                "skipped_reason": res.skipped_reason,
            },
        )
        return res

    pending: dict[concurrent.futures.Future[ToolResult], Tool] = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers, thread_name_prefix="osintkit") as pool:
        for tool in tools:
            pending[pool.submit(work, tool)] = tool
        try:
            for future in concurrent.futures.as_completed(pending, timeout=None):
                tool = pending[future]
                tool_timeout = float(tool.timeout or cfg.get("tool_timeout", 90))
                try:
                    scan.results.append(future.result(timeout=tool_timeout))
                except concurrent.futures.TimeoutError:
                    scan.results.append(
                        ToolResult(
                            tool_id=tool.id,
                            name=tool.name,
                            category=tool.category,
                            status="timeout",
                            error=f"superó {tool_timeout:.0f}s",
                        )
                    )
                except Exception as exc:  # noqa: BLE001
                    scan.results.append(
                        ToolResult(
                            tool_id=tool.id,
                            name=tool.name,
                            category=tool.category,
                            status="error",
                            error=str(exc),
                        )
                    )
                if cancel.is_set():
                    for fut in pending:
                        fut.cancel()
        except KeyboardInterrupt:
            cancel.set()
            for fut in pending:
                fut.cancel()
            raise

    order = {tool.id: i for i, tool in enumerate(tools)}
    scan.results.sort(key=lambda r: order.get(r.tool_id, 9999))
    scan.duration = time.monotonic() - started
    scan.finished_at = iso_now()
    emit("finished", scan.as_dict())
    return scan


def summarize(scan: ScanResult) -> str:
    return (
        f"{len(scan.results)} herramientas · {scan.ok_count} ok · "
        f"{scan.error_count} errores · {scan.skipped_count} omitidas · "
        f"{scan.finding_count} hallazgos · {format_duration(scan.duration)}"
    )


def dedupe_strings(values: Iterable[str]) -> list[str]:
    return dedupe(values)
