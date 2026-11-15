"""Interfaz de línea de comandos de osintkit."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import textwrap
from pathlib import Path
from typing import Any, Iterable

from . import catalog
from .config import (
    APP_NAME,
    KNOWN_KEYS,
    VERSION,
    Config,
    cache_dir,
    config_dir,
    config_path,
    data_dir,
    reports_dir,
)
from .core import (
    MODULES,
    ScanResult,
    ToolResult,
    install_hint,
    load_builtin_modules,
    load_plugins,
    missing_requirements,
    run_scan,
    run_tool,
    summarize,
    tool_state,
)
from .http import HttpClient, NetworkError, cache_info, new_http
from .plates import (
    compact_plate,
    country_label,
    normalize_plate,
    resolve_country,
    split_plate_country,
)
from .report import FORMATS, render_console, write_reports
from .util import (
    detect_kind,
    format_duration,
    human_bytes,
    normalize_target,
    truncate,
)

try:  # pragma: no cover - color opcional
    from .ui import colorize as _colorize
except Exception:  # pragma: no cover
    def _colorize(text: str, level: str = "info") -> str:  # type: ignore
        return text


# ---------------------------------------------------------------------------
# Utilidades de presentación
# ---------------------------------------------------------------------------

def _color_enabled(args: argparse.Namespace) -> bool:
    if getattr(args, "no_color", False) or os.environ.get("NO_COLOR"):
        return False
    return sys.stdout.isatty()


def _style(text: str, level: str, enabled: bool) -> str:
    return _colorize(text, level) if enabled else text


def _print_table(headers: list[str], rows: list[list[str]], *, enabled: bool = False) -> None:
    widths = [len(h) for h in headers]
    for row in rows:
        for index, value in enumerate(row):
            widths[index] = max(widths[index], len(value))
    line = "  ".join(_style(h.ljust(widths[i]), "info", enabled) for i, h in enumerate(headers))
    print(line)
    print("  ".join("-" * width for width in widths))
    for row in rows:
        print("  ".join(value.ljust(widths[i]) for i, value in enumerate(row)))


def _err(message: str) -> None:
    print(message, file=sys.stderr)


def _tool_available(tool: catalog.Tool, cfg: Config) -> str:
    state, detail = tool_state(tool, cfg)
    if state == "listo":
        return "listo"
    if state == "enlace":
        return "web"
    return f"falta ({detail})"


def _load(args: argparse.Namespace) -> tuple[Config, list[str]]:
    cfg = Config(Path(args.config).expanduser() if getattr(args, "config", None) else None)
    load_builtin_modules()
    plugins = load_plugins(cfg)
    return cfg, plugins


def _detect(
    target: str,
    kind: str | None,
    country: str = "",
) -> tuple[str, str, dict[str, Any] | None]:
    """Normaliza el objetivo y resuelve el país de una placa.

    Un ``--country`` explícito convierte un objetivo automático en placa. Si el
    país viaja dentro del objetivo, se separa para dejar solo la matrícula.
    """
    normalized = normalize_target(target)
    explicit = resolve_country(country) if country and country.strip() else None
    if kind and kind != "auto":
        chosen = kind
    elif explicit:
        chosen = "plate"
    else:
        chosen = detect_kind(normalized)
    if chosen != "plate":
        return normalized, chosen, explicit
    plate, resolved = split_plate_country(normalized, country)
    return normalize_plate(plate), chosen, resolved or explicit


def _select_tools(
    cfg: Config,
    kind: str,
    *,
    profile: str | None,
    tool_ids: list[str] | None,
    category: str | None,
    include_active: bool,
    all_tools: bool,
) -> tuple[list[catalog.Tool], str]:
    notes: list[str] = []
    if tool_ids:
        tools = [catalog.get_tool(tid) for tid in tool_ids]
        missing = [tid for tid, tool in zip(tool_ids, tools) if tool is None]
        if missing:
            raise SystemExit("Herramientas desconocidas: " + ", ".join(missing))
        selected = [tool for tool in tools if tool is not None]
        selected = [tool for tool in selected if kind in tool.kinds] or selected
        if category:
            selected = [tool for tool in selected if tool.category == category]
        return selected, "selección manual"

    profile_name = catalog.resolve_profile(profile, kind)
    if all_tools:
        selected = catalog.tools_for_kind(kind)
        label = "todas"
    else:
        selected = catalog.profile_tools(profile_name, kind)
        label = profile_name
        if not selected:
            selected = catalog.tools_for_kind(kind)
            label = "todas (perfil vacío)"
    if category:
        selected = [tool for tool in selected if tool.category == category]
    if not include_active:
        passive = [tool for tool in selected if tool.passive]
        removed = len(selected) - len(passive)
        if removed:
            notes.append(f"{removed} herramientas activas omitidas (usa --active)")
        selected = passive
    return selected, label


def _confirm_active(tools: Iterable[catalog.Tool], assume_yes: bool) -> bool:
    active = [tool for tool in tools if not tool.passive]
    if not active:
        return True
    _err("")
    _err("⚠  Herramientas activas seleccionadas:")
    for tool in active:
        _err(f"   · {tool.id} — {tool.name}")
    _err("   Úsalas solo sobre sistemas que te pertenecen o para los que tienes autorización escrita.")
    if assume_yes:
        return True
    if not sys.stdin.isatty():
        _err("Entrada no interactiva: añade --yes para confirmar la autorización.")
        return False
    try:
        answer = input("¿Confirmas que tienes autorización? [s/N] ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        return False
    return answer in ("s", "si", "sí", "y", "yes")


def _ask(prompt: str) -> str:
    try:
        return input(prompt).strip()
    except (EOFError, KeyboardInterrupt):
        return ""


def _menu_choice(
    title: str,
    options: Iterable[tuple[str, str, str]],
    default_index: int = 0,
) -> str:
    """Menú numerado sencillo para el asistente de la CLI."""
    items = list(options)
    print("")
    print(title)
    for index, (_value, label, description) in enumerate(items, start=1):
        marker = "*" if index - 1 == default_index else " "
        print(f" {marker} {index:2}. {label:26} {description}")
    while True:
        raw = _ask(f"Elige 1-{len(items)} [Enter = {default_index + 1}]: ")
        if not raw:
            return items[default_index][0]
        try:
            index = int(raw) - 1
        except ValueError:
            index = -1
        if 0 <= index < len(items):
            return items[index][0]
        print("Opción no válida; escribe un número de la lista.")


def _interactive_scan(
    args: argparse.Namespace,
) -> tuple[str, str, str | None, bool, dict[str, Any] | None] | None:
    """Asistente: tipo de objetivo, valor y profundidad del escaneo."""
    kind_default = 0
    if getattr(args, "kind", "auto") and args.kind != "auto":
        for index, (kind, _label, _description) in enumerate(catalog.TARGET_TYPES):
            if kind == args.kind:
                kind_default = index
                break
    chosen = _menu_choice(
        "¿Qué tipo de objetivo quieres investigar?",
        catalog.TARGET_TYPES,
        kind_default,
    )
    target_raw = getattr(args, "target", "") or _ask("Objetivo: ")
    if not target_raw:
        return None
    target, kind, country = _detect(
        target_raw,
        chosen,
        str(getattr(args, "country", "") or ""),
    )
    if kind == "plate" and not country:
        print("\nPara una placa necesito el país (código o nombre: ES, MX, AR, UK, NL…).")
        for _attempt in range(3):
            raw = _ask("País: ")
            country = resolve_country(raw)
            if country:
                break
            if not raw:
                print("El país es obligatorio para escanear una placa.")
                continue
            print("País no reconocido. Prueba con el código ISO o el nombre en español.")
        if not country:
            print("No se puede continuar sin un país válido.")
            return None
    label = f"  ·  país: {country_label(country)}" if country else ""
    print(f"\nObjetivo: {target}  ·  tipo: {kind}{label}")

    profile_names = catalog.profiles_for_kind(kind)
    profile_options: list[tuple[str, str, str]] = [
        ("auto", "Automático (recomendado)", "solo técnicas pasivas"),
    ]
    for name in profile_names:
        profile = catalog.PROFILES.get(name, {})
        active = catalog.profile_has_active(name, kind)
        suffix = " · técnicas activas" if active else ""
        profile_options.append(
            (name, str(profile.get("name", name)), str(profile.get("description", "")) + suffix)
        )
    default_profile = 0
    if getattr(args, "profile", None):
        resolved = catalog.resolve_profile(args.profile, kind)
        for index, (name, _label, _description) in enumerate(profile_options):
            if name == resolved:
                default_profile = index
                break
    selected_profile = _menu_choice(
        "¿Qué profundidad quieres usar?",
        profile_options,
        default_profile,
    )
    profile = None if selected_profile == "auto" else selected_profile

    active = bool(getattr(args, "active", False))
    if profile and catalog.profile_has_active(profile, kind) and not active:
        answer = _ask(
            "Ese perfil incluye técnicas activas. "
            "¿Confirmas que tienes autorización? [s/N]: "
        )
        active = answer.lower() in ("s", "si", "sí", "y", "yes")
        if not active:
            print("Usando solo herramientas pasivas del perfil automático.")
            profile = None
    return target, kind, profile, active, country



def _progress(quiet: bool):
    def on_event(event: str, payload: dict[str, Any]) -> None:
        if quiet:
            return
        if event == "start":
            _err(f"  → {payload.get('name') or payload.get('tool')}")
        elif event == "done":
            status = str(payload.get("status", ""))
            marker = {"ok": "✓", "error": "✗", "skipped": "·", "timeout": "⏱", "cancelled": "×"}.get(status, "?")
            count = payload.get("count", 0)
            extra = ""
            if payload.get("error"):
                extra = f" — {truncate(str(payload['error']), 120)}"
            elif payload.get("skipped_reason"):
                extra = f" — {truncate(str(payload['skipped_reason']), 120)}"
            _err(f"  {marker} {payload.get('name') or payload.get('tool')} ({count}){extra}")

    return on_event


def _formats(value: str) -> list[str]:
    if not value or value == "none":
        return []
    formats = [part.strip().lower() for part in value.replace(";", ",").split(",") if part.strip()]
    invalid = [fmt for fmt in formats if fmt not in FORMATS and fmt != "markdown"]
    if invalid:
        raise SystemExit(f"Formato desconocido: {', '.join(invalid)} (usa json, md, html)")
    return formats


def _write_outputs(scan: ScanResult, args: argparse.Namespace) -> list[Path]:
    formats = _formats(getattr(args, "format", "json,md,html"))
    if not formats:
        return []
    directory = getattr(args, "report_dir", None) or None
    paths = write_reports(scan, formats=formats, directory=directory)
    if not getattr(args, "quiet", False):
        for path in paths:
            print(f"Informe: {path}")
    return paths


# ---------------------------------------------------------------------------
# Comandos
# ---------------------------------------------------------------------------

def cmd_scan(args: argparse.Namespace) -> int:
    cfg, plugins = _load(args)
    interactive = bool(getattr(args, "interactive", False)) or not getattr(args, "target", "")
    if interactive:
        if not sys.stdin.isatty():
            _err("Falta el objetivo. Uso: osintkit scan OBJETIVO [-k tipo] [-p perfil]")
            _err("O ejecuta `osintkit scan -i` en una terminal interactiva.")
            return 2
        selection = _interactive_scan(args)
        if selection is None:
            _err("Escaneo cancelado.")
            return 2
        target, kind, profile, active, country = selection
        args.target = target
        args.kind = kind
        args.profile = profile
        if active:
            args.active = True
            args.yes = True
    else:
        target, kind, country = _detect(
            args.target,
            args.kind,
            str(getattr(args, "country", "") or ""),
        )
    if getattr(args, "country", "") and country is None:
        _err(
            "País no reconocido: "
            f"«{args.country}». Usa un código ISO (ES, MX, AR, UK, NL…) o el nombre."
        )
        return 2
    if kind == "plate" and country is None:
        _err("Para escanear una placa indica el país con --country/--pais.")
        _err('Ejemplo: osintkit scan "1234 ABC" -k plate --pais ES')
        _err('También puedes incluir el país: osintkit scan "1234ABC, Reino Unido"')
        return 2
    if kind == "plate" and country is not None and not compact_plate(target):
        _err("La placa está vacía o no contiene caracteres válidos.")
        return 2
    scan_options = {"country": str(country.get("code") or country.get("name") or "")} if country else {}
    if plugins and not args.quiet:
        _err(f"Plugins cargados: {', '.join(plugins)}")
    tools, label = _select_tools(
        cfg,
        kind,
        profile=args.profile,
        tool_ids=args.tools,
        category=args.category,
        include_active=args.active,
        all_tools=args.all,
    )
    if not tools:
        _err(f"No hay herramientas para el tipo «{kind}» con esos filtros.")
        return 2
    if args.dry_run:
        context = f" · país: {country_label(country)}" if country else ""
        print(f"Objetivo: {target} ({kind}){context} · perfil: {label}")
        print(f"Herramientas: {len(tools)}")
        for tool in tools:
            state = _tool_available(tool, cfg)
            print(f"  {tool.id:32} {state:20} {tool.name}")
        return 0
    active = [tool for tool in tools if not tool.passive]
    if active and not _confirm_active(active, args.yes):
        return 2

    if not args.quiet:
        context = f" · país: {country_label(country)}" if country else ""
        print(f"Objetivo: {target} ({kind}){context}")
        print(f"Perfil: {label} · {len(tools)} herramientas · concurrencia {args.concurrency or cfg.get('concurrency')}")
        print("")
    cancel = None
    try:
        scan = run_scan(
            tools,
            target,
            kind,
            cfg,
            profile=label,
            options=scan_options,
            no_cache=args.no_cache,
            concurrency=args.concurrency,
            on_event=_progress(args.quiet),
        )
    except KeyboardInterrupt:
        _err("Escaneo cancelado.")
        return 130

    if not args.quiet:
        print("")
        print(render_console(scan, color=_color_enabled(args)))
    _write_outputs(scan, args)
    return 1 if scan.error_count and not scan.ok_count else 0


def cmd_run(args: argparse.Namespace) -> int:
    cfg, _ = _load(args)
    tool = catalog.get_tool(args.tool_id)
    if not tool:
        candidates = [t for t in catalog.TOOLS if args.tool_id in t.id or args.tool_id in t.name.lower()]
        if len(candidates) == 1:
            tool = candidates[0]
        else:
            _err(f"Herramienta no encontrada: {args.tool_id}")
            if candidates:
                _err("Quizá quisiste: " + ", ".join(t.id for t in candidates[:10]))
            return 2
    target, kind, country = _detect(
        args.target,
        args.kind,
        str(getattr(args, "country", "") or ""),
    )
    if getattr(args, "country", "") and country is None:
        _err(
            "País no reconocido: "
            f"«{args.country}». Usa un código ISO (ES, MX, AR, UK, NL…) o el nombre."
        )
        return 2
    if kind not in tool.kinds and (not args.kind or args.kind == "auto") and len(tool.kinds) == 1:
        target, kind, country = _detect(
            args.target,
            tool.kinds[0],
            str(getattr(args, "country", "") or ""),
        )
    if kind not in tool.kinds:
        _err(
            f"«{tool.id}» no admite objetivos de tipo {kind}. "
            f"Tipos válidos: {', '.join(tool.kinds)}"
        )
        return 2
    if kind == "plate" and country is None:
        _err("Para consultar una placa indica el país con --country/--pais.")
        _err('Ejemplo: osintkit run plate_lookup "1234 ABC" --pais ES')
        return 2
    if not tool.passive and not _confirm_active([tool], args.yes):
        return 2

    result = ToolResult(tool_id=tool.id, name=tool.name, category=tool.category)
    ctx = None
    from .core import Context, run_tool as _run_tool

    http = new_http(cfg, no_cache=args.no_cache)
    options = {"country": str(country.get("code") or country.get("name") or "")} if country else {}
    ctx = Context(
        cfg,
        http,
        target,
        kind,
        options=options,
        timeout=float(cfg.get("tool_timeout", 90)),
    )
    result = _run_tool(tool, ctx)
    scan = ScanResult(target=target, kind=kind, profile=tool.id, results=[result])
    scan.duration = result.duration
    from .util import iso_now

    scan.finished_at = iso_now()
    if not args.quiet:
        print(render_console(scan, color=_color_enabled(args)))
    _write_outputs(scan, args)
    return 0 if result.status in ("ok", "skipped") else 1


def cmd_list(args: argparse.Namespace) -> int:
    cfg, _ = _load(args)
    tools = catalog.filter_tools(
        kind=args.kind,
        category=args.category,
        query=args.query or "",
        passive_only=args.passive,
        available_only=args.available,
        cfg=cfg,
    )
    enabled = _color_enabled(args)
    if args.json:
        payload = []
        for tool in tools:
            state, detail = tool_state(tool, cfg)
            payload.append(
                {
                    "id": tool.id,
                    "name": tool.name,
                    "category": tool.category,
                    "category_name": catalog.CATEGORIES.get(tool.category, (tool.category, ""))[0],
                    "kinds": list(tool.kinds),
                    "mode": tool.mode,
                    "passive": tool.passive,
                    "state": state,
                    "detail": detail,
                    "keys": list(tool.keys),
                    "bins": list(tool.bins),
                    "description": tool.description,
                }
            )
        print(json.dumps(payload, ensure_ascii=False, indent=2))
        return 0

    rows = []
    for tool in tools:
        state, _ = tool_state(tool, cfg)
        marker = {"listo": "✓", "falta": "✗", "enlace": "↗"}.get(state, "?")
        rows.append(
            [
                tool.id,
                tool.name,
                tool.category,
                ",".join(tool.kinds),
                tool.mode,
                marker if state != "falta" else "✗ falta",
            ]
        )
    _print_table(["ID", "Nombre", "Categoría", "Tipos", "Modo", "Estado"], rows, enabled=enabled)
    print(f"\n{len(tools)} herramientas · {len(catalog.CATEGORIES)} categorías")
    return 0


def cmd_search(args: argparse.Namespace) -> int:
    cfg, _ = _load(args)
    tools = catalog.filter_tools(query=args.query, kind=args.kind, cfg=cfg)
    if not tools:
        print("Sin coincidencias.")
        return 1
    for tool in tools:
        state, detail = tool_state(tool, cfg)
        print(f"{tool.id:34} {tool.name}")
        print(f"  {tool.category} · {', '.join(tool.kinds)} · {tool.mode} · {state}")
        print(f"  {textwrap.shorten(tool.description, 150)}")
        if state == "falta":
            print(f"  requiere: {detail}")
    return 0


def cmd_show(args: argparse.Namespace) -> int:
    cfg, _ = _load(args)
    tool = catalog.get_tool(args.tool_id)
    if not tool:
        _err(f"Herramienta no encontrada: {args.tool_id}")
        return 2
    state, detail = tool_state(tool, cfg)
    print(f"{tool.name}  [{tool.id}]")
    print("=" * min(72, len(tool.name) + len(tool.id) + 4))
    print(f"Categoría:  {tool.category} — {catalog.CATEGORIES.get(tool.category, ('', ''))[0]}")
    print(f"Tipos:      {', '.join(tool.kinds)}")
    print(f"Modo:       {tool.mode}")
    print(f"Pasiva:     {'sí' if tool.passive else 'no (requiere autorización)'}")
    print(f"Estado:     {state}" + (f" · {detail}" if detail else ""))
    print(f"Descripción: {tool.description}")
    if tool.keys:
        print("Claves:")
        for key in tool.keys:
            print(f"  - {key}: {'configurada' if cfg.has_key(key) else 'falta'}")
    if tool.bins:
        print("Binarios:")
        for binary in tool.bins:
            path = shutil.which(binary)
            print(f"  - {binary}: {path or 'no instalado'}")
    if tool.commands:
        print("Comandos:")
        for kind, command in tool.commands.items():
            print(f"  {kind}: {command}")
    if tool.url:
        print(f"URL: {tool.url}")
    if tool.tags:
        print(f"Etiquetas: {', '.join(tool.tags)}")
    hint = install_hint(tool)
    if hint:
        print(f"Instalación sugerida: {hint}")
    return 0


def cmd_doctor(args: argparse.Namespace) -> int:
    cfg, plugins = _load(args)
    enabled = _color_enabled(args)
    print(f"osintkit {VERSION} · Python {sys.version.split()[0]}")
    print(f"Config: {config_path()}")
    print(f"Informes: {reports_dir(cfg)}")
    print(f"Plugins: {', '.join(plugins) or '—'}")
    print("")

    binaries = sorted({binary for tool in catalog.TOOLS for binary in tool.bins})
    present = [binary for binary in binaries if shutil.which(binary)]
    missing = [binary for binary in binaries if not shutil.which(binary)]
    print(f"Binarios externos: {len(present)}/{len(binaries)} disponibles")
    if present:
        print("  ✓ " + ", ".join(present[:25]) + (" …" if len(present) > 25 else ""))
    if missing and args.verbose:
        print("  ✗ " + ", ".join(missing[:40]) + (" …" if len(missing) > 40 else ""))
    print("")

    known = sorted(set(KNOWN_KEYS) | set(cfg.keys))
    configured = [key for key in known if cfg.has_key(key)]
    print(f"Claves API: {len(configured)}/{len(known)} configuradas")
    for key in known:
        source = cfg.key_source(key)
        if source != "—":
            print(f"  ✓ {key:32} ({source})")
        elif args.verbose:
            print(f"  · {key:32} sin configurar")
    print("")

    endpoints = [
        ("DNS-over-HTTPS", "https://dns.google/resolve?name=example.com&type=A"),
        ("crt.sh", "https://crt.sh/?q=example.com&output=json"),
        ("NVD", "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2024-3094"),
        ("VirusTotal (sin clave)", "https://www.virustotal.com/api/v3/domains/example.com"),
        ("Internet Archive", "https://archive.org/advancedsearch.php?q=osint&rows=1&output=json"),
        ("Hacker News", "https://hn.algolia.com/api/v1/search?query=osint&hitsPerPage=1"),
        ("GitHub API", "https://api.github.com/rate_limit"),
    ]
    http = new_http(cfg, no_cache=True)
    http.timeout = 12
    print("Conectividad:")
    for name, url in endpoints:
        try:
            response = http.get(url, timeout=12, retries=0)
            status = response.status
            level = "ok" if response.ok else "warn"
            extra = f" ({response.elapsed:.2f}s)"
            if status in (401, 403) and "VirusTotal" in name:
                extra += " · esperado sin clave"
                level = "ok"
        except (NetworkError, Exception) as exc:  # noqa: BLE001
            status = "—"
            level = "bad"
            extra = f" ({truncate(str(exc), 90)})"
        marker = "✓" if level == "ok" else ("!" if level == "warn" else "✗")
        print(f"  {marker} {name:24} {status}{extra}")

    info = cache_info()
    print("")
    print(f"Caché: {info['files']} archivos · {human_bytes(info['bytes'])} · {cache_dir()}")
    return 0


def cmd_install(args: argparse.Namespace) -> int:
    cfg, _ = _load(args)
    hints: dict[str, list[str]] = {}
    for tool in catalog.TOOLS:
        if not tool.bins:
            continue
        missing = [binary for binary in tool.bins if not shutil.which(binary)]
        if not missing:
            continue
        hint = install_hint(tool)
        if not hint:
            hint = "sudo xbps-install -S " + " ".join(missing)
        hints.setdefault(hint, []).append(tool.id)
    if not hints:
        print("No falta ningún binario del catálogo. ✓")
        return 0
    print(f"Comandos para cubrir {sum(len(v) for v in hints.values())} herramientas:\n")
    for hint in sorted(hints):
        print(f"# {', '.join(hints[hint][:6])}" + (" …" if len(hints[hint]) > 6 else ""))
        print(hint)
        print("")
    if args.dry_run:
        print("(--dry-run: no se ejecutó nada)")
    return 0


def cmd_profiles(args: argparse.Namespace) -> int:
    for name, profile in catalog.PROFILES.items():
        tools = profile.get("tools", [])
        print(f"{name:14} {profile.get('name', '')}")
        print(f"  {profile.get('description', '')}")
        print(f"  tipos: {', '.join(profile.get('kinds', ()))} · {len(tools)} herramientas")
        print("")
    return 0


def cmd_catalog(args: argparse.Namespace) -> int:
    errors = catalog.validate_catalog()
    if errors:
        _err("El catálogo tiene errores:")
        for error in errors:
            _err(f"  - {error}")
        return 2
    if args.markdown:
        output = Path(args.markdown).expanduser()
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(catalog.catalog_markdown(), encoding="utf-8")
        print(f"Catálogo escrito en {output}")
        return 0
    if args.json:
        payload = [
            {
                "id": tool.id,
                "name": tool.name,
                "category": tool.category,
                "kinds": list(tool.kinds),
                "mode": tool.mode,
                "description": tool.description,
                "module": tool.module,
                "commands": tool.commands,
                "url": tool.url,
                "keys": list(tool.keys),
                "bins": list(tool.bins),
                "passive": tool.passive,
                "tags": list(tool.tags),
            }
            for tool in catalog.TOOLS
        ]
        print(json.dumps(payload, ensure_ascii=False, indent=2))
        return 0
    print(catalog.catalog_markdown())
    return 0


def cmd_config(args: argparse.Namespace) -> int:
    cfg, _ = _load(args)
    action = args.action or "show"
    if action == "init":
        path = cfg.ensure_file()
        print(f"Configuración creada en {path}")
        return 0
    if action == "path":
        print(cfg.path)
        return 0
    if action == "show":
        payload = {
            "path": str(cfg.path),
            "version": VERSION,
            "settings": cfg.settings,
            "keys": cfg.masked_keys(),
        }
        print(json.dumps(payload, ensure_ascii=False, indent=2))
        return 0
    if action == "set":
        if args.name is None or args.value is None:
            _err("Uso: osintkit config set NOMBRE VALOR")
            return 2
        try:
            value: Any = json.loads(args.value)
        except ValueError:
            value = args.value
        cfg.set(args.name, value)
        path = cfg.save()
        print(f"{args.name} = {value!r} · guardado en {path}")
        return 0
    if action == "set-key":
        if not args.name or args.value is None:
            _err("Uso: osintkit config set-key NOMBRE VALOR")
            return 2
        name = args.name.upper()
        cfg.set_key(name, args.value)
        cfg.save()
        os.chmod(cfg.path, 0o600)
        print(f"Clave {name} guardada en {cfg.path} (permisos 600)")
        return 0
    if action == "unset-key":
        if not args.name:
            _err("Uso: osintkit config unset-key NOMBRE")
            return 2
        name = args.name.upper()
        cfg.keys.pop(name, None)
        cfg.save()
        print(f"Clave {name} eliminada")
        return 0
    if action == "clear-cache":
        from .http import Cache

        count = Cache().clear()
        print(f"{count} archivos de caché eliminados")
        return 0
    _err(f"Acción desconocida: {action}")
    return 2


def cmd_tui(args: argparse.Namespace) -> int:
    cfg, _ = _load(args)
    try:
        from .ui import run_tui
    except Exception as exc:  # noqa: BLE001
        _err(f"No se pudo cargar la interfaz: {exc}")
        return 1
    try:
        return run_tui(cfg)
    except KeyboardInterrupt:
        return 130


def cmd_version(args: argparse.Namespace) -> int:
    print(f"{APP_NAME} {VERSION}")
    print(f"Python {sys.version.split()[0]}")
    print(f"Catálogo: {len(catalog.TOOLS)} herramientas · {len(catalog.CATEGORIES)} categorías")
    try:
        load_builtin_modules()
        print(f"Módulos internos: {len(MODULES)}")
    except Exception as exc:  # noqa: BLE001
        print(f"Módulos internos: error ({exc})")
    return 0


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

def _program_name() -> str:
    """Muestra el alias usado al abrir la ayuda (osintkit u osintol)."""
    name = Path(sys.argv[0]).name
    return name if name in {"osintkit", "osintol"} else "osintkit"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=_program_name(),
        description="Kit de OSINT para terminal: DNS, web, IP, email, usuarios, teléfono, "
                    "dispositivos, vehículos, cripto, organizaciones, amenazas, búsqueda "
                    "y archivos.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(
            """\
            Ejemplos:
              osintkit                              # abre la interfaz TUI
              osintol                               # alias equivalente
              osintkit scan example.com
              osintkit scan -i                     # asistente: tipo y perfil
              osintkit scan 1.1.1.1 -p ip
              osintkit scan usuario -k username --all
              osintkit scan usuario@gmail.com
              osintkit scan "ubuntu 24.04" -k device
              osintkit scan "android 14" -p device-deep
              osintkit scan "1234 ABC" -k plate --pais ES
              osintkit scan "1234ABC, Reino Unido" -p plate
              osintkit run plate_lookup "45-MF-HV" --pais NL
              osintkit run username_mass usuario
              osintkit run email_mass usuario@gmail.com
              osintkit run phone_sources "+34 600 123 456"
              osintkit run dns_records example.com
              osintkit list --kind domain --available
              osintkit search shodan
              osintkit doctor -v

            Ética: usa osintkit solo con autorización. Las herramientas activas
            se omiten salvo que las selecciones y confirmes.
            """
        ),
    )
    parser.add_argument("--config", help="ruta alternativa del archivo de configuración")
    parser.add_argument("--no-color", action="store_true", help="desactiva el color")
    parser.add_argument("--version", action="version", version=f"osintkit {VERSION}")
    sub = parser.add_subparsers(dest="command")

    scan = sub.add_parser("scan", help="escanea un objetivo con un perfil de herramientas")
    scan.add_argument("target", nargs="?", default="", help="dominio, IP, email, usuario, teléfono, dispositivo, placa, dirección, URL, hash, archivo o texto")
    scan.add_argument("-i", "--interactive", action="store_true", help="asistente para elegir tipo de objetivo y perfil")
    scan.add_argument("-k", "--kind", choices=catalog.ALL + ("auto",), default="auto", help="tipo de objetivo")
    scan.add_argument("-p", "--profile", help="perfil de escaneo (ver: osintkit profiles)")
    scan.add_argument(
        "--country",
        "--pais",
        dest="country",
        default="",
        metavar="PAÍS",
        help="país de la placa: código ISO o nombre (ES, MX, AR, UK, NL…)",
    )
    scan.add_argument("-t", "--tools", nargs="+", help="IDs de herramientas concretas")
    scan.add_argument("-c", "--category", help="filtra por categoría")
    scan.add_argument("--all", action="store_true", help="todas las herramientas del tipo (no solo el perfil)")
    scan.add_argument("--active", action="store_true", help="incluye herramientas activas (requiere autorización)")
    scan.add_argument("--yes", action="store_true", help="confirma la autorización sin preguntar")
    scan.add_argument("--no-cache", action="store_true", help="no usa la caché HTTP")
    scan.add_argument("--concurrency", type=int, help="número de hilos (por defecto: configuración)")
    scan.add_argument("-f", "--format", default="json,md,html", help="informes: json,md,html,none")
    scan.add_argument("--report-dir", help="directorio de informes")
    scan.add_argument("--dry-run", action="store_true", help="muestra las herramientas sin ejecutarlas")
    scan.add_argument("-q", "--quiet", action="store_true", help="solo informes, sin progreso")
    scan.set_defaults(func=cmd_scan)

    run = sub.add_parser("run", help="ejecuta una sola herramienta")
    run.add_argument("tool_id", help="ID de la herramienta (ver: osintkit list)")
    run.add_argument("target", help="objetivo")
    run.add_argument("-k", "--kind", choices=catalog.ALL + ("auto",), default="auto")
    run.add_argument(
        "--country",
        "--pais",
        dest="country",
        default="",
        metavar="PAÍS",
        help="país de la placa: código ISO o nombre",
    )
    run.add_argument("--yes", action="store_true", help="confirma la autorización")
    run.add_argument("--no-cache", action="store_true")
    run.add_argument("-f", "--format", default="json,md,html")
    run.add_argument("--report-dir")
    run.add_argument("-q", "--quiet", action="store_true")
    run.set_defaults(func=cmd_run)

    listing = sub.add_parser("list", help="lista el catálogo de herramientas")
    listing.add_argument("query", nargs="?", default="", help="texto a buscar")
    listing.add_argument("-k", "--kind", choices=catalog.ALL)
    listing.add_argument("-c", "--category", choices=list(catalog.CATEGORIES))
    listing.add_argument("--passive", action="store_true", help="solo pasivas")
    listing.add_argument("--available", action="store_true", help="solo listas para usar")
    listing.add_argument("--json", action="store_true")
    listing.set_defaults(func=cmd_list)

    search = sub.add_parser("search", help="busca herramientas por nombre, etiqueta o descripción")
    search.add_argument("query")
    search.add_argument("-k", "--kind", choices=catalog.ALL)
    search.set_defaults(func=cmd_search)

    show = sub.add_parser("show", help="muestra el detalle de una herramienta")
    show.add_argument("tool_id")
    show.set_defaults(func=cmd_show)

    doctor = sub.add_parser("doctor", help="diagnóstico de dependencias, claves y conectividad")
    doctor.add_argument("-v", "--verbose", action="store_true")
    doctor.set_defaults(func=cmd_doctor)

    install = sub.add_parser("install", help="sugiere comandos para instalar binarios faltantes")
    install.add_argument("--dry-run", action="store_true")
    install.set_defaults(func=cmd_install)

    profiles = sub.add_parser("profiles", help="lista los perfiles de escaneo")
    profiles.set_defaults(func=cmd_profiles)

    cat = sub.add_parser("catalog", help="muestra o valida el catálogo")
    cat.add_argument("--markdown", metavar="RUTA", help="escribe el catálogo en Markdown")
    cat.add_argument("--json", action="store_true")
    cat.set_defaults(func=cmd_catalog)

    config = sub.add_parser("config", help="gestiona la configuración y las claves API")
    config.add_argument(
        "action",
        nargs="?",
        default="show",
        choices=["show", "init", "path", "set", "set-key", "unset-key", "clear-cache"],
    )
    config.add_argument("name", nargs="?")
    config.add_argument("value", nargs="?")
    config.set_defaults(func=cmd_config)

    tui = sub.add_parser("tui", help="abre la interfaz de terminal")
    tui.set_defaults(func=cmd_tui)

    ver = sub.add_parser("version", help="muestra la versión")
    ver.set_defaults(func=cmd_version)

    return parser


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    # Permitir --no-color tanto antes como después del subcomando.
    if "--no-color" in argv:
        argv = ["--no-color"] + [item for item in argv if item != "--no-color"]
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        args = parser.parse_args(["tui"] + [item for item in argv if item != "--no-color"])
        args.no_color = "--no-color" in argv
    try:
        return int(args.func(args) or 0)
    except BrokenPipeError:
        return 0
    except SystemExit:
        raise
    except KeyboardInterrupt:
        _err("Interrumpido.")
        return 130
    except Exception as exc:  # noqa: BLE001
        if os.environ.get("OSINTKIT_DEBUG"):
            raise
        _err(f"Error: {type(exc).__name__}: {exc}")
        _err("Define OSINTKIT_DEBUG=1 para ver la traza completa.")
        return 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
