"""Interfaz de terminal (curses) para osintkit."""

from __future__ import annotations

import curses
import queue
import textwrap
import threading
from typing import Any

from . import catalog
from .config import KNOWN_KEYS, VERSION, Config
from .core import ScanResult, load_plugins, run_scan, summarize
from .report import write_reports
from .util import detect_kind, format_duration, normalize_target, truncate

# Colores de alto contraste. "muted" usa el color por defecto del terminal
# (39) en lugar de gris oscuro (90): así se lee bien sobre fondos claros y
# oscuros. Los estados usan variantes brillantes.
ANSI = {
    "info": "\033[96m",
    "good": "\033[92m",
    "warn": "\033[93m",
    "bad": "\033[91m",
    "link": "\033[95m",
    "ok": "\033[92m",
    "error": "\033[91m",
    "timeout": "\033[91m",
    "skipped": "\033[93m",
    "cancelled": "\033[93m",
    "title": "\033[1;96m",
    "site": "\033[1;92m",
    "value": "\033[97m",
    "url": "\033[4;96m",
    "muted": "\033[39m",
    "reset": "\033[0m",
}

# Tipos que se pueden elegir en la TUI y en el asistente de la CLI.
TARGET_TYPES: tuple[tuple[str, str, str], ...] = catalog.TARGET_TYPES


def colorize(text: str, level: str = "info") -> str:
    """Colorea texto para la CLI. La TUI usa atributos de curses."""
    code = ANSI.get(level)
    if not code:
        return text
    return f"{code}{text}{ANSI['reset']}"


BANNER = r"""
  ___  ___ ___ _  _ _____ _  _____
 / _ \/ __|_ _| \| |_   _| |/ /_ _|
| (_) \__ \| || .` | | | | ' < | |
 \___/|___/___|_|\_| |_| |_|\_\___|
"""


class _Screen:
    def __init__(self, stdscr: "curses.window", cfg: Config) -> None:
        self.stdscr = stdscr
        self.cfg = cfg
        self.height, self.width = stdscr.getmaxyx()
        self.pairs: dict[str, int] = {}

    def setup(self) -> None:
        curses.curs_set(0)
        try:
            curses.use_default_colors()
        except curses.error:
            pass
        try:
            self.stdscr.keypad(True)
        except curses.error:
            pass
        definitions = {
            "info": curses.COLOR_CYAN,
            "good": curses.COLOR_GREEN,
            "warn": curses.COLOR_YELLOW,
            "bad": curses.COLOR_RED,
            "link": curses.COLOR_MAGENTA,
            "title": curses.COLOR_CYAN,
            "site": curses.COLOR_GREEN,
            "url": curses.COLOR_CYAN,
        }
        for index, (name, color) in enumerate(definitions.items(), start=1):
            try:
                curses.init_pair(index, color, -1)
            except curses.error:
                pass
            self.pairs[name] = curses.color_pair(index)
        # Sin pareja de color: usa el color de texto normal del terminal.
        self.pairs["muted"] = 0
        self.pairs["value"] = 0

    def attr(self, level: str) -> int:
        base = self.pairs.get(level, 0)
        if level in ("title", "site"):
            return base | curses.A_BOLD
        if level == "url":
            return base | curses.A_UNDERLINE
        # Nunca A_DIM: en muchas terminales convierte el texto en gris ilegible.
        return base

    def refresh_size(self) -> None:
        self.height, self.width = self.stdscr.getmaxyx()

    def put(self, y: int, x: int, text: str, level: str = "info", *, bold: bool = False) -> None:
        if y < 0 or x < 0 or y >= self.height or x >= self.width:
            return
        text = text[: max(0, self.width - x - 1)]
        attribute = self.attr(level)
        if bold:
            attribute |= curses.A_BOLD
        try:
            self.stdscr.addstr(y, x, text, attribute)
        except curses.error:
            pass

    def line(self, y: int, char: str = "─", level: str = "muted") -> None:
        self.put(y, 0, char * (self.width - 1), level)

    def clear(self) -> None:
        self.stdscr.erase()

    def header(self, subtitle: str = "") -> int:
        self.clear()
        self.put(0, 0, " OSINTKIT ", "title", bold=True)
        self.put(0, 10, f"v{VERSION}", "muted")
        if subtitle:
            self.put(0, 20, truncate(subtitle, self.width - 22), "muted")
        self.line(1)
        return 2

    def footer(self, keys: list[tuple[str, str]]) -> None:
        y = self.height - 1
        x = 0
        self.line(y - 1)
        for key, label in keys:
            text = f" {key} "
            if x + len(text) + len(label) + 2 >= self.width:
                break
            self.put(y, x, text, "title", bold=True)
            x += len(text)
            self.put(y, x, label + "  ", "muted")
            x += len(label) + 2

    def prompt(self, y: int, label: str, value: str = "") -> str:
        curses.curs_set(1)
        self.put(y, 2, label)
        self.put(y, 2 + len(label) + 1, value)
        self.stdscr.refresh()
        try:
            curses.echo()
            raw = self.stdscr.getstr(y, 2 + len(label) + 1, max(1, self.width - 8))
            return raw.decode("utf-8", errors="replace").strip()
        finally:
            curses.noecho()
            curses.curs_set(0)

    def message(self, text: str, level: str = "info", wait: bool = True) -> None:
        self.put(self.height - 2, 1, truncate(text, self.width - 2), level)
        self.stdscr.refresh()
        if wait:
            self.stdscr.getch()


class _App:
    def __init__(self, stdscr: "curses.window", cfg: Config) -> None:
        self.screen = _Screen(stdscr, cfg)
        self.cfg = cfg
        self.section = "menu"
        self.menu_index = 0
        self.catalog_index = 0
        self.catalog_scroll = 0
        self.result_scroll = 0
        self.results: ScanResult | None = None
        self.result_lines: list[list[tuple[str, str]]] = []
        self.scan_thread: threading.Thread | None = None
        self.events: queue.Queue[tuple[str, dict[str, Any]]] = queue.Queue()
        self.progress: list[str] = []
        self.scan_target = ""
        self.scan_kind = ""
        self.scan_profile = ""
        self.scan_step = "kind"  # kind | target | profile
        self.kind_index = 0
        self.profile_options: list[str] = []
        self.profile_index = 0
        self.include_active = False
        self.cancel_event: threading.Event | None = None
        self.plugins = load_plugins(cfg)
        self.menu = [
            ("Escanear objetivo", "Reconocimiento guiado por perfil"),
            ("Catálogo de herramientas", f"{len(catalog.TOOLS)} capacidades en {len(catalog.CATEGORIES)} categorías"),
            ("Perfiles", "Combinaciones predefinidas de herramientas"),
            ("Estado y claves", "Dependencias, API keys y caché"),
            ("Ayuda y ética", "Cómo usar osintkit de forma responsable"),
            ("Salir", ""),
        ]

    # ------------------------------------------------------------------
    # Bucle principal
    # ------------------------------------------------------------------
    def run(self) -> int:
        self.screen.setup()
        while True:
            if self.section == "menu":
                self.draw_menu()
                key = self.screen.stdscr.getch()
                self.handle_menu(key)
            elif self.section == "scan":
                self.draw_scan()
                if self.section == "results":
                    continue
                if self.running:
                    # Refrescar progreso sin exigir que el usuario pulse una tecla.
                    self.screen.stdscr.timeout(150)
                key = self.screen.stdscr.getch()
                self.screen.stdscr.timeout(-1)
                if key == -1:
                    continue
                if self.running:
                    self.handle_running(key)
                else:
                    self.handle_scan(key)
            elif self.section == "results":
                self.draw_results()
                if self.handle_results(self.screen.stdscr.getch()):
                    return 0
            elif self.section == "catalog":
                self.draw_catalog()
                self.handle_catalog(self.screen.stdscr.getch())
            elif self.section == "profiles":
                self.draw_profiles()
                if self.screen.stdscr.getch() in (27, ord("q")):
                    self.section = "menu"
            elif self.section == "status":
                self.draw_status()
                if self.screen.stdscr.getch() in (27, ord("q")):
                    self.section = "menu"
            elif self.section == "help":
                self.draw_help()
                if self.screen.stdscr.getch() in (27, ord("q")):
                    self.section = "menu"
            elif self.section == "detail":
                self.draw_detail()
                if self.screen.stdscr.getch() in (27, ord("q")):
                    self.section = "catalog"

    @property
    def running(self) -> bool:
        return self.scan_thread is not None and self.scan_thread.is_alive()

    # ------------------------------------------------------------------
    # Menú
    # ------------------------------------------------------------------
    def draw_menu(self) -> None:
        screen = self.screen
        y = screen.header("reconocimiento OSINT en una sola terminal")
        for offset, line in enumerate(BANNER.strip("\n").splitlines()):
            if y + offset < screen.height - 10:
                screen.put(y + offset, 2, line, "title")
        y += 7
        screen.put(y, 2, "Menú", "title", bold=True)
        y += 1
        for index, (label, description) in enumerate(self.menu):
            selected = index == self.menu_index
            pointer = "▸" if selected else " "
            level = "good" if selected else "info"
            screen.put(y + index, 2, f"{pointer} {label}", level, bold=selected)
            if description:
                screen.put(y + index, 36, truncate(description, screen.width - 38), "muted")
        y += len(self.menu) + 1
        info = [
            f"Objetivos admitidos: {', '.join(catalog.ALL)}",
            f"Plugins: {', '.join(self.plugins) or 'ninguno'}",
            "Todo se ejecuta en local; las consultas salen a APIs públicas.",
        ]
        for offset, text in enumerate(info):
            if y + offset < screen.height - 3:
                screen.put(y + offset, 2, text, "muted")
        screen.footer([("↑↓", "mover"), ("Enter", "abrir"), ("q", "salir")])
        screen.stdscr.refresh()

    def handle_menu(self, key: int) -> None:
        if key in (curses.KEY_UP, ord("k")):
            self.menu_index = (self.menu_index - 1) % len(self.menu)
        elif key in (curses.KEY_DOWN, ord("j")):
            self.menu_index = (self.menu_index + 1) % len(self.menu)
        elif key in (10, 13, curses.KEY_ENTER):
            index = self.menu_index
            if index == 0:
                self.section = "scan"
                self.results = None
                self.progress = []
                self.scan_target = ""
                self.scan_kind = ""
                self.scan_profile = ""
                self.scan_step = "kind"
                self.include_active = False
                self.kind_index = 0
            elif index == 1:
                self.section = "catalog"
            elif index == 2:
                self.section = "profiles"
            elif index == 3:
                self.section = "status"
            elif index == 4:
                self.section = "help"
            else:
                raise SystemExit(0)
        elif key in (ord("q"), 27):
            raise SystemExit(0)

    # ------------------------------------------------------------------
    # Escaneo
    # ------------------------------------------------------------------
    def _type_label(self, kind: str) -> str:
        for value, label, _description in TARGET_TYPES:
            if value == kind:
                return label
        return kind

    def _type_example(self, kind: str) -> str:
        for value, _label, description in TARGET_TYPES:
            if value == kind:
                return description
        return ""

    def _refresh_profile_options(self) -> None:
        self.profile_options = ["auto"] + catalog.profiles_for_kind(self.scan_kind)
        self.profile_index = 0

    def _ask_target(self) -> bool:
        """Pide el objetivo y prepara la elección de profundidad."""
        screen = self.screen
        chosen = TARGET_TYPES[self.kind_index][0]
        label = self._type_label(chosen)
        example = self._type_example(chosen)
        screen.clear()
        screen.header("nuevo escaneo · escribe el objetivo")
        screen.put(3, 2, f"Tipo elegido: {label}", "title", bold=True)
        if example:
            screen.put(4, 2, f"Ejemplo: {example}", "muted")
        screen.put(6, 2, "Objetivo (Enter para continuar, Esc para cancelar):", "info")
        screen.stdscr.refresh()
        value = screen.prompt(8, "Objetivo:")
        if not value:
            return False
        target = normalize_target(value)
        if chosen == "auto":
            kind = detect_kind(target)
        else:
            kind = chosen
        self.scan_target = target
        self.scan_kind = kind
        self.scan_profile = catalog.resolve_profile(None, kind)
        self.include_active = False
        self._refresh_profile_options()
        self.scan_step = "profile"
        return True

    def draw_scan(self) -> None:
        screen = self.screen
        # Drenar eventos aunque el hilo ya haya terminado: si no, el resultado
        # se queda en la cola y la pantalla vuelve al formulario.
        if not self.events.empty():
            self._drain_events()
        if self.section == "results":
            self.draw_results()
            return
        if self.running:
            self.draw_running()
            return
        if self.results is not None:
            y = screen.header("último escaneo completado")
            screen.put(y + 1, 2, summarize(self.results), "good", bold=True)
            screen.put(y + 3, 2, "Enter para ver el informe · r para repetir · e para nuevo objetivo", "info")
            screen.footer([("Enter", "resultados"), ("r", "repetir"), ("e", "objetivo"), ("Esc", "volver")])
            screen.stdscr.refresh()
            return
        if self.scan_step == "profile":
            self.draw_scan_profile()
            return
        self.draw_scan_kind()

    def draw_scan_kind(self) -> None:
        screen = self.screen
        y = screen.header("paso 1 de 2 · ¿qué quieres investigar?")
        screen.put(y, 2, "Elige el tipo de objetivo", "title", bold=True)
        start = y + 2
        for index, (_kind, label, description) in enumerate(TARGET_TYPES):
            row = start + index
            if row >= screen.height - 3:
                break
            selected = index == self.kind_index
            pointer = "▸" if selected else " "
            level = "good" if selected else "info"
            screen.put(row, 2, f"{pointer} {label}", level, bold=selected)
            if screen.width > 48:
                screen.put(row, 34, truncate(description, screen.width - 36), "muted")
        hint = start + len(TARGET_TYPES) + 1
        if hint < screen.height - 2:
            screen.put(hint, 2, "↑↓ para elegir · Enter para escribir el objetivo · Esc para volver", "info")
        screen.footer([("↑↓", "tipo"), ("Enter", "elegir"), ("Esc", "volver")])
        screen.stdscr.refresh()

    def draw_scan_profile(self) -> None:
        screen = self.screen
        y = screen.header("paso 2 de 2 · profundidad del escaneo")
        screen.put(y, 2, f"Objetivo: {self.scan_target}", "good", bold=True)
        screen.put(y + 1, 2, f"Tipo: {self._type_label(self.scan_kind)} ({self.scan_kind})", "info")
        screen.put(y + 3, 2, "Elige el perfil", "title", bold=True)
        start = y + 4
        for index, name in enumerate(self.profile_options):
            row = start + index
            if row >= screen.height - 5:
                break
            selected = index == self.profile_index
            pointer = "▸" if selected else " "
            level = "good" if selected else "info"
            if name == "auto":
                label = "Automático (recomendado)"
                description = "solo técnicas pasivas"
                active = False
            else:
                profile = catalog.PROFILES.get(name, {})
                label = str(profile.get("name", name))
                description = str(profile.get("description", ""))
                active = catalog.profile_has_active(name, self.scan_kind)
            suffix = " · ACTIVO" if active else ""
            screen.put(row, 2, f"{pointer} {label}{suffix}", level, bold=selected)
            if screen.width > 58:
                screen.put(row, 42, truncate(description, screen.width - 44), "muted")
        row = start + len(self.profile_options) + 1
        if row < screen.height - 3:
            active_state = "sí, autorizadas" if self.include_active else "no (solo pasivo)"
            level = "warn" if self.include_active else "info"
            screen.put(row, 2, f"Técnicas activas: {active_state}", level, bold=self.include_active)
            screen.put(row + 1, 2, "a cambia la autorización · e cambia el objetivo · b cambia el tipo", "muted")
        screen.footer([("↑↓", "perfil"), ("Enter", "escanear"), ("a", "activas"), ("e", "objetivo"), ("b", "tipo"), ("Esc", "atrás")])
        screen.stdscr.refresh()

    def handle_scan(self, key: int) -> None:
        if self.section == "results":
            self.handle_results(key)
            return
        if self.results is not None:
            if key in (10, 13, curses.KEY_ENTER):
                self.section = "results"
                self.result_scroll = 0
            elif key == ord("r"):
                self.start_scan()
            elif key == ord("e"):
                self.results = None
                self.scan_step = "kind"
                self.kind_index = 0
            elif key in (27, ord("q")):
                self.section = "menu"
            return

        if self.scan_step == "kind":
            if key in (27, ord("q")):
                self.section = "menu"
            elif key in (curses.KEY_UP, ord("k")):
                self.kind_index = (self.kind_index - 1) % len(TARGET_TYPES)
            elif key in (curses.KEY_DOWN, ord("j")):
                self.kind_index = (self.kind_index + 1) % len(TARGET_TYPES)
            elif key in (10, 13, curses.KEY_ENTER):
                self._ask_target()
            return

        # Paso de perfil
        if key in (27, ord("b")):
            self.scan_step = "kind"
        elif key in (curses.KEY_UP, ord("k")):
            self.profile_index = (self.profile_index - 1) % max(1, len(self.profile_options))
        elif key in (curses.KEY_DOWN, ord("j")):
            self.profile_index = (self.profile_index + 1) % max(1, len(self.profile_options))
        elif key in (10, 13, curses.KEY_ENTER):
            self.start_scan()
        elif key == ord("e"):
            self._ask_target()
        elif key == ord("a"):
            self.include_active = not self.include_active
        elif key == ord("q"):
            self.section = "menu"


    def start_scan(self) -> None:
        target = normalize_target(self.scan_target)
        if not target:
            self.screen.message("Escribe un objetivo primero.", "warn")
            return
        kind = self.scan_kind or detect_kind(target)
        selected = (
            self.profile_options[self.profile_index]
            if self.profile_options and 0 <= self.profile_index < len(self.profile_options)
            else "auto"
        )
        profile = catalog.resolve_profile(None if selected == "auto" else selected, kind)
        all_tools = catalog.profile_tools(profile, kind) or catalog.tools_for_kind(kind)
        active_count = sum(1 for tool in all_tools if not tool.passive)
        tools = all_tools if self.include_active else [tool for tool in all_tools if tool.passive]
        if not tools:
            if active_count:
                self.screen.message(
                    "Ese perfil solo tiene técnicas activas. Pulsa «a» para autorizarlas.",
                    "warn",
                )
            else:
                self.screen.message("No hay herramientas para ese perfil.", "warn")
            return
        self.scan_target = target
        self.scan_kind = kind
        self.scan_profile = profile
        self.results = None
        self.result_lines = []
        active_text = "sí" if self.include_active and active_count else "no (solo pasivo)"
        self.progress = [
            f"Objetivo: {target}",
            f"Tipo: {self._type_label(kind)} ({kind}) · perfil: {profile}",
            f"{len(tools)} herramientas · técnicas activas: {active_text}",
            "",
        ]
        self.events = queue.Queue()
        self.cancel_event = threading.Event()

        def worker() -> None:
            try:
                scan = run_scan(
                    tools,
                    target,
                    kind,
                    self.cfg,
                    profile=profile,
                    cancel=self.cancel_event,
                    on_event=lambda event, payload: self.events.put((event, payload)),
                )
                self.events.put(("scan", {"scan": scan}))
            except Exception as exc:  # noqa: BLE001
                self.events.put(("error", {"message": f"{type(exc).__name__}: {exc}"}))

        self.scan_thread = threading.Thread(target=worker, daemon=True, name="osintkit-tui-scan")
        self.scan_thread.start()

    def _drain_events(self) -> None:
        while True:
            try:
                event, payload = self.events.get_nowait()
            except queue.Empty:
                break
            if event == "start":
                self.progress.append(f"→ {payload.get('name') or payload.get('tool')}")
            elif event == "done":
                status = str(payload.get("status") or "")
                marker = {"ok": "✓", "error": "✗", "skipped": "·", "timeout": "⏱", "cancelled": "×"}.get(status, "?")
                count = payload.get("count", 0)
                self.progress.append(f"  {marker} {payload.get('name') or payload.get('tool')} ({count})")
            elif event == "scan":
                self.results = payload.get("scan")
                self._build_result_lines()
                self.result_scroll = 0
                self.progress.append("")
                self.progress.append("Escaneo completado. Abriendo informe…")
                # Mostrar el informe automáticamente al terminar.
                self.section = "results"
            elif event == "error":
                self.progress.append(f"✗ {payload.get('message')}")

    def draw_running(self) -> None:
        screen = self.screen
        self._drain_events()
        if self.section == "results":
            self.draw_results()
            return
        y = screen.header(f"escaneando {self.scan_target}")
        visible = max(1, screen.height - y - 4)
        lines = self.progress[-visible:]
        for offset, line in enumerate(lines):
            level = "muted"
            if line.startswith("  ✓"):
                level = "good"
            elif line.startswith("  ✗"):
                level = "bad"
            elif line.startswith("  ·"):
                level = "warn"
            elif line.startswith("→"):
                level = "info"
            screen.put(y + offset, 2, truncate(line, screen.width - 4), level)
        if self.results is None and not self.running:
            screen.put(screen.height - 3, 2, "Pulsa Enter para ver los resultados.", "good")
        screen.footer([("Esc", "cancelar"), ("Enter", "resultados")])
        screen.stdscr.refresh()

    def handle_running(self, key: int) -> None:
        if self.section == "results":
            self.handle_results(key)
            return
        if key == 27 and self.cancel_event is not None:
            self.cancel_event.set()
            self.progress.append("Cancelando…")
        elif key in (10, 13, curses.KEY_ENTER):
            if self.results is not None:
                self.section = "results"
                self.result_scroll = 0

    # ------------------------------------------------------------------
    # Resultados
    # ------------------------------------------------------------------
    def _build_result_lines(self) -> None:
        lines: list[list[tuple[str, str]]] = []
        scan = self.results
        if not scan:
            self.result_lines = lines
            return
        for result in scan.results:
            if result.status == "ok" and not result.findings:
                continue
            level = {
                "ok": "good", "error": "bad", "timeout": "bad",
                "skipped": "warn", "cancelled": "warn",
            }.get(result.status, "info")
            header = f"[{result.status}] {result.name} ({result.count})"
            lines.append([(header, level)])
            if result.error:
                lines.append([(f"  ! {result.error}", "bad")])
            if result.skipped_reason:
                lines.append([(f"  · {result.skipped_reason}", "warn")])
            for finding in result.findings:
                marker = {"good": "✓", "warn": "!", "bad": "✗", "link": "→"}.get(finding.level, "·")
                if finding.url:
                    # Nombre del sitio, detalle y URL con colores distintos.
                    segments = [(f"  {marker} ", finding.level), (finding.title, "site")]
                    if (
                        finding.value
                        and finding.value != finding.title
                        and finding.value != finding.url
                    ):
                        segments.append((" — ", "muted"))
                        segments.append((finding.value, "value"))
                    lines.append(segments)
                    lines.append([("     ", "muted"), (finding.url, "url")])
                else:
                    value = f" — {finding.value}" if finding.value else ""
                    lines.append([(f"  {finding.title}{value}", finding.level)])
            lines.append([])
        self.result_lines = lines

    def draw_results(self) -> None:
        screen = self.screen
        scan = self.results
        y = screen.header(f"informe · {scan.target}" if scan else "informe")
        if scan:
            screen.put(y, 2, summarize(scan), "good", bold=True)
            screen.put(
                y + 1,
                2,
                f"Tipo: {self._type_label(scan.kind)} ({scan.kind}) · perfil: {scan.profile or '—'}",
                "info",
            )
            y += 3
        visible = max(1, screen.height - y - 2)
        total = len(self.result_lines)
        self.result_scroll = max(0, min(self.result_scroll, max(0, total - 1)))
        if not total:
            screen.put(y, 2, "Sin hallazgos que mostrar. Pulsa s para guardar el informe.", "info")
        for offset in range(visible):
            index = self.result_scroll + offset
            if index >= total:
                break
            x = 1
            for text, level in self.result_lines[index]:
                if x >= screen.width - 1:
                    break
                text = text[: max(0, screen.width - x - 1)]
                screen.put(y + offset, x, text, level)
                x += len(text)
        if total:
            percent = int(100 * (self.result_scroll + visible) / total)
            screen.put(screen.height - 2, max(0, screen.width - 8), f"{min(100, percent):3d}%", "muted")
        screen.footer([("↑↓", "mover"), ("g/G", "inicio/fin"), ("s", "guardar"), ("Esc", "menú")])
        screen.stdscr.refresh()

    def handle_results(self, key: int) -> bool:
        if key in (27, ord("q")):
            self.section = "menu"
        elif key in (curses.KEY_UP, ord("k")):
            self.result_scroll = max(0, self.result_scroll - 1)
        elif key in (curses.KEY_DOWN, ord("j")):
            self.result_scroll = min(max(0, len(self.result_lines) - 1), self.result_scroll + 1)
        elif key == curses.KEY_PPAGE:
            self.result_scroll = max(0, self.result_scroll - max(1, self.screen.height - 5))
        elif key == curses.KEY_NPAGE:
            self.result_scroll = min(
                max(0, len(self.result_lines) - 1),
                self.result_scroll + max(1, self.screen.height - 5),
            )
        elif key == ord("g"):
            self.result_scroll = 0
        elif key == ord("G"):
            self.result_scroll = max(0, len(self.result_lines) - 1)
        elif key == ord("s") and self.results:
            paths = write_reports(self.results)
            self.screen.message("Guardado: " + " · ".join(str(p) for p in paths), "good")
        return False

    # ------------------------------------------------------------------
    # Catálogo
    # ------------------------------------------------------------------
    def draw_catalog(self) -> None:
        screen = self.screen
        y = screen.header(f"catálogo · {len(catalog.TOOLS)} herramientas")
        visible = screen.height - y - 2
        tools = catalog.TOOLS
        if self.catalog_index < self.catalog_scroll:
            self.catalog_scroll = self.catalog_index
        if self.catalog_index >= self.catalog_scroll + visible:
            self.catalog_scroll = self.catalog_index - visible + 1
        for offset in range(visible):
            index = self.catalog_scroll + offset
            if index >= len(tools):
                break
            tool = tools[index]
            selected = index == self.catalog_index
            level = "good" if selected else "info"
            pointer = "▸" if selected else " "
            name = truncate(tool.name, 28)
            screen.put(y + offset, 1, f"{pointer} {tool.id:28} {name:30}", level, bold=selected)
            state = "✓" if tool.module else ("⚙" if tool.commands else "↗")
            screen.put(y + offset, screen.width - 20, f"{tool.category:10} {state}", "muted")
        tool = tools[self.catalog_index]
        screen.footer([("↑↓", "mover"), ("Enter", "detalle"), ("Esc", "menú")])
        screen.stdscr.refresh()

    def handle_catalog(self, key: int) -> None:
        if key in (27, ord("q")):
            self.section = "menu"
        elif key in (curses.KEY_UP, ord("k")):
            self.catalog_index = max(0, self.catalog_index - 1)
        elif key in (curses.KEY_DOWN, ord("j")):
            self.catalog_index = min(len(catalog.TOOLS) - 1, self.catalog_index + 1)
        elif key == curses.KEY_PPAGE:
            self.catalog_index = max(0, self.catalog_index - max(1, self.screen.height - 5))
        elif key == curses.KEY_NPAGE:
            self.catalog_index = min(
                len(catalog.TOOLS) - 1, self.catalog_index + max(1, self.screen.height - 5)
            )
        elif key in (10, 13, curses.KEY_ENTER):
            self.section = "detail"

    def draw_detail(self) -> None:
        screen = self.screen
        tool = catalog.TOOLS[self.catalog_index]
        y = screen.header(tool.id)
        lines = [
            (tool.name, "title"),
            ("", "info"),
            (f"Categoría: {tool.category} — {catalog.CATEGORIES.get(tool.category, ('', ''))[0]}", "info"),
            (f"Tipos: {', '.join(tool.kinds)}", "info"),
            (f"Modo: {tool.mode} · {'pasiva' if tool.passive else 'ACTIVA (requiere autorización)'}", "good" if tool.passive else "warn"),
            ("", "info"),
        ]
        for line in textwrap.wrap(tool.description, max(20, screen.width - 6)):
            lines.append((line, "info"))
        lines.append(("", "info"))
        if tool.keys:
            lines.append(("Claves API:", "title"))
            for key in tool.keys:
                lines.append((f"  {key}: {'configurada' if self.cfg.has_key(key) else 'falta'}", "good" if self.cfg.has_key(key) else "warn"))
        if tool.bins:
            import shutil

            lines.append(("Binarios:", "title"))
            for binary in tool.bins:
                path = shutil.which(binary)
                lines.append((f"  {binary}: {path or 'no instalado'}", "info" if path else "warn"))
        if tool.commands:
            lines.append(("Comandos:", "title"))
            for kind, command in tool.commands.items():
                lines.append((f"  {kind}: {command}", "info"))
        if tool.url:
            lines.append((f"URL: {tool.url}", "link"))
        if tool.tags:
            lines.append((f"Etiquetas: {', '.join(tool.tags)}", "muted"))
        for offset, (text, level) in enumerate(lines[: screen.height - y - 2]):
            screen.put(y + offset, 2, truncate(text, screen.width - 3), level)
        screen.footer([("Esc", "volver"), ("q", "menú")])
        screen.stdscr.refresh()

    # ------------------------------------------------------------------
    # Pantallas informativas
    # ------------------------------------------------------------------
    def draw_profiles(self) -> None:
        screen = self.screen
        y = screen.header("perfiles de escaneo")
        offset = 0
        for name, profile in catalog.PROFILES.items():
            if y + offset >= screen.height - 2:
                break
            screen.put(y + offset, 2, f"{name:14} {profile.get('name', '')}", "title")
            offset += 1
            screen.put(y + offset, 4, truncate(str(profile.get("description", "")), screen.width - 6), "muted")
            offset += 1
            screen.put(
                y + offset,
                4,
                f"tipos: {', '.join(profile.get('kinds', ()))} · {len(profile.get('tools', []))} herramientas",
                "info",
            )
            offset += 2
        screen.footer([("Esc", "volver")])
        screen.stdscr.refresh()

    def draw_status(self) -> None:
        screen = self.screen
        y = screen.header("estado del sistema")
        import shutil

        binaries = sorted({binary for tool in catalog.TOOLS for binary in tool.bins})
        present = [binary for binary in binaries if shutil.which(binary)]
        known = sorted(set(KNOWN_KEYS) | set(self.cfg.keys))
        configured = [key for key in known if self.cfg.has_key(key)]
        lines = [
            (f"Python: {__import__('sys').version.split()[0]}", "info"),
            (f"Config: {self.cfg.path}", "info"),
            (f"Binarios: {len(present)}/{len(binaries)}", "good" if present else "warn"),
            (f"Claves API: {len(configured)}/{len(known)}", "good" if configured else "warn"),
            (f"Plugins: {', '.join(self.plugins) or 'ninguno'}", "info"),
            ("", "info"),
            ("Claves configuradas:", "title"),
        ]
        for key in known:
            source = self.cfg.key_source(key)
            if source != "—":
                lines.append((f"  ✓ {key} ({source})", "good"))
        if not configured:
            lines.append(("  ninguna; usa `osintkit config set-key NOMBRE VALOR`", "warn"))
        lines.append(("", "info"))
        lines.append(("Binarios disponibles:", "title"))
        for binary in present:
            lines.append((f"  ✓ {binary} — {shutil.which(binary)}", "good"))
        for offset, (text, level) in enumerate(lines[: screen.height - y - 2]):
            screen.put(y + offset, 2, truncate(text, screen.width - 3), level)
        screen.footer([("Esc", "volver")])
        screen.stdscr.refresh()

    def draw_help(self) -> None:
        screen = self.screen
        y = screen.header("ayuda y ética")
        lines = [
            ("Qué hace osintkit", "title"),
            ("Agrupa decenas de fuentes OSINT pasivas en una sola interfaz: DNS, certificados,",
             "info"),
            ("WHOIS/RDAP, HTTP/TLS, reputación de IP, emails, usuarios, teléfonos, cripto,",
             "info"),
            ("organizaciones, CVEs, malware, buscadores y metadatos de archivos.", "info"),
            ("", "info"),
            ("Límites importantes", "title"),
            ("· Los datos de terceros pueden ser inexactos o estar desactualizados.", "info"),
            ("· Sin API key, algunos servicios limitan o bloquean las consultas.", "info"),
            ("· Las herramientas activas (nmap, nuclei, ffuf…) solo se ejecutan si las", "info"),
            ("  seleccionas y confirmas autorización.", "info"),
            ("", "info"),
            ("Ética y legalidad", "title"),
            ("Usa osintkit únicamente sobre sistemas y datos para los que tengas autorización.",
             "warn"),
            ("El reconocimiento no autorizado puede ser ilegal. Respeta la privacidad y las", "warn"),
            ("condiciones de servicio de cada fuente.", "warn"),
            ("", "info"),
            ("CLI", "title"),
            ("osintkit scan dominio.com     osintkit list --kind ip", "muted"),
            ("osintkit run ip_geo 1.1.1.1  osintkit doctor -v", "muted"),
        ]
        for offset, (text, level) in enumerate(lines[: screen.height - y - 2]):
            screen.put(y + offset, 2, truncate(text, screen.width - 3), level)
        screen.footer([("Esc", "volver")])
        screen.stdscr.refresh()


def run_tui(cfg: Config | None = None) -> int:
    import sys

    if not sys.stdout.isatty():
        print("La interfaz TUI necesita una terminal interactiva.")
        print("Prueba: osintkit scan example.com")
        return 1
    cfg = cfg or Config()
    try:
        curses.wrapper(lambda stdscr: _App(stdscr, cfg).run())
    except KeyboardInterrupt:
        return 130
    return 0
