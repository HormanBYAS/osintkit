"""Generación de informes en JSON, Markdown y HTML."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable

from .catalog import BY_ID
from .config import reports_dir
from .core import Finding, ScanResult, summarize
from .summary import final_findings
from .util import format_duration, html_escape, iso_now, slugify

FORMATS = ("json", "md", "html")

LEVEL_LABELS = {
    "info": "Info",
    "good": "OK",
    "warn": "Aviso",
    "bad": "Riesgo",
    "link": "Enlace",
}


def report_basename(scan: ScanResult) -> str:
    stamp = (scan.started_at or iso_now()).replace(":", "").replace("-", "")[:15]
    return f"osintkit_{scan.kind}_{slugify(scan.target, 50)}_{stamp}"


def render_json(scan: ScanResult) -> str:
    payload = scan.as_dict()
    payload["generated_by"] = "osintkit"
    payload["summary_text"] = summarize(scan)
    payload["final_summary"] = [finding.as_dict() for finding in final_findings(scan)]
    return json.dumps(payload, ensure_ascii=False, indent=2) + "\n"


def _tool_title(result: Any) -> str:
    tool = BY_ID.get(result.tool_id)
    if tool:
        return f"{tool.name} (`{tool.id}`)"
    return f"{result.name} (`{result.tool_id}`)"


def _markdown_finding(finding: Finding) -> str:
    prefix = f"**[{LEVEL_LABELS.get(finding.level, finding.level)}]**"
    title = finding.title
    value = finding.value
    if finding.url:
        title = f"[{title}]({finding.url})"
    line = f"- {prefix} {title}"
    if value:
        line += f" — {value}"
    return line


def render_markdown(scan: ScanResult) -> str:
    lines = [
        f"# Informe OSINT · {scan.target}",
        "",
        f"- **Tipo de objetivo:** `{scan.kind}`",
        f"- **Perfil:** `{scan.profile or '—'}`",
        f"- **Inicio:** {scan.started_at}",
        f"- **Fin:** {scan.finished_at or '—'}",
        f"- **Duración:** {format_duration(scan.duration)}",
        f"- **Resumen:** {summarize(scan)}",
        "",
        "## Resumen por herramienta",
        "",
        "| Herramienta | Estado | Hallazgos | Duración |",
        "|---|---|---:|---:|",
    ]
    for result in scan.results:
        lines.append(
            f"| {_tool_title(result)} | `{result.status}` | {result.count} | "
            f"{format_duration(result.duration)} |"
        )
    lines.append("")

    for result in scan.results:
        if not result.findings and result.status == "ok":
            continue
        lines += [
            f"## {_tool_title(result)}",
            "",
            f"Estado: **{result.status}**"
            + (f" · {result.error}" if result.error else "")
            + (f" · {result.skipped_reason}" if result.skipped_reason else ""),
            "",
        ]
        if not result.findings:
            lines += ["_Sin hallazgos._", ""]
            continue
        for finding in result.findings:
            lines.append(_markdown_finding(finding))
        lines.append("")

    lines += ["## Resumen final", ""]
    for finding in final_findings(scan):
        lines.append(_markdown_finding(finding))
    lines.append("")

    lines += [
        "---",
        "",
        "_Generado por osintkit. Los datos provienen de terceros y pueden ser "
        "inexactos. Úsalo solo con autorización y fines legítimos._",
        "",
    ]
    return "\n".join(lines)


def _html_finding_items(findings: Iterable[Finding]) -> list[str]:
    items: list[str] = []
    for finding in findings:
        level = html_escape(finding.level)
        title = html_escape(finding.title)
        if finding.url:
            title = (
                f'<a href="{html_escape(finding.url)}" rel="noopener noreferrer">'
                f"{title}</a>"
            )
        value = html_escape(finding.value)
        items.append(
            f'<li class="finding {level}"><span class="dot"></span>'
            f'<div><strong>{title}</strong>'
            + (f"<p>{value}</p>" if value else "")
            + "</div></li>"
        )
    return items


def render_html(scan: ScanResult) -> str:
    rows: list[str] = []
    for result in scan.results:
        badge = {
            "ok": "ok", "error": "bad", "timeout": "bad",
            "skipped": "warn", "cancelled": "warn",
        }.get(result.status, "info")
        rows.append(
            "<tr>"
            f"<td>{html_escape(_tool_title(result))}</td>"
            f'<td><span class="badge {badge}">{html_escape(result.status)}</span></td>'
            f"<td class='num'>{result.count}</td>"
            f"<td class='num'>{html_escape(format_duration(result.duration))}</td>"
            "</tr>"
        )

    sections: list[str] = []
    for result in scan.results:
        if not result.findings and result.status == "ok":
            continue
        meta = html_escape(
            " · ".join(
                part for part in (result.error, result.skipped_reason) if part
            )
        )
        items = _html_finding_items(result.findings)
        sections.append(
            "<section class='tool'>"
            f"<h3>{html_escape(_tool_title(result))}</h3>"
            f"<p class='meta'>Estado: <strong>{html_escape(result.status)}</strong>"
            + (f" · {meta}" if meta else "")
            + "</p>"
            + (f"<ul>{''.join(items)}</ul>" if items else "<p><em>Sin hallazgos.</em></p>")
            + "</section>"
        )

    final = final_findings(scan)
    final_items = _html_finding_items(final)
    sections.append(
        "<section class='tool final'>"
        "<h3>Resumen final</h3>"
        "<p class='meta'>Direcciones IP, datos técnicos y enlaces con más información.</p>"
        + (f"<ul>{''.join(final_items)}</ul>" if final_items else "")
        + "</section>"
    )

    tool_count = len(scan.results)
    findings = scan.finding_count
    return f"""<!doctype html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Informe OSINT · {html_escape(scan.target)}</title>
<style>
:root {{ color-scheme: dark; --bg:#0f1216; --panel:#171c22; --line:#2a333d;
  --text:#e7edf3; --muted:#b7c3cf; --ok:#31c48d; --warn:#f5b544; --bad:#f05252;
  --info:#5aa9e6; --link:#7dd3fc; }}
* {{ box-sizing: border-box; }}
body {{ margin:0; padding:2rem; background:var(--bg); color:var(--text);
  font:15px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif; }}
header, main {{ max-width: 1080px; margin: 0 auto; }}
h1 {{ font-size:1.7rem; margin:0 0 .4rem; overflow-wrap:anywhere; }}
h3 {{ font-size:1.02rem; margin:0 0 .35rem; }}
a {{ color:var(--link); }}
.muted {{ color:var(--muted); }}
.stats {{ display:flex; flex-wrap:wrap; gap:.6rem; margin:1.2rem 0 1.6rem; }}
.stat {{ background:var(--panel); border:1px solid var(--line); border-radius:10px;
  padding:.55rem .8rem; min-width:110px; }}
.stat b {{ display:block; font-size:1.25rem; }}
table {{ width:100%; border-collapse:collapse; background:var(--panel);
  border:1px solid var(--line); border-radius:10px; overflow:hidden; margin:1rem 0 2rem; }}
th, td {{ text-align:left; padding:.55rem .7rem; border-bottom:1px solid var(--line);
  vertical-align:top; }}
th {{ color:var(--muted); font-weight:600; font-size:.82rem; text-transform:uppercase;
  letter-spacing:.04em; }}
tr:last-child td {{ border-bottom:0; }}
.num {{ text-align:right; font-variant-numeric: tabular-nums; }}
.badge {{ display:inline-block; padding:.1rem .45rem; border-radius:6px;
  font-size:.78rem; background:#26303a; }}
.badge.ok {{ background:rgba(49,196,141,.16); color:var(--ok); }}
.badge.warn {{ background:rgba(245,181,68,.16); color:var(--warn); }}
.badge.bad {{ background:rgba(240,82,82,.16); color:var(--bad); }}
.tool {{ background:var(--panel); border:1px solid var(--line); border-radius:12px;
  padding:1rem 1.1rem; margin:0 0 1rem; }}
.meta {{ color:var(--muted); margin:.1rem 0 .7rem; font-size:.86rem; }}
ul {{ list-style:none; margin:0; padding:0; }}
.finding {{ display:flex; gap:.55rem; padding:.35rem 0; border-top:1px solid rgba(255,255,255,.045); }}
.finding:first-child {{ border-top:0; }}
.finding p {{ margin:.08rem 0 0; color:var(--muted); overflow-wrap:anywhere; }}
.dot {{ width:7px; height:7px; border-radius:50%; margin-top:.55rem; flex:0 0 auto;
  background:var(--info); }}
.finding.good .dot {{ background:var(--ok); }}
.finding.warn .dot {{ background:var(--warn); }}
.finding.bad .dot {{ background:var(--bad); }}
.finding.link .dot {{ background:var(--link); }}
footer {{ max-width:1080px; margin:2rem auto 0; color:var(--muted); font-size:.82rem; }}
</style>
</head>
<body>
<header>
<h1>Informe OSINT · {html_escape(scan.target)}</h1>
<p class="muted">Tipo <code>{html_escape(scan.kind)}</code> · perfil
<code>{html_escape(scan.profile or "—")}</code> · inicio {html_escape(scan.started_at)} ·
duración {html_escape(format_duration(scan.duration))}</p>
</header>
<main>
<div class="stats">
<div class="stat"><b>{tool_count}</b><span class="muted">herramientas</span></div>
<div class="stat"><b>{scan.ok_count}</b><span class="muted">ok</span></div>
<div class="stat"><b>{findings}</b><span class="muted">hallazgos</span></div>
<div class="stat"><b>{scan.error_count}</b><span class="muted">errores</span></div>
<div class="stat"><b>{scan.skipped_count}</b><span class="muted">omitidas</span></div>
</div>
<table>
<thead><tr><th>Herramienta</th><th>Estado</th><th class="num">Hallazgos</th><th class="num">Duración</th></tr></thead>
<tbody>{''.join(rows)}</tbody>
</table>
{''.join(sections)}
</main>
<footer>Generado por osintkit. Datos de terceros; pueden ser inexactos.
Úsalo solo con autorización y fines legítimos.</footer>
</body>
</html>
"""


def write_reports(
    scan: ScanResult,
    *,
    formats: Iterable[str] = FORMATS,
    directory: str | Path | None = None,
) -> list[Path]:
    target_dir = Path(directory).expanduser() if directory else reports_dir()
    target_dir.mkdir(parents=True, exist_ok=True)
    base = report_basename(scan)
    writers = {
        "json": (".json", render_json),
        "md": (".md", render_markdown),
        "markdown": (".md", render_markdown),
        "html": (".html", render_html),
    }
    paths: list[Path] = []
    for fmt in formats:
        writer = writers.get(fmt.lower())
        if not writer:
            continue
        suffix, render = writer
        path = target_dir / f"{base}{suffix}"
        path.write_text(render(scan), encoding="utf-8")
        paths.append(path)
    return paths


def render_console(scan: ScanResult, *, color: bool = True, max_findings: int = 50) -> str:
    """Resumen legible para terminal, sin curses."""
    try:
        from .ui import colorize
    except Exception:  # pragma: no cover - ui opcional
        def colorize(text: str, level: str) -> str:  # type: ignore
            return text

    title = f"INFORME · {scan.target} ({scan.kind})"
    lines = [
        colorize(title, "title") if color else title,
        summarize(scan),
        f"Perfil: {scan.profile or '—'} · duración: {format_duration(scan.duration)}",
        "",
    ]

    def finding_lines(finding: Finding) -> list[str]:
        marker = {"good": "✓", "warn": "!", "bad": "✗", "link": "→"}.get(finding.level, "·")
        if finding.url:
            site = finding.title
            detail = ""
            if (
                finding.value
                and finding.value != finding.title
                and finding.value != finding.url
            ):
                detail = finding.value
            if color:
                line = f"   {colorize(marker, finding.level)} {colorize(site, 'site')}"
                if detail:
                    line += colorize(f" — {detail}", "value")
            else:
                line = f"   {marker} {site}" + (f" — {detail}" if detail else "")
            url_line = f"     {finding.url}"
            return [line, colorize(url_line, "url") if color else url_line]
        value = f": {finding.value}" if finding.value else ""
        line = f"   {marker} {finding.title}{value}"
        return [colorize(line, finding.level) if color else line]

    for result in scan.results:
        if result.status == "ok" and not result.findings:
            continue
        level = {
            "ok": "good", "error": "bad", "timeout": "bad",
            "skipped": "warn", "cancelled": "warn",
        }.get(result.status, "info")
        icon = {
            "ok": "✓", "error": "✗", "timeout": "⏱",
            "skipped": "·", "cancelled": "×",
        }.get(result.status, "•")
        head = f"{icon} [{result.status:9}] {result.name} ({result.count})"
        lines.append(colorize(head, level) if color else head)
        if result.error:
            lines.append(colorize(f"   ! {result.error}", "bad") if color else f"   ! {result.error}")
        if result.skipped_reason:
            lines.append(
                colorize(f"   · {result.skipped_reason}", "warn")
                if color
                else f"   · {result.skipped_reason}"
            )
        shown = result.findings if max_findings <= 0 else result.findings[:max_findings]
        for finding in shown:
            lines.extend(finding_lines(finding))
        if max_findings > 0 and len(result.findings) > max_findings:
            hidden = len(result.findings) - max_findings
            lines.append(f"   … {hidden} hallazgos más (el informe completo está en los archivos)")
        lines.append("")

    final = final_findings(scan)
    if final:
        header = "RESUMEN FINAL"
        lines.append(colorize(header, "title") if color else header)
        for finding in final:
            lines.extend(finding_lines(finding))
        lines.append("")
    return "\n".join(lines)
