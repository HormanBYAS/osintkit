"""osintkit: kit de OSINT para terminal, sin dependencias obligatorias."""

from __future__ import annotations

from .config import APP_NAME, VERSION

__all__ = ["APP_NAME", "VERSION", "main"]


def main(argv: list[str] | None = None) -> int:
    """Punto de entrada perezoso para no cargar todo el paquete al importar."""
    from .cli import main as _main

    return _main(argv)


__version__ = VERSION
