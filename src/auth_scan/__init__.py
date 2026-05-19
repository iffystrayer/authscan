"""auth-scan: CLI Web Authentication Security Assessment Tool."""

from __future__ import annotations

from importlib import metadata as _metadata


def _resolve_version() -> str:
    """Return the installed package version.

    Prefers ``importlib.metadata`` (the canonical source from
    ``pyproject.toml``). Falls back to a hardcoded sentinel only for
    in-tree imports before the project is installed.
    """
    try:
        return _metadata.version("auth-scan")
    except _metadata.PackageNotFoundError:
        return "0.0.0+local"


__version__ = _resolve_version()
__author__ = "auth-scan Engineering Team"
