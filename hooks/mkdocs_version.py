"""MkDocs hook that injects the live package version into markdown.

Pages can write `{{ version }}` and the hook replaces it with the
``project.version`` field from ``pyproject.toml`` at build time.
Avoids the v0.3.0 vs v0.3.3 doc-skew that hardcoded version strings
caused before.

The hook reads ``pyproject.toml`` directly rather than importing
``pipeline_check`` so it works in the docs CI environment, which
installs MkDocs Material from ``requirements-docs.txt`` but does
not install the package itself.

Registered via the `hooks:` key in `mkdocs.yml`.
"""
from __future__ import annotations

from pathlib import Path

import tomllib

_PYPROJECT = Path(__file__).resolve().parent.parent / "pyproject.toml"


def _read_version() -> str:
    with _PYPROJECT.open("rb") as fh:
        data = tomllib.load(fh)
    project = data.get("project")
    if isinstance(project, dict):
        version = project.get("version")
        if isinstance(version, str):
            return version
    return "0.0.0"


_VERSION = _read_version()


def on_page_markdown(markdown: str, **_kwargs: object) -> str:
    return markdown.replace("{{ version }}", _VERSION)
