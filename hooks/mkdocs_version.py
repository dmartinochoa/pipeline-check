"""MkDocs hook that injects the live package version into markdown.

Pages can write `{{ version }}` and the hook replaces it with
`pipeline_check.__version__` at build time. Avoids the v0.3.0 vs
v0.3.3 doc-skew that hardcoded version strings caused before.

Registered via the `hooks:` key in `mkdocs.yml`.
"""
from __future__ import annotations

from pipeline_check import __version__ as _version


def on_page_markdown(markdown: str, **_kwargs: object) -> str:
    return markdown.replace("{{ version }}", _version)
