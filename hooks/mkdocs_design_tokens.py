"""MkDocs hook that mirrors the shared design-tokens CSS into docs/.

Canonical source: ``pipeline_check/core/_design_tokens.css``. This file
ships in the wheel and is inlined into every HTML report at module-
import time.

The docs site needs the same tokens but cannot ``@import`` a file
inside ``pipeline_check/`` (mkdocs only serves files under
``docs_dir``). This hook copies the canonical CSS to
``docs/stylesheets/_design_tokens.css`` on every ``mkdocs build`` /
``mkdocs serve`` so a single edit to the package file updates both
the report and the docs site.

The destination file is committed to git too. The hook only writes
when the contents differ, keeping ``mkdocs serve`` reloads quiet and
making accidental drift visible to CI (``git diff --exit-code`` in
the docs pipeline trips when someone edited only the package copy).

Registered via the ``hooks:`` key in ``mkdocs.yml``.
"""
from __future__ import annotations

from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_SRC = _ROOT / "pipeline_check" / "core" / "_design_tokens.css"
_DST = _ROOT / "docs" / "stylesheets" / "_design_tokens.css"

_HEADER = (
    "/* DO NOT EDIT. Mirrored from pipeline_check/core/_design_tokens.css\n"
    "   by hooks/mkdocs_design_tokens.py. Edit the package file and\n"
    "   re-run ``mkdocs build`` (or rely on the docs CI to refresh). */\n"
)


def on_pre_build(**_kwargs: object) -> None:
    if not _SRC.is_file():
        # The package file should always exist; surface the absence
        # loudly so a misconfigured build doesn't silently ship the
        # stale mirror.
        raise FileNotFoundError(
            f"design-tokens source missing: {_SRC} "
            "(expected to live in the package and ship in the wheel)"
        )
    want = _HEADER + _SRC.read_text(encoding="utf-8")
    have = _DST.read_text(encoding="utf-8") if _DST.is_file() else ""
    if want != have:
        _DST.parent.mkdir(parents=True, exist_ok=True)
        _DST.write_text(want, encoding="utf-8")
