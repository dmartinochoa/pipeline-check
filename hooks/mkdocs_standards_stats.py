"""MkDocs hook that injects per-standard check counts into markdown.

Pages can write tokens like ``{{ standards.owasp_cicd_top_10.checks }}``
and ``{{ standards.nist_800_53.controls }}`` and this hook swaps them
out at build time with the live count parsed from
``pipeline_check/core/standards/data/<name>.py``.

Why parse instead of import: the docs CI environment installs MkDocs
Material from ``requirements-docs.txt`` but does not install the
package itself, so ``from pipeline_check.core.standards.data import …``
isn't available. We use ``ast`` to walk the source module and count
the ``mappings={…}`` and ``controls={…}`` dict literals — fragile
against deep refactors but rock-solid against the current
hand-written data shape:

    STANDARD = Standard(
        name="…",
        controls={"CTRL-1": "…", …},
        mappings={"CHECK-001": [...], …},
    )

Registered via the ``hooks:`` key in ``mkdocs.yml``.
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

_DATA_DIR = (
    Path(__file__).resolve().parent.parent
    / "pipeline_check" / "core" / "standards" / "data"
)

_TOKEN_RE = re.compile(
    r"\{\{\s*standards\.(?P<name>[a-z0-9_]+)\.(?P<field>checks|controls)\s*\}\}"
)


def _scan_one(path: Path) -> tuple[int, int]:
    """Return (checks_count, controls_count) parsed from a standards module.

    Walks the AST, finds ``STANDARD = Standard(…)`` and counts the
    keys in the ``controls`` and ``mappings`` keyword arguments.
    """
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"))
    except (OSError, SyntaxError):
        return (0, 0)
    checks = 0
    controls = 0
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        # Look for ``STANDARD = Standard(…)``
        if not (
            len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
            and node.targets[0].id == "STANDARD"
            and isinstance(node.value, ast.Call)
        ):
            continue
        for kw in node.value.keywords:
            if kw.arg == "mappings" and isinstance(kw.value, ast.Dict):
                checks = len(kw.value.keys)
            elif kw.arg == "controls" and isinstance(kw.value, ast.Dict):
                controls = len(kw.value.keys)
        break
    return checks, controls


def _build_index() -> dict[str, dict[str, int]]:
    """Scan every standards module once at hook-load time."""
    out: dict[str, dict[str, int]] = {}
    if not _DATA_DIR.exists():
        return out
    for path in _DATA_DIR.glob("*.py"):
        if path.name.startswith("_"):
            continue
        checks, controls = _scan_one(path)
        out[path.stem] = {"checks": checks, "controls": controls}
    return out


_INDEX = _build_index()


def on_page_markdown(markdown: str, **_kwargs: object) -> str:
    if "{{ standards." not in markdown:
        return markdown

    def _sub(m: re.Match[str]) -> str:
        info = _INDEX.get(m.group("name"))
        if info is None:
            return m.group(0)  # unknown standard — leave token in place
        return str(info.get(m.group("field"), ""))

    return _TOKEN_RE.sub(_sub, markdown)
