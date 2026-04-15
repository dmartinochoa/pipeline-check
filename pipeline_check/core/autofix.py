"""Suggest concrete source edits to remediate a finding.

Each fixer takes the raw YAML text of a workflow file plus the relevant
finding and returns the edited text, or ``None`` if the fixer can't
safely generate a patch (e.g. the file has already been fixed by hand,
or the issue requires data the scanner doesn't have).

Design rules:

- Fixers never touch the filesystem. ``render_patch`` converts the
  before/after pair into a unified diff; the CLI writes the patch to
  stdout and the user decides whether to apply it.
- Fixers must be *idempotent* — running one whose output is already
  present returns ``None``, never a no-op patch.
- Fixers operate on text, not the parsed YAML AST. Parsing and
  re-serialising destroys comments, blank lines, and YAML style that
  maintainers rely on; text patches preserve them.

Only a small set of high-confidence fixers is implemented so far:

- ``GHA-004`` — add a top-level ``permissions: contents: read`` block.

Future fixers (``GHA-001`` SHA-pinning, ``actions/checkout`` with
``persist-credentials: false``) require network access or AST edits
and are intentionally not included yet.
"""
from __future__ import annotations

import difflib
import re
from typing import Callable

from .checks.base import Finding


Fixer = Callable[[str, Finding], "str | None"]

_FIXERS: dict[str, Fixer] = {}


def register(check_id: str) -> Callable[[Fixer], Fixer]:
    """Decorator used by fixers to register themselves under a check ID."""
    def _wrap(fn: Fixer) -> Fixer:
        _FIXERS[check_id.upper()] = fn
        return fn
    return _wrap


def available_fixers() -> list[str]:
    return sorted(_FIXERS.keys())


def generate_fix(finding: Finding, content: str) -> str | None:
    """Run the registered fixer for ``finding.check_id`` against ``content``.

    Returns the edited text, or ``None`` if no fixer is registered or
    the fixer decided the content already satisfies the check.
    """
    fn = _FIXERS.get(finding.check_id.upper())
    if fn is None:
        return None
    try:
        out = fn(content, finding)
    except Exception:
        return None
    if out is None or out == content:
        return None
    return out


def render_patch(path: str, before: str, after: str) -> str:
    """Unified diff between ``before`` and ``after`` for *path*."""
    return "".join(
        difflib.unified_diff(
            before.splitlines(keepends=True),
            after.splitlines(keepends=True),
            fromfile=f"a/{path}",
            tofile=f"b/{path}",
        )
    )


# ── Fixers ────────────────────────────────────────────────────────────────


_TOPLEVEL_KEY_RE = re.compile(r"^(?:permissions|jobs|on|name|env|defaults)\s*:",
                              re.MULTILINE)


@register("GHA-004")
def _fix_gha004(content: str, finding: Finding) -> str | None:
    """Insert ``permissions: contents: read`` at the top of the workflow.

    Idempotent: returns ``None`` if a top-level ``permissions:`` key
    already exists.
    """
    for m in _TOPLEVEL_KEY_RE.finditer(content):
        if m.group(0).split(":", 1)[0] == "permissions":
            return None

    # Insert the block before the first `jobs:` (the canonical anchor)
    # or, if no jobs: exists, before the first `on:` trigger.
    anchor = re.search(r"^jobs\s*:", content, re.MULTILINE) or \
             re.search(r"^on\s*:", content, re.MULTILINE)
    if anchor is None:
        return None
    insert_at = anchor.start()
    block = "permissions:\n  contents: read\n\n"
    return content[:insert_at] + block + content[insert_at:]
