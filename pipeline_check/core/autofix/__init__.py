"""Suggest concrete source edits to remediate a finding.

Each fixer takes the raw YAML text of a workflow file plus the relevant
finding and returns the edited text, or ``None`` if the fixer can't
safely generate a patch (e.g. the file has already been fixed by hand,
or the issue requires data the scanner doesn't have).

Design rules:

- Fixers never touch the filesystem. ``render_patch`` converts the
  before/after pair into a unified diff; the CLI writes the patch to
  stdout and the user decides whether to apply it.
- Fixers must be *idempotent* . running one whose output is already
  present returns ``None``, never a no-op patch.
- Fixers operate on text, not the parsed YAML AST. Parsing and
  re-serialising destroys comments, blank lines, and YAML style that
  maintainers rely on; text patches preserve them.

Package layout
--------------
This module is a thin facade. The decorator (``register``), registry
(``_FIXERS``), and dispatch helpers live here so callers can import
them without paying for the full fixer body. The 100+ actual fixers
live in sibling modules under this package and are pulled in when the
package is first imported, which is when their ``@register(...)``
decorators run.

To add a fixer category, drop a new ``pipeline_check/core/autofix/<name>.py``
module exporting ``@register("<CHECK-ID>")``-decorated callables and
add an ``import`` line at the bottom of this file. (We keep the imports
explicit rather than walking the directory so a typo in a sibling
module fails loudly at import time, not silently as a missing fixer.)
"""
from __future__ import annotations

import difflib
from collections.abc import Callable

from ..checks.base import Finding

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

    Fixer exceptions propagate . the CLI catches at the call site so a
    single broken fixer doesn't abort a batch run, but a bug in a
    fixer surfaces instead of being silently swallowed.
    """
    fn = _FIXERS.get(finding.check_id.upper())
    if fn is None:
        return None
    out = fn(content, finding)
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


# Side-effect import: bringing the implementation module in runs every
# ``@register(...)`` decorator and populates ``_FIXERS``. Kept explicit
# (rather than ``pkgutil.walk_packages``) so the failure mode of a bad
# import is "package init crashes loudly", not "fixer silently absent".
from . import _impl as _impl  # noqa: F401, E402
