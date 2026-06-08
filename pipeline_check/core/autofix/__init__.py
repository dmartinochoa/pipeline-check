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
  re-serializing destroys comments, blank lines, and YAML style that
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

import logging
from collections.abc import Callable

import yaml

from .._yaml_strict import safe_load_all_strict
from ..checks.base import Finding

Fixer = Callable[[str, Finding], "str | None"]

SAFE = "safe"
UNSAFE = "unsafe"

_FIXERS: dict[str, tuple[Fixer, str]] = {}

_log = logging.getLogger(__name__)


def register(
    check_id: str, *, safety: str = UNSAFE,
) -> Callable[[Fixer], Fixer]:
    """Decorator used by fixers to register themselves under a check ID.

    *safety* must be ``"safe"`` (edit is semantically equivalent or
    strictly additive) or ``"unsafe"`` (edit relies on inference).
    Missing labels default to ``"unsafe"`` so unlabeled fixers don't
    run under the default ``--fix`` mode.
    """
    if safety not in (SAFE, UNSAFE):
        raise ValueError(f"safety must be {SAFE!r} or {UNSAFE!r}, got {safety!r}")

    def _wrap(fn: Fixer) -> Fixer:
        _FIXERS[check_id.upper()] = (fn, safety)
        return fn
    return _wrap


def available_fixers() -> list[str]:
    return sorted(_FIXERS.keys())


def fixer_safety(check_id: str) -> str | None:
    """Return the safety tier for *check_id*, or None if no fixer exists."""
    entry = _FIXERS.get(check_id.upper())
    return entry[1] if entry is not None else None


def iter_fixers() -> list[tuple[str, str]]:
    """Return ``(check_id, safety)`` for every registered fixer, sorted by ID.

    Backs ``--list-fixers``. One entry per check ID, so a single
    callable bound to several IDs (the cross-provider comment-out
    fixers register the same function under each provider's ID)
    contributes one row per ID. That matches the headline autofixer
    count, which is ``len(_FIXERS)``.
    """
    return sorted((cid, safety) for cid, (_fn, safety) in _FIXERS.items())


def _roundtrip_safe(before: str, after: str) -> bool:
    """Reject patches that broke a YAML file or rewrote its top-level shape.

    Fixers rewrite text via regex; on flow mappings, block scalars, or
    multi-doc streams a misfire can produce something that no longer
    parses or that swapped a mapping for a list. Bail out before the
    operator sees the diff so the worst case is "no patch", not "patch
    that mangles the file".

    Returns ``True`` when:

    1. *before* didn't parse cleanly as a YAML mapping or list. The
       file is a Dockerfile, an odd-shape document, or empty; no
       structural invariant to check, let the fixer's output through.
    2. *after* parses, has the same top-level Python type as *before*,
       and (for multi-doc streams) the same number of documents.
    """
    try:
        before_docs = safe_load_all_strict(before)
    except yaml.YAMLError:
        return True
    # Dockerfile / scalar / empty input: ``safe_load_all`` returned
    # nothing structural to check, let the fixer's output through.
    if not any(isinstance(d, (dict, list)) for d in before_docs):
        return True
    try:
        # Strict loader: a fixer that emits a duplicate mapping key
        # (the classic "insert a second ``with:`` / ``env:`` block"
        # bug) must be rejected here, not silently accepted by
        # last-wins parsing and written to disk.
        after_docs = safe_load_all_strict(after)
    except yaml.YAMLError:
        _log.warning("autofix output failed to parse as YAML; bailing")
        return False
    # True multi-doc stream (Kubernetes manifest with several
    # ``---``-separated docs): the fixer must preserve the doc count.
    # Single-doc inputs whose ``after_docs`` drops to zero are the
    # "fully commented out" case; that's permitted below.
    if len(before_docs) > 1 and len(before_docs) != len(after_docs):
        _log.warning(
            "autofix output changed multi-doc count (%d -> %d); bailing",
            len(before_docs), len(after_docs),
        )
        return False
    # Each structured before-doc must keep its top-level Python type
    # in the corresponding after-doc, with ``None`` (fully commented
    # out) as a permitted compatibility shape.
    for b, a in zip(before_docs, after_docs, strict=False):
        if isinstance(b, (dict, list)) and a is not None and type(a) is not type(b):
            _log.warning(
                "autofix output changed top-level YAML type "
                "(%s -> %s); bailing",
                type(b).__name__, type(a).__name__,
            )
            return False
    return True


def generate_fix(
    finding: Finding, content: str, *, tier: str = SAFE,
) -> str | None:
    """Run the registered fixer for ``finding.check_id`` against ``content``.

    *tier* controls which fixers are eligible:

    - ``"safe"``: only run fixers registered as safe.
    - ``"unsafe"``: run both safe and unsafe fixers.
    - ``"unsafe-only"``: only run fixers registered as unsafe.

    Returns the edited text, or ``None`` if no fixer is registered, the
    fixer's safety doesn't match *tier*, the fixer decided the content
    already satisfies the check, or the generated patch would no longer
    parse as the same shape of YAML document.
    """
    entry = _FIXERS.get(finding.check_id.upper())
    if entry is None:
        return None
    fn, safety = entry
    if tier == SAFE and safety != SAFE:
        return None
    if tier == "unsafe-only" and safety != UNSAFE:
        return None
    out = fn(content, finding)
    if out is None or out == content:
        return None
    if not _roundtrip_safe(content, out):
        return None
    return out


def render_patch(path: str, before: str, after: str) -> str:
    """Unified diff between ``before`` and ``after`` for *path*."""
    # Imported here, not at module top, so ``difflib`` stays off the
    # import path of a plain scan (autofix is pulled in by the fix
    # engine on every CLI load, but a diff is only rendered under --fix).
    import difflib
    return "".join(
        difflib.unified_diff(
            before.splitlines(keepends=True),
            after.splitlines(keepends=True),
            fromfile=f"a/{path}",
            tofile=f"b/{path}",
        )
    )


# Side-effect imports: bringing each fixer module in runs every
# ``@register(...)`` decorator and populates ``_FIXERS``. Kept explicit
# (rather than ``pkgutil.walk_packages``) so the failure mode of a bad
# import is "package init crashes loudly", not "fixer silently absent".
# Provider-keyed sibling modules import the shared ``_insert_comment_above``
# helper from ``_impl``, so ``_impl`` must come first.
from . import _impl as _impl  # noqa: E402
from . import helm as helm  # noqa: E402
