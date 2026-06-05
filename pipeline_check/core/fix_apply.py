"""Autofix application: plan, write, emit patches.

The fix engine itself lives in ``core/autofix``; this is the thin
orchestration layer that the CLI's ``--fix`` / ``--fix --apply`` and the
``fix-pr`` command share (plan the edits, write them with line-ending
fidelity, or render them as unified diffs). Kept Click-free, status goes
to ``sys.stderr`` via ``print`` like the other ``core`` modules, so any
entry point can drive it.
"""
from __future__ import annotations

import os
import sys
from typing import Any

from . import autofix as _autofix


def emit_fix_patches(
    findings: list[Any], *, to_stderr: bool = False, tier: str = "safe",
) -> None:
    """Emit one unified-diff patch per failing finding that has a fixer.

    Patches go to stdout by default so a user can pipe straight into
    ``git apply``. When a machine-readable report is already occupying
    stdout (``--output json/sarif/html/both``), the caller sets
    ``to_stderr=True`` to avoid corrupting that stream.

    File read errors are silently skipped, a missing file is almost
    always due to a finding with a synthetic resource name (e.g. an
    AWS check), not a real on-disk workflow. Per-path content is
    cached so multiple findings against the same file only re-read
    the source once.
    """
    cache: dict[str, str] = {}
    dirty: dict[str, str] = {}
    patch_count = 0
    patched_files: set[str] = set()
    for f in findings:
        if f.passed:
            continue
        path = f.resource
        if not path or not os.path.isfile(path):
            continue
        before = dirty[path] if path in dirty else cache.get(path)
        if before is None:
            try:
                with open(path, encoding="utf-8") as fh:
                    before = fh.read()
            except (OSError, UnicodeDecodeError):
                continue
            cache[path] = before
        try:
            after = _autofix.generate_fix(f, before, tier=tier)
        except Exception as exc:
            print(
                f"[autofix] fixer for {f.check_id} raised {type(exc).__name__}: {exc}",
                file=sys.stderr,
            )
            continue
        if after is None:
            continue
        patch_count += 1
        patched_files.add(path)
        print(
            _autofix.render_patch(path, before, after),
            end="",
            file=sys.stderr if to_stderr else sys.stdout,
        )
        dirty[path] = after
    if patch_count:
        print(
            f"[autofix] {patch_count} patch(es) for {len(patched_files)} file(s)."
            f" Run with --apply to modify in place.",
            file=sys.stderr,
        )


def plan_fix_edits(
    findings: list[Any], *, tier: str = "safe",
) -> tuple[dict[str, str], dict[str, str], set[str]]:
    """Compute the autofix edits without touching disk.

    Returns ``(edits, newlines, fixed_ids)`` where *edits* maps each path
    to its fully-patched content (every applicable fixer folded in,
    idempotent), *newlines* records the path's original line ending, and
    *fixed_ids* is the set of check IDs whose fixer actually produced a
    change (used by ``fix-pr`` for the PR title / body). Splitting the
    planning out of the write lets ``fix-pr`` decide whether there's
    anything to commit before it creates a branch.

    The line-ending bookkeeping matters on Windows: reading in text mode
    normalizes CRLF to ``\\n``, and writing it back in text mode would
    translate ``\\n`` to ``os.linesep``, silently flipping a pure-LF file
    to CRLF. We read with ``newline=""``, patch the in-memory LF copy,
    and re-apply the detected ending on write so only patched lines move.
    """
    cache: dict[str, str] = {}
    dirty: dict[str, str] = {}  # path → final content
    newlines: dict[str, str] = {}
    fixed_ids: set[str] = set()
    for f in findings:
        if f.passed:
            continue
        path = f.resource
        if not path or not os.path.isfile(path):
            continue
        before = dirty[path] if path in dirty else cache.get(path)
        if before is None:
            try:
                with open(path, encoding="utf-8", newline="") as fh:
                    raw = fh.read()
            except (OSError, UnicodeDecodeError):
                continue
            newlines[path] = "\r\n" if "\r\n" in raw else "\n"
            before = raw.replace("\r\n", "\n")
            cache[path] = before
        try:
            after = _autofix.generate_fix(f, before, tier=tier)
        except Exception as exc:
            print(
                f"[autofix] fixer for {f.check_id} raised {type(exc).__name__}: {exc}",
                file=sys.stderr,
            )
            continue
        if after is None:
            continue
        dirty[path] = after
        fixed_ids.add(f.check_id)
    return dirty, newlines, fixed_ids


def write_fix_edits(
    edits: dict[str, str], newlines: dict[str, str],
) -> list[str]:
    """Write planned *edits* to disk; return the paths actually written."""
    written: list[str] = []
    for path, content in edits.items():
        eol = newlines.get(path, "\n")
        if eol != "\n":
            content = content.replace("\n", eol)
        try:
            with open(path, "w", encoding="utf-8", newline="") as fh:
                fh.write(content)
            written.append(path)
        except OSError as exc:
            print(f"[autofix] could not write {path}: {exc}", file=sys.stderr)
    return written


def apply_fix_patches(findings: list[Any], *, tier: str = "safe") -> list[str]:
    """Apply autofixes in place; print an N-files-modified summary to stderr.

    Each fixer is idempotent, so it's safe to re-run after an apply,
    already-fixed files produce no further patch. Unfixable findings
    are silently skipped. Returns the list of modified paths so callers
    (``fix-pr``) can stage exactly those files.
    """
    edits, newlines, _fixed_ids = plan_fix_edits(findings, tier=tier)
    written = write_fix_edits(edits, newlines)
    print(f"[autofix] {len(written)} file(s) modified.", file=sys.stderr)
    return written
