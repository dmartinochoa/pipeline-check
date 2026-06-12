"""Post-scan UX hint emitters for the ``scan`` command.

Small, self-contained ``[hint]`` / ``[warn]`` nudges the CLI prints to
stderr after a scan to catch common first-run mistakes (wrong provider,
a JavaScript repo scanned with only ``--pipeline github``, a fully
API-degraded AWS run). Extracted from ``cli.py`` to keep that module
focused on argument wiring and orchestration; the functions are pure
(they read findings / cwd and emit, returning nothing) and re-imported
into ``cli`` so the call sites in ``scan()`` are unchanged.
"""
from __future__ import annotations

import os
from typing import Any

import click

from .core.detect import detect_pipeline_from_cwd


def _find_sibling_package_jsons(root: str, max_depth: int = 3) -> list[str]:
    """Return up to a handful of ``package.json`` paths under *root*.

    Bounded by ``max_depth`` and skipping the usual heavy directories
    (``node_modules`` chief among them — a single transitive install
    can land tens of thousands of nested ``package.json`` files, and
    none of them belong to the consuming repo). Used by the
    npm-alongside-github hint so the scanner can nudge users who
    invoke ``--pipeline github`` alone in a repo that also ships
    JavaScript code.
    """
    skip_dirs: frozenset[str] = frozenset({
        "node_modules", ".git", "vendor", "dist", "build",
        ".venv", "venv", "__pycache__", ".tox", ".mypy_cache",
        ".pytest_cache", "target",
    })
    hits: list[str] = []
    root_abs = os.path.abspath(root)
    root_depth = root_abs.rstrip(os.sep).count(os.sep)
    for dirpath, dirnames, filenames in os.walk(root_abs):
        dirnames[:] = [d for d in dirnames if d not in skip_dirs]
        if dirpath.count(os.sep) - root_depth > max_depth:
            dirnames[:] = []
            continue
        if "package.json" in filenames:
            hits.append(os.path.join(dirpath, "package.json"))
            if len(hits) >= 5:
                break
    return hits


def _maybe_emit_npm_alongside_github_hint(
    pipelines_resolved: list[str],
    findings: list[Any],
) -> None:
    """Nudge the user when ``--pipeline github`` scanned a tree that
    also ships ``package.json`` files.

    The npm provider catches dependency-confusion / floating-range /
    lockfile-integrity issues that the github pipeline can't see (it
    only inspects workflow YAML, not the consumed manifests). Fires
    only on single-provider ``--pipeline github`` invocations where
    a quick depth-bounded walk of cwd finds a ``package.json``
    outside ``node_modules`` / build / vendor directories. Off when
    the user explicitly multi-provider-ran ``github,npm`` (the npm
    coverage is already in scope).
    """
    if pipelines_resolved != ["github"]:
        return
    pjs = _find_sibling_package_jsons(".")
    if not pjs:
        return
    def _safe_relpath(p: str) -> str:
        try:
            return os.path.relpath(p)
        except ValueError:
            return p

    sample = ", ".join(_safe_relpath(p) for p in pjs[:3])
    more = "" if len(pjs) <= 3 else f" (+{len(pjs) - 3} more)"
    # One ``package.json`` at the repo root resolves via the npm
    # provider's own cwd auto-detection (``pipeline_check --pipeline
    # npm`` without ``--npm-path``); multiple or nested manifests need
    # an explicit ``--npm-path <dir>`` per manifest, so the hint
    # surfaces the directory the user would point at.
    pj_dirs = sorted({
        _safe_relpath(os.path.dirname(p)) or "." for p in pjs
    })
    if len(pj_dirs) == 1 and pj_dirs[0] in (".", ""):
        suggestion = (
            "rerun with ``--pipelines github,npm`` to also scan the "
            "manifest"
        )
    else:
        dir_sample = ", ".join(pj_dirs[:3])
        suggestion = (
            f"rerun with ``--pipeline npm --npm-path <dir>`` for each "
            f"({dir_sample})"
        )
    click.echo(
        f"[hint] this repo also ships package.json files ({sample}"
        f"{more}). ``--pipeline github`` only inspects workflow "
        f"YAML; {suggestion} for dependency-confusion / "
        f"lockfile-integrity / floating-range coverage.",
        err=True,
    )


def _maybe_emit_wrong_provider_hint(pipeline_lc: str, findings: list[Any]) -> None:
    """Nudge the user when AWS was scanned but a CI config file exists.

    Fires only when the caller explicitly picked ``--pipeline aws`` (or
    configured it) AND every finding is a degraded ``*-000`` API-access
    probe AND cwd looks like a CI repo. Designed to catch the common
    'wrong credentials / wrong provider' first-run mistake without
    spamming legitimate AWS runs.
    """
    if pipeline_lc != "aws" or not findings:
        return
    if not all(getattr(f, "check_id", "").endswith("-000") for f in findings):
        return
    detected = detect_pipeline_from_cwd()
    if not detected:
        return
    click.echo(
        f"[hint] no real AWS results. This looks like a '{detected}' "
        f"repo; try: pipeline_check --pipeline {detected}",
        err=True,
    )


def _maybe_emit_degraded_scan_warning(findings: list[Any]) -> None:
    """Surface a ``[warn]`` line when degraded-mode findings dominate.

    Every AWS module emits a single ``<PREFIX>-000`` INFO-severity
    finding when its boto3 enumeration fails (missing credentials,
    AccessDenied, throttling). Those findings are NOT security gaps —
    they're tool-status — but they still render as "FAIL" rows in the
    table, and they don't count toward the score (INFO is ignored by
    the weighted formula), so a fully-degraded scan can confusingly
    display "Score 100 / Grade A" right next to fourteen FAIL rows.

    This helper bridges that gap: when ``>0`` degraded-mode findings
    exist, emit a stderr ``[warn]`` line listing how many modules
    failed API access so the operator knows the score reflects only
    the modules that actually returned data.
    """
    degraded = [
        f for f in findings
        if getattr(f, "check_id", "").endswith("-000")
        and not getattr(f, "passed", True)
    ]
    if not degraded:
        return
    n = len(degraded)
    click.echo(
        f"[warn] scan degraded: {n} module(s) failed API access. The "
        f"score reflects only the modules that returned data; run "
        f"with --verbose to see which modules were skipped.",
        err=True,
    )
