"""Shared helpers for npm per-rule tests.

Each test builds an inline ``package.json`` or ``package-lock.json``
text, wraps it in an :class:`NpmContext`, and asks the orchestrator
for the named ``NPM-*`` finding.
"""
from __future__ import annotations

import json
from typing import Any

from pipeline_check.core.checks.npm.base import (
    NpmContext,
    NpmLock,
    NpmManifest,
    NpmRc,
    parse_npmrc,
)
from pipeline_check.core.checks.npm.pipelines import NpmChecks


def manifest_ctx(data: dict[str, Any], path: str = "package.json") -> NpmContext:
    """Build an NpmContext from a single package.json dict."""
    text = json.dumps(data, indent=2)
    return NpmContext(
        manifests=[NpmManifest(path=path, text=text, data=data)],
        locks=[],
    )


def lock_ctx(
    data: dict[str, Any], path: str = "package-lock.json",
) -> NpmContext:
    """Build an NpmContext from a single lockfile dict."""
    text = json.dumps(data, indent=2)
    version = data.get("lockfileVersion")
    return NpmContext(
        manifests=[],
        locks=[NpmLock(
            path=path, text=text, data=data,
            lockfile_version=version if isinstance(version, int) else 1,
        )],
    )


def run_check_manifest(data: dict[str, Any], check_id: str) -> Any:
    """Run every npm check on a single package.json; return the named finding."""
    for f in NpmChecks(manifest_ctx(data)).run():
        if f.check_id == check_id:
            return f
    raise AssertionError(
        f"check_id {check_id!r} not produced for manifest input"
    )


def run_check_lock(data: dict[str, Any], check_id: str) -> Any:
    """Run every npm check on a single lockfile; return the named finding."""
    for f in NpmChecks(lock_ctx(data)).run():
        if f.check_id == check_id:
            return f
    raise AssertionError(
        f"check_id {check_id!r} not produced for lockfile input"
    )


def rc_ctx(text: str, path: str = ".npmrc") -> NpmContext:
    """Build an NpmContext from a single .npmrc body."""
    return NpmContext(
        manifests=[], locks=[],
        rcs=[NpmRc(path=path, text=text, settings=parse_npmrc(text))],
    )


def run_check_rc(text: str, check_id: str) -> Any:
    """Run every npm check on a single .npmrc; return the named finding."""
    for f in NpmChecks(rc_ctx(text)).run():
        if f.check_id == check_id:
            return f
    raise AssertionError(
        f"check_id {check_id!r} not produced for .npmrc input"
    )
