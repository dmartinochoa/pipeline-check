"""Shared helpers for pypi per-rule tests.

Each test builds an inline ``requirements.txt`` body, wraps it in a
:class:`PypiContext`, and asks the orchestrator for the named
``PYPI-*`` finding.
"""
from __future__ import annotations

from typing import Any

from pipeline_check.core.checks.pypi.base import (
    PypiContext,
    RequirementsFile,
    _parse_requirements,
)
from pipeline_check.core.checks.pypi.pipelines import PypiChecks


def pypi_ctx(text: str, path: str = "requirements.txt") -> PypiContext:
    """Build a PypiContext from a single requirements.txt body."""
    lines, options = _parse_requirements(text)
    return PypiContext([RequirementsFile(
        path=path, text=text, lines=lines, options=options,
    )])


def run_check(text: str, check_id: str, path: str = "requirements.txt") -> Any:
    """Run every pypi check; return the Finding with the given id."""
    ctx = pypi_ctx(text, path=path)
    for f in PypiChecks(ctx).run():
        if f.check_id == check_id:
            return f
    raise AssertionError(
        f"check_id {check_id!r} not produced for requirements input"
    )
