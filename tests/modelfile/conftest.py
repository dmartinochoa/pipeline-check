"""Shared helpers for Modelfile per-rule tests.

Parse a Modelfile snippet into a one-file ``ModelfileContext``, run the
orchestrator, return the Finding for the requested check_id. Keeps each
rule's tests to small inline literals (no disk I/O).
"""
from __future__ import annotations

import textwrap

from pipeline_check.core.checks.modelfile.base import (
    Modelfile,
    ModelfileContext,
    parse_modelfile,
)
from pipeline_check.core.checks.modelfile.checks import ModelfileChecks


def modelfile_ctx(raw: str, path: str = "Modelfile") -> ModelfileContext:
    """Build a ModelfileContext from a single Modelfile body."""
    raw = textwrap.dedent(raw)
    return ModelfileContext(
        [Modelfile(path=path, text=raw, directives=parse_modelfile(raw))]
    )


def run_check(raw: str, check_id: str):
    """Run every Modelfile check; return the Finding with the given id."""
    ctx = modelfile_ctx(raw)
    for f in ModelfileChecks(ctx).run():
        if f.check_id == check_id:
            return f
    raise AssertionError(
        f"check_id {check_id!r} not found in modelfile orchestrator output"
    )
