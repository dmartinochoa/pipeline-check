"""Shared helpers for Dockerfile per-rule tests.

Dockerfile rules take a single ``Dockerfile`` object (path + text +
parsed Instruction list), not the ``(path, doc)`` pair the YAML
providers use. The conftest exposes a ``run_check(text, check_id)``
helper that wraps a snippet in a ``Dockerfile`` and runs the
orchestrator.
"""
from __future__ import annotations

from pipeline_check.core.checks.dockerfile.base import (
    Dockerfile,
    DockerfileContext,
    parse_dockerfile,
)
from pipeline_check.core.checks.dockerfile.pipelines import DockerfileChecks


def df_ctx(text: str, path: str = "Dockerfile") -> DockerfileContext:
    """Build a DockerfileContext from inline source."""
    return DockerfileContext([Dockerfile(
        path=path,
        text=text,
        instructions=parse_dockerfile(text),
    )])


def run_check(text: str, check_id: str):
    """Run every Dockerfile check; return the Finding with the given id."""
    ctx = df_ctx(text)
    for f in DockerfileChecks(ctx).run():
        if f.check_id == check_id:
            return f
    raise AssertionError(
        f"check_id {check_id!r} not found in Dockerfile orchestrator output"
    )
