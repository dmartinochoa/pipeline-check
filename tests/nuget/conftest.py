"""Shared helpers for NuGet per-rule tests."""
from __future__ import annotations

from pipeline_check.core.checks.nuget.base import NuGetContext, NuGetProject
from pipeline_check.core.checks.nuget.pipelines import NuGetChecks


def run_check(
    projects: list[NuGetProject] | None = None,
    configs: list | None = None,
    locks: list | None = None,
    check_id: str = "",
    ctx: NuGetContext | None = None,
):
    """Run every NuGet check; return the Finding with the given id."""
    if ctx is None:
        ctx = NuGetContext(
            projects=projects or [],
            configs=configs or [],
            locks=locks or [],
        )
    for f in NuGetChecks(ctx).run():
        if f.check_id == check_id:
            return f
    raise AssertionError(
        f"check_id {check_id!r} not found in NuGet orchestrator output"
    )
