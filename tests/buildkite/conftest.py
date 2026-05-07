"""Shared helpers for Buildkite per-rule tests."""
from __future__ import annotations

import textwrap

import yaml

from pipeline_check.core.checks.buildkite.base import (
    BuildkiteContext,
    Pipeline,
)
from pipeline_check.core.checks.buildkite.pipelines import (
    BuildkitePipelineChecks,
)


def bk_ctx(yaml_text: str, path: str = ".buildkite/pipeline.yml") -> BuildkiteContext:
    """Parse a YAML snippet into a BuildkiteContext with one pipeline doc."""
    data = yaml.safe_load(textwrap.dedent(yaml_text))
    if data is None:
        data = {}
    return BuildkiteContext([Pipeline(path=path, data=data)])


def run_check(yaml_text: str, check_id: str):
    """Run every Buildkite check; return the Finding with the given id."""
    ctx = bk_ctx(yaml_text)
    for f in BuildkitePipelineChecks(ctx).run():
        if f.check_id == check_id:
            return f
    raise AssertionError(
        f"check_id {check_id!r} not found in Buildkite orchestrator output"
    )
