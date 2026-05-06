"""Shared helpers for GitLab CI per-rule tests.

Mirrors ``tests/azure/conftest.py``: parse a YAML snippet into a
``GitLabContext``, run the orchestrator, return the Finding for the
requested check_id.
"""
from __future__ import annotations

import textwrap

import yaml

from pipeline_check.core.checks.gitlab.base import GitLabContext, Pipeline
from pipeline_check.core.checks.gitlab.pipelines import GitLabPipelineChecks


def gl_ctx(yaml_text: str, path: str = ".gitlab-ci.yml") -> GitLabContext:
    """Parse a YAML snippet into a GitLabContext with one pipeline doc."""
    data = yaml.safe_load(textwrap.dedent(yaml_text))
    if data is None:
        data = {}
    return GitLabContext([Pipeline(path=path, data=data)])


def run_check(yaml_text: str, check_id: str):
    """Run every GitLab check; return the Finding with the given id."""
    ctx = gl_ctx(yaml_text)
    for f in GitLabPipelineChecks(ctx).run():
        if f.check_id == check_id:
            return f
    raise AssertionError(
        f"check_id {check_id!r} not found in GitLab orchestrator output"
    )
