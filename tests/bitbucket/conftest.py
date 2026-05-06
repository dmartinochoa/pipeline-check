"""Shared helpers for Bitbucket Pipelines per-rule tests.

Existing ``test_pipelines.py`` inlined ``_ctx`` / ``_run`` helpers;
this conftest factors them out so new test modules can import the
same helpers without duplicating the boilerplate.
"""
from __future__ import annotations

import textwrap

import yaml

from pipeline_check.core.checks.bitbucket.base import BitbucketContext, Pipeline
from pipeline_check.core.checks.bitbucket.pipelines import BitbucketPipelineChecks


def bb_ctx(yaml_text: str, path: str = "bitbucket-pipelines.yml") -> BitbucketContext:
    """Parse a YAML snippet into a BitbucketContext with one pipeline doc."""
    data = yaml.safe_load(textwrap.dedent(yaml_text))
    if data is None:
        data = {}
    return BitbucketContext([Pipeline(path=path, data=data)])


def run_check(yaml_text: str, check_id: str):
    """Run every Bitbucket check; return the Finding with the given id."""
    ctx = bb_ctx(yaml_text)
    for f in BitbucketPipelineChecks(ctx).run():
        if f.check_id == check_id:
            return f
    raise AssertionError(
        f"check_id {check_id!r} not found in Bitbucket orchestrator output"
    )
