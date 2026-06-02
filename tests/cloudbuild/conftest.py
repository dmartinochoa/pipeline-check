"""Shared helpers for Cloud Build per-rule tests.

Mirrors ``tests/circleci/conftest.py``: parse a YAML snippet into a
``CloudBuildContext``, run the orchestrator, return the Finding for
the requested check_id. Keeps each rule's tests as small inline
literals rather than separate fixture files.
"""
from __future__ import annotations

import textwrap

import yaml

from pipeline_check.core.checks.cloudbuild.base import (
    CloudBuildContext,
    Pipeline,
)
from pipeline_check.core.checks.cloudbuild.pipelines import CloudBuildPipelineChecks


def gcb_ctx(yaml_text: str, path: str = "cloudbuild.yaml") -> CloudBuildContext:
    """Parse a YAML snippet into a CloudBuildContext with one pipeline doc."""
    data = yaml.safe_load(textwrap.dedent(yaml_text))
    if data is None:
        data = {}
    return CloudBuildContext([Pipeline(path=path, data=data)])


def run_check(yaml_text: str, check_id: str):
    """Run every Cloud Build check; return the Finding with the given id."""
    ctx = gcb_ctx(yaml_text)
    for f in CloudBuildPipelineChecks(ctx).run():
        if f.check_id == check_id:
            return f
    raise AssertionError(
        f"check_id {check_id!r} not found in Cloud Build orchestrator output"
    )
