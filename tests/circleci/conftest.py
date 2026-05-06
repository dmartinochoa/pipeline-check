"""Shared helpers for CircleCI per-rule tests.

Mirrors ``tests/azure/conftest.py``: parse a YAML snippet into a
``CircleCIContext``, run the orchestrator, return the Finding for
the requested check_id. Keeps each rule's tests as small inline
literals rather than separate fixture files.
"""
from __future__ import annotations

import textwrap

import yaml

from pipeline_check.core.checks.circleci.base import (
    CircleCIContext,
    CircleConfig,
)
from pipeline_check.core.checks.circleci.pipelines import CircleCIPipelineChecks


def cc_ctx(yaml_text: str, path: str = ".circleci/config.yml") -> CircleCIContext:
    """Parse a YAML snippet into a CircleCIContext with one config doc."""
    data = yaml.safe_load(textwrap.dedent(yaml_text))
    if data is None:
        data = {}
    return CircleCIContext([CircleConfig(path=path, data=data)])


def run_check(yaml_text: str, check_id: str):
    """Run every CircleCI check; return the Finding with the given id."""
    ctx = cc_ctx(yaml_text)
    for f in CircleCIPipelineChecks(ctx).run():
        if f.check_id == check_id:
            return f
    raise AssertionError(
        f"check_id {check_id!r} not found in CircleCI orchestrator output"
    )
