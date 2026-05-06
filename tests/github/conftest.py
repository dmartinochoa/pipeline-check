"""Shared helpers for GitHub Actions per-rule tests.

Existing ``test_workflows.py`` inlined ``_ctx`` / ``_run`` helpers;
this conftest factors them out so new test modules can import the
same shape without duplicating the boilerplate. The original file
keeps its inline helpers untouched so its history stays clean.
"""
from __future__ import annotations

import textwrap

import yaml

from pipeline_check.core.checks.github.base import GitHubContext, Workflow
from pipeline_check.core.checks.github.workflows import WorkflowChecks


def gha_ctx(yaml_text: str, path: str = "wf.yml") -> GitHubContext:
    """Parse a YAML snippet into a GitHubContext with one workflow doc."""
    data = yaml.safe_load(textwrap.dedent(yaml_text))
    if data is None:
        data = {}
    return GitHubContext([Workflow(path=path, data=data)])


def run_check(yaml_text: str, check_id: str):
    """Run every GitHub Actions check; return the Finding with the given id."""
    ctx = gha_ctx(yaml_text)
    for f in WorkflowChecks(ctx).run():
        if f.check_id == check_id:
            return f
    raise AssertionError(
        f"check_id {check_id!r} not found in GitHub orchestrator output"
    )
