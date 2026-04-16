"""Scenario tests for GitLab CI edge cases.

Fixture bodies live under ``tests/fixtures/scenarios/gitlab/``.
This module mirrors the pattern from ``test_pipeline_poisoning.py``.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from pipeline_check.core.checks.gitlab.base import GitLabContext, Pipeline
from pipeline_check.core.checks.gitlab.pipelines import GitLabPipelineChecks

import yaml

SCENARIO_DIR = Path(__file__).parent / "fixtures" / "scenarios" / "gitlab"


def _scenario(name: str) -> str:
    return (SCENARIO_DIR / name).read_text(encoding="utf-8")


def _scan(text: str, tmp_path: Path):
    data = yaml.safe_load(text)
    ctx = GitLabContext([Pipeline(path=str(tmp_path / "ci.yml"), data=data)])
    return {f.check_id: f.passed for f in GitLabPipelineChecks(ctx).run()}


# ── GL-002 env-chain taint tracking ──────────────────────────────────


def test_gl002_flags_env_chain_global(tmp_path):
    results = _scan(_scenario("gl002-env-chain-global-tainted.yml"), tmp_path)
    assert results["GL-002"] is False


def test_gl002_flags_env_chain_job(tmp_path):
    results = _scan(_scenario("gl002-env-chain-job-tainted.yml"), tmp_path)
    assert results["GL-002"] is False


def test_gl002_env_chain_safe_not_flagged(tmp_path):
    results = _scan(_scenario("gl002-env-chain-safe.yml"), tmp_path)
    assert results["GL-002"] is True


def test_gl002_env_chain_quoted_not_flagged(tmp_path):
    results = _scan(_scenario("gl002-env-chain-quoted.yml"), tmp_path)
    assert results["GL-002"] is True


def test_gl002_dict_form_variable_flagged(tmp_path):
    results = _scan(_scenario("gl002-dict-form-variable.yml"), tmp_path)
    assert results["GL-002"] is False


def test_gl002_command_sub_bypass_flagged(tmp_path):
    results = _scan(_scenario("gl002-command-sub-bypass.yml"), tmp_path)
    assert results["GL-002"] is False


# ── GL-004 deploy command detection ──────────────────────────────────


def test_gl004_deploy_command_flagged(tmp_path):
    results = _scan(_scenario("gl004-deploy-command.yml"), tmp_path)
    assert results["GL-004"] is False


def test_gl004_deploy_with_env_passes(tmp_path):
    results = _scan(_scenario("gl004-deploy-with-env.yml"), tmp_path)
    assert results["GL-004"] is True
