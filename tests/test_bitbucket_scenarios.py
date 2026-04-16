"""Scenario tests for Bitbucket Pipelines edge cases.

Fixture bodies live under ``tests/fixtures/scenarios/bitbucket/``.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from pipeline_check.core.checks.bitbucket.base import BitbucketContext, Pipeline
from pipeline_check.core.checks.bitbucket.pipelines import BitbucketPipelineChecks

import yaml

SCENARIO_DIR = Path(__file__).parent / "fixtures" / "scenarios" / "bitbucket"


def _scenario(name: str) -> str:
    return (SCENARIO_DIR / name).read_text(encoding="utf-8")


def _scan(text: str, tmp_path: Path):
    data = yaml.safe_load(text)
    ctx = BitbucketContext([Pipeline(path=str(tmp_path / "bitbucket-pipelines.yml"), data=data)])
    return {f.check_id: f.passed for f in BitbucketPipelineChecks(ctx).run()}


# -- BB-002 env-chain taint tracking ------------------------------------------


def test_bb002_flags_env_chain_export(tmp_path):
    results = _scan(_scenario("bb002-env-chain-export-tainted.yml"), tmp_path)
    assert results["BB-002"] is False


def test_bb002_env_chain_safe_not_flagged(tmp_path):
    results = _scan(_scenario("bb002-env-chain-safe.yml"), tmp_path)
    assert results["BB-002"] is True


def test_bb002_env_chain_quoted_safe(tmp_path):
    results = _scan(_scenario("bb002-env-chain-quoted-safe.yml"), tmp_path)
    assert results["BB-002"] is True


def test_bb002_command_sub_bypass_flagged(tmp_path):
    results = _scan(_scenario("bb002-command-sub-bypass.yml"), tmp_path)
    assert results["BB-002"] is False


# -- BB-004 deploy command detection -------------------------------------------


def test_bb004_deploy_command_flagged(tmp_path):
    results = _scan(_scenario("bb004-deploy-command.yml"), tmp_path)
    assert results["BB-004"] is False


def test_bb004_deploy_with_deployment_passes(tmp_path):
    results = _scan(_scenario("bb004-deploy-with-deployment.yml"), tmp_path)
    assert results["BB-004"] is True
