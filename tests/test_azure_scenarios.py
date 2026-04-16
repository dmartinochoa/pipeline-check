"""Scenario tests for Azure DevOps Pipelines edge cases.

Fixture bodies live under ``tests/fixtures/scenarios/azure/``.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from pipeline_check.core.checks.azure.base import AzureContext, Pipeline
from pipeline_check.core.checks.azure.pipelines import AzurePipelineChecks

import yaml

SCENARIO_DIR = Path(__file__).parent / "fixtures" / "scenarios" / "azure"


def _scenario(name: str) -> str:
    return (SCENARIO_DIR / name).read_text(encoding="utf-8")


def _scan(text: str, tmp_path: Path):
    data = yaml.safe_load(text)
    ctx = AzureContext([Pipeline(path=str(tmp_path / "azure-pipelines.yml"), data=data)])
    return {f.check_id: f.passed for f in AzurePipelineChecks(ctx).run()}


# ── ADO-002 env-chain taint tracking ─────────────────────────────────


def test_ado002_flags_env_chain_pipeline(tmp_path):
    results = _scan(_scenario("ado002-env-chain-pipeline-tainted.yml"), tmp_path)
    assert results["ADO-002"] is False


def test_ado002_flags_env_chain_list_form(tmp_path):
    results = _scan(_scenario("ado002-env-chain-list-form.yml"), tmp_path)
    assert results["ADO-002"] is False


def test_ado002_env_chain_safe_not_flagged(tmp_path):
    results = _scan(_scenario("ado002-env-chain-safe.yml"), tmp_path)
    assert results["ADO-002"] is True


def test_ado002_flags_env_chain_powershell(tmp_path):
    results = _scan(_scenario("ado002-env-chain-powershell.yml"), tmp_path)
    assert results["ADO-002"] is False


def test_ado002_command_sub_bypass_flagged(tmp_path):
    results = _scan(_scenario("ado002-command-sub-bypass.yml"), tmp_path)
    assert results["ADO-002"] is False


# ── ADO-004 deploy command detection ─────────────────────────────────


def test_ado004_deploy_command_flagged(tmp_path):
    results = _scan(_scenario("ado004-deploy-command.yml"), tmp_path)
    assert results["ADO-004"] is False


def test_ado004_deploy_with_env_passes(tmp_path):
    results = _scan(_scenario("ado004-deploy-with-env.yml"), tmp_path)
    assert results["ADO-004"] is True
