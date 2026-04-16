"""Edge-case coverage for the Azure DevOps parser.

Covers layout branches that the main test file doesn't exercise:

- Flat top-level ``steps:`` shape — the walker must synthesise a single
  virtual job.
- Deployment-strategy ``on.success`` / ``on.failure`` hooks.
- Directory fallback when no canonical ``azure-pipelines.yml`` is
  present.
- Loader resilience against malformed / binary / non-dict files.
"""
from __future__ import annotations

import pytest
import yaml

from pipeline_check.core.checks.azure.base import (
    AzureContext,
    iter_jobs,
    iter_steps,
)

from .conftest import azure_ctx, run_check


def _ctx(text: str) -> AzureContext:
    return azure_ctx(text, path="t.yml")


def _run(text: str, check_id: str):
    return run_check(text, check_id)


class TestShapeSynthesis:
    def test_flat_steps_yields_single_pseudo_job(self):
        doc = yaml.safe_load(
            "steps:\n"
            "  - script: echo hi\n"
            "  - task: DownloadSecureFile@1\n"
        )
        jobs = list(iter_jobs(doc))
        assert len(jobs) == 1
        loc, job = jobs[0]
        assert loc == "<pipeline>"
        # Flat shape jobs iterate their own steps.
        steps = list(iter_steps(job))
        assert [s[0] for s in steps] == ["steps[0]", "steps[1]"]

    def test_flat_steps_script_injection_detected(self):
        f = _run(
            """
            steps:
              - script: echo $(Build.SourceBranchName)
            """,
            "ADO-002",
        )
        assert not f.passed


class TestStrategyHooks:
    def test_on_success_steps_walked(self):
        doc = yaml.safe_load(
            "jobs:\n"
            "  - deployment: D\n"
            "    environment: prod\n"
            "    strategy:\n"
            "      runOnce:\n"
            "        deploy:\n"
            "          steps:\n"
            "            - script: ./deploy.sh\n"
            "        on:\n"
            "          success:\n"
            "            steps:\n"
            "              - script: echo OK\n"
            "          failure:\n"
            "            steps:\n"
            "              - script: echo FAIL\n"
        )
        jobs = list(iter_jobs(doc))
        assert len(jobs) == 1
        step_locs = [loc for loc, _ in iter_steps(jobs[0][1])]
        assert "runOnce.on.success[0]" in step_locs
        assert "runOnce.on.failure[0]" in step_locs

    def test_rolling_strategy_walked(self):
        doc = yaml.safe_load(
            "jobs:\n"
            "  - deployment: D\n"
            "    environment: prod\n"
            "    strategy:\n"
            "      rolling:\n"
            "        preDeploy:\n"
            "          steps:\n"
            "            - script: ./pre.sh\n"
            "        deploy:\n"
            "          steps:\n"
            "            - script: ./deploy.sh\n"
        )
        jobs = list(iter_jobs(doc))
        step_locs = [loc for loc, _ in iter_steps(jobs[0][1])]
        assert "rolling.preDeploy[0]" in step_locs
        assert "rolling.deploy[0]" in step_locs


class TestLoaderResilience:
    def test_directory_with_canonical_file(self, tmp_path):
        (tmp_path / "azure-pipelines.yml").write_text(
            "steps:\n  - script: make\n"
        )
        ctx = AzureContext.from_path(tmp_path)
        assert len(ctx.pipelines) == 1

    def test_directory_fallback_to_any_yaml(self, tmp_path):
        # No canonical file — walker should fall back to any *.yml.
        (tmp_path / "ci.yml").write_text(
            "steps:\n  - script: make\n"
        )
        ctx = AzureContext.from_path(tmp_path)
        assert len(ctx.pipelines) == 1

    def test_missing_path_raises(self, tmp_path):
        with pytest.raises(ValueError, match="does not exist"):
            AzureContext.from_path(tmp_path / "nope")

    def test_malformed_yaml_skipped(self, tmp_path):
        (tmp_path / "azure-pipelines.yml").write_text(
            "steps: [unterminated\n"
        )
        ctx = AzureContext.from_path(tmp_path)
        assert ctx.pipelines == []

    def test_binary_file_skipped(self, tmp_path):
        (tmp_path / "azure-pipelines.yml").write_bytes(b"\xff\xfe\x00binary")
        ctx = AzureContext.from_path(tmp_path)
        assert ctx.pipelines == []

    def test_non_dict_root_skipped(self, tmp_path):
        (tmp_path / "azure-pipelines.yml").write_text("- one\n- two\n")
        ctx = AzureContext.from_path(tmp_path)
        assert ctx.pipelines == []


class TestVariableFormsAndScripts:
    def test_powershell_body_is_scanned_for_injection(self):
        f = _run(
            """
            steps:
              - powershell: Write-Host $(System.PullRequest.PullRequestId)
            """,
            "ADO-002",
        )
        assert not f.passed

    def test_pwsh_body_is_scanned(self):
        f = _run(
            """
            steps:
              - pwsh: Write-Host $(Build.SourceVersionMessage)
            """,
            "ADO-002",
        )
        assert not f.passed

    def test_variables_list_without_value_ignored(self):
        """List form where entries lack `value` shouldn't crash or false-positive."""
        f = _run(
            """
            variables:
              - group: my-group
              - name: X
                value: safe
            steps:
              - script: make
            """,
            "ADO-003",
        )
        assert f.passed
