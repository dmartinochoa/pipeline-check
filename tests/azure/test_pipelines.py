"""Unit tests for the Azure DevOps Pipelines provider and checks."""
from __future__ import annotations

import textwrap

import pytest
import yaml

from pipeline_check.core.checks.base import Severity
from pipeline_check.core.checks.azure.base import AzureContext, Pipeline
from pipeline_check.core.checks.azure.pipelines import AzurePipelineChecks


def _ctx(yaml_text: str) -> AzureContext:
    data = yaml.safe_load(textwrap.dedent(yaml_text))
    return AzureContext([Pipeline(path="azure-pipelines.yml", data=data)])


def _run(yaml_text: str, check_id: str):
    findings = AzurePipelineChecks(_ctx(yaml_text)).run()
    return next(f for f in findings if f.check_id == check_id)


class TestADO001TaskPinning:
    def test_major_only_task_fails(self):
        f = _run(
            """
            steps:
              - task: DownloadSecureFile@1
            """,
            "ADO-001",
        )
        assert not f.passed
        assert f.severity == Severity.HIGH

    def test_full_semver_passes(self):
        f = _run(
            """
            steps:
              - task: DownloadSecureFile@1.2.3
            """,
            "ADO-001",
        )
        assert f.passed

    def test_no_task_refs_passes(self):
        f = _run(
            """
            steps:
              - script: echo hi
            """,
            "ADO-001",
        )
        assert f.passed


class TestADO002ScriptInjection:
    def test_source_branch_fails(self):
        f = _run(
            """
            steps:
              - script: echo $(Build.SourceBranchName)
            """,
            "ADO-002",
        )
        assert not f.passed

    def test_pr_source_branch_fails(self):
        f = _run(
            """
            steps:
              - bash: echo $(System.PullRequest.SourceBranch)
            """,
            "ADO-002",
        )
        assert not f.passed

    def test_quoted_assignment_passes(self):
        f = _run(
            """
            steps:
              - script: BRANCH="$(Build.SourceBranchName)"
            """,
            "ADO-002",
        )
        assert f.passed

    def test_safe_variable_passes(self):
        f = _run(
            """
            steps:
              - script: echo "$(Build.BuildNumber)"
            """,
            "ADO-002",
        )
        assert f.passed


class TestADO003LiteralSecrets:
    def test_aws_key_mapping_form_fails(self):
        f = _run(
            """
            variables:
              AWS_ACCESS_KEY_ID: AKIAIOSFODNN7EXAMPLE
            steps:
              - script: make
            """,
            "ADO-003",
        )
        assert not f.passed
        assert f.severity == Severity.CRITICAL

    def test_aws_key_list_form_fails(self):
        f = _run(
            """
            variables:
              - name: AWS_ACCESS_KEY_ID
                value: AKIAIOSFODNN7EXAMPLE
            steps:
              - script: make
            """,
            "ADO-003",
        )
        assert not f.passed

    def test_clean_passes(self):
        f = _run(
            """
            variables:
              buildConfiguration: Release
            steps:
              - script: make
            """,
            "ADO-003",
        )
        assert f.passed


class TestADO004DeploymentEnv:
    def test_deployment_without_env_fails(self):
        f = _run(
            """
            jobs:
              - deployment: DeployWeb
                strategy:
                  runOnce:
                    deploy:
                      steps:
                        - script: ./deploy.sh
            """,
            "ADO-004",
        )
        assert not f.passed

    def test_deployment_with_env_passes(self):
        f = _run(
            """
            jobs:
              - deployment: DeployWeb
                environment: production
                strategy:
                  runOnce:
                    deploy:
                      steps:
                        - script: ./deploy.sh
            """,
            "ADO-004",
        )
        assert f.passed

    def test_regular_job_ignored(self):
        f = _run(
            """
            jobs:
              - job: Build
                steps:
                  - script: make
            """,
            "ADO-004",
        )
        assert f.passed


class TestADO005ContainerPinning:
    def test_resources_container_floating_fails(self):
        f = _run(
            """
            resources:
              containers:
                - container: py
                  image: python:latest
            jobs:
              - job: Build
                container: py
                steps:
                  - script: make
            """,
            "ADO-005",
        )
        assert not f.passed

    def test_resources_container_pinned_passes(self):
        f = _run(
            """
            resources:
              containers:
                - container: py
                  image: python:3.12.1-slim
            jobs:
              - job: Build
                container: py
                steps:
                  - script: make
            """,
            "ADO-005",
        )
        assert f.passed

    def test_per_job_container_dict_fails(self):
        f = _run(
            """
            jobs:
              - job: Build
                container:
                  image: python:latest
                steps:
                  - script: make
            """,
            "ADO-005",
        )
        assert not f.passed

    def test_per_job_container_digest_passes(self):
        sha = "a" * 64
        f = _run(
            f"""
            jobs:
              - job: Build
                container:
                  image: python@sha256:{sha}
                steps:
                  - script: make
            """,
            "ADO-005",
        )
        assert f.passed

    def test_no_container_passes(self):
        f = _run(
            """
            steps:
              - script: make
            """,
            "ADO-005",
        )
        assert f.passed


class TestAzureProvider:
    def test_requires_path(self):
        from pipeline_check.core.providers.azure import AzureProvider
        with pytest.raises(ValueError, match="azure-path"):
            AzureProvider().build_context()

    def test_loads_from_file(self, tmp_path):
        from pipeline_check.core.providers.azure import AzureProvider
        p = tmp_path / "azure-pipelines.yml"
        p.write_text("steps:\n  - script: make\n")
        ctx = AzureProvider().build_context(azure_path=str(p))
        assert len(ctx.pipelines) == 1


class TestStagedPipeline:
    """Ensures the walker reaches every job nested under stages."""

    def test_ado001_reaches_staged_task(self):
        f = _run(
            """
            stages:
              - stage: Build
                jobs:
                  - job: B
                    steps:
                      - task: DotNetCoreCLI@2
              - stage: Deploy
                jobs:
                  - deployment: D
                    environment: prod
                    strategy:
                      runOnce:
                        deploy:
                          steps:
                            - task: AzureWebApp@1
            """,
            "ADO-001",
        )
        # Both tasks are major-only — should fail.
        assert not f.passed

    def test_ado002_reaches_deployment_strategy_steps(self):
        f = _run(
            """
            jobs:
              - deployment: D
                environment: prod
                strategy:
                  runOnce:
                    deploy:
                      steps:
                        - script: echo $(Build.SourceVersionMessage)
            """,
            "ADO-002",
        )
        assert not f.passed
