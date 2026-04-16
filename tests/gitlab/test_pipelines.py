"""Unit tests for the GitLab CI provider and pipeline checks."""
from __future__ import annotations

import textwrap

import pytest
import yaml

from pipeline_check.core.checks.base import Severity
from pipeline_check.core.checks.gitlab.base import GitLabContext, Pipeline
from pipeline_check.core.checks.gitlab.pipelines import GitLabPipelineChecks


def _ctx(yaml_text: str) -> GitLabContext:
    data = yaml.safe_load(textwrap.dedent(yaml_text))
    return GitLabContext([Pipeline(path=".gitlab-ci.yml", data=data)])


def _run(yaml_text: str, check_id: str):
    findings = GitLabPipelineChecks(_ctx(yaml_text)).run()
    return next(f for f in findings if f.check_id == check_id)


class TestGL001ImagePinning:
    def test_latest_tag_fails(self):
        f = _run(
            """
            image: python:latest
            build:
              script: [make]
            """,
            "GL-001",
        )
        assert not f.passed
        assert f.severity == Severity.HIGH

    def test_no_tag_fails(self):
        f = _run(
            """
            build:
              image: python
              script: [make]
            """,
            "GL-001",
        )
        assert not f.passed

    def test_specific_version_passes(self):
        f = _run(
            """
            image: python:3.12.1-slim
            build:
              script: [make]
            """,
            "GL-001",
        )
        assert f.passed

    def test_digest_passes(self):
        f = _run(
            """
            image: python@sha256:""" + "a" * 64 + """
            build:
              script: [make]
            """,
            "GL-001",
        )
        assert f.passed


class TestGL002ScriptInjection:
    def test_commit_message_interpolation_fails(self):
        f = _run(
            """
            build:
              script:
                - echo $CI_COMMIT_MESSAGE
            """,
            "GL-002",
        )
        assert not f.passed
        assert f.severity == Severity.HIGH

    def test_mr_title_interpolation_fails(self):
        f = _run(
            """
            build:
              script:
                - echo "${CI_MERGE_REQUEST_TITLE}"
            """,
            "GL-002",
        )
        assert not f.passed

    def test_safe_variable_passes(self):
        f = _run(
            """
            build:
              script:
                - echo "$CI_JOB_ID"
            """,
            "GL-002",
        )
        assert f.passed


class TestGL003LiteralSecrets:
    def test_aws_key_fails_critical(self):
        f = _run(
            """
            variables:
              MY_KEY: AKIAIOSFODNN7EXAMPLE
            build:
              script: [make]
            """,
            "GL-003",
        )
        assert not f.passed
        assert f.severity == Severity.CRITICAL

    def test_password_key_fails(self):
        f = _run(
            """
            variables:
              DATABASE_PASSWORD: hunter2
            build:
              script: [make]
            """,
            "GL-003",
        )
        assert not f.passed

    def test_variable_reference_passes(self):
        f = _run(
            """
            variables:
              DATABASE_PASSWORD: $DB_PASS_FROM_CI
            build:
              script: [make]
            """,
            "GL-003",
        )
        assert f.passed


class TestGL004DeployGating:
    def test_ungated_deploy_fails(self):
        f = _run(
            """
            deploy_prod:
              stage: deploy
              script: [./deploy.sh]
            """,
            "GL-004",
        )
        assert not f.passed
        assert f.severity == Severity.MEDIUM

    def test_manual_passes(self):
        f = _run(
            """
            deploy_prod:
              stage: deploy
              script: [./deploy.sh]
              when: manual
            """,
            "GL-004",
        )
        assert f.passed

    def test_environment_passes(self):
        f = _run(
            """
            deploy_prod:
              stage: deploy
              script: [./deploy.sh]
              environment:
                name: production
            """,
            "GL-004",
        )
        assert f.passed


class TestGL005IncludePinning:
    def test_project_unpinned_fails(self):
        f = _run(
            """
            include:
              - project: 'acme/ci-templates'
            build:
              script: [make]
            """,
            "GL-005",
        )
        assert not f.passed

    def test_project_on_main_fails(self):
        f = _run(
            """
            include:
              - project: 'acme/ci-templates'
                ref: main
            build:
              script: [make]
            """,
            "GL-005",
        )
        assert not f.passed

    def test_project_tag_passes(self):
        f = _run(
            """
            include:
              - project: 'acme/ci-templates'
                ref: v1.2.3
            build:
              script: [make]
            """,
            "GL-005",
        )
        assert f.passed

    def test_no_include_passes(self):
        f = _run(
            """
            build:
              script: [make]
            """,
            "GL-005",
        )
        assert f.passed


class TestGitLabProvider:
    def test_requires_path(self):
        from pipeline_check.core.providers.gitlab import GitLabProvider
        with pytest.raises(ValueError, match="gitlab-path"):
            GitLabProvider().build_context()

    def test_loads_from_file(self, tmp_path):
        from pipeline_check.core.providers.gitlab import GitLabProvider
        p = tmp_path / ".gitlab-ci.yml"
        p.write_text("build:\n  script: [make]\n")
        ctx = GitLabProvider().build_context(gitlab_path=str(p))
        assert len(ctx.pipelines) == 1
