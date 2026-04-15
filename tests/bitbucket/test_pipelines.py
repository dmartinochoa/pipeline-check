"""Unit tests for the Bitbucket Pipelines provider and checks."""
from __future__ import annotations

import textwrap

import pytest
import yaml

from pipeline_check.core.checks.base import Severity
from pipeline_check.core.checks.bitbucket.base import BitbucketContext, Pipeline
from pipeline_check.core.checks.bitbucket.pipelines import BitbucketPipelineChecks


def _ctx(yaml_text: str) -> BitbucketContext:
    data = yaml.safe_load(textwrap.dedent(yaml_text))
    return BitbucketContext([Pipeline(path="bitbucket-pipelines.yml", data=data)])


def _run(yaml_text: str, check_id: str):
    findings = BitbucketPipelineChecks(_ctx(yaml_text)).run()
    return next(f for f in findings if f.check_id == check_id)


class TestBB001PipePinning:
    def test_major_only_tag_fails(self):
        f = _run(
            """
            pipelines:
              default:
                - step:
                    script:
                      - pipe: atlassian/aws-s3-deploy:1
            """,
            "BB-001",
        )
        assert not f.passed
        assert f.severity == Severity.HIGH

    def test_full_semver_passes(self):
        f = _run(
            """
            pipelines:
              default:
                - step:
                    script:
                      - pipe: atlassian/aws-s3-deploy:1.4.0
            """,
            "BB-001",
        )
        assert f.passed

    def test_digest_passes(self):
        f = _run(
            """
            pipelines:
              default:
                - step:
                    script:
                      - pipe: atlassian/aws-s3-deploy@sha256:deadbeef
            """,
            "BB-001",
        )
        assert f.passed


class TestBB002ScriptInjection:
    def test_branch_interpolation_fails(self):
        f = _run(
            """
            pipelines:
              default:
                - step:
                    script:
                      - echo $BITBUCKET_BRANCH
            """,
            "BB-002",
        )
        assert not f.passed

    def test_quoted_assignment_passes(self):
        f = _run(
            """
            pipelines:
              default:
                - step:
                    script:
                      - BRANCH="$BITBUCKET_BRANCH"
            """,
            "BB-002",
        )
        assert f.passed

    def test_safe_var_passes(self):
        f = _run(
            """
            pipelines:
              default:
                - step:
                    script:
                      - echo "$BITBUCKET_COMMIT"
            """,
            "BB-002",
        )
        assert f.passed


class TestBB003LiteralSecrets:
    def test_aws_key_fails_critical(self):
        f = _run(
            """
            definitions:
              variables:
                MY_KEY: AKIAIOSFODNN7EXAMPLE
            pipelines:
              default:
                - step:
                    script: [make]
            """,
            "BB-003",
        )
        assert not f.passed
        assert f.severity == Severity.CRITICAL

    def test_clean_passes(self):
        f = _run(
            """
            pipelines:
              default:
                - step:
                    script: [make]
            """,
            "BB-003",
        )
        assert f.passed


class TestBB004DeployEnv:
    def test_deploy_without_deployment_fails(self):
        f = _run(
            """
            pipelines:
              default:
                - step:
                    name: Deploy to production
                    script: [./deploy.sh]
            """,
            "BB-004",
        )
        assert not f.passed

    def test_deployment_declared_passes(self):
        f = _run(
            """
            pipelines:
              default:
                - step:
                    name: Deploy to production
                    deployment: production
                    script: [./deploy.sh]
            """,
            "BB-004",
        )
        assert f.passed

    def test_non_deploy_step_passes(self):
        f = _run(
            """
            pipelines:
              default:
                - step:
                    name: Run tests
                    script: [pytest]
            """,
            "BB-004",
        )
        assert f.passed


class TestBB005MaxTime:
    def test_missing_fails(self):
        f = _run(
            """
            pipelines:
              default:
                - step:
                    script: [make]
            """,
            "BB-005",
        )
        assert not f.passed

    def test_present_passes(self):
        f = _run(
            """
            pipelines:
              default:
                - step:
                    max-time: 30
                    script: [make]
            """,
            "BB-005",
        )
        assert f.passed


class TestBitbucketProvider:
    def test_requires_path(self):
        from pipeline_check.core.providers.bitbucket import BitbucketProvider
        with pytest.raises(ValueError, match="bitbucket-path"):
            BitbucketProvider().build_context()

    def test_loads_from_file(self, tmp_path):
        from pipeline_check.core.providers.bitbucket import BitbucketProvider
        p = tmp_path / "bitbucket-pipelines.yml"
        p.write_text("pipelines:\n  default:\n    - step:\n        script: [make]\n")
        ctx = BitbucketProvider().build_context(bitbucket_path=str(p))
        assert len(ctx.pipelines) == 1
