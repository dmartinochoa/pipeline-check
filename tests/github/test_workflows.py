"""Unit tests for the GitHub Actions provider and workflow checks."""
from __future__ import annotations

import textwrap

import pytest

from pipeline_check.core.checks.base import Severity
from pipeline_check.core.checks.github.base import GitHubContext, Workflow
from pipeline_check.core.checks.github.workflows import WorkflowChecks
from pipeline_check.core.providers.github import GitHubProvider


def _ctx(yaml_text: str) -> GitHubContext:
    import yaml

    data = yaml.safe_load(textwrap.dedent(yaml_text))
    return GitHubContext([Workflow(path="wf.yml", data=data)])


def _run(yaml_text: str, check_id: str):
    findings = WorkflowChecks(_ctx(yaml_text)).run()
    return next(f for f in findings if f.check_id == check_id)


class TestGHA001PinnedActions:
    def test_tag_ref_fails(self):
        f = _run(
            """
            on: push
            jobs:
              build:
                runs-on: ubuntu-latest
                steps:
                  - uses: actions/checkout@v4
            """,
            "GHA-001",
        )
        assert not f.passed
        assert f.severity == Severity.HIGH

    def test_sha_ref_passes(self):
        sha = "a" * 40
        f = _run(
            f"""
            on: push
            jobs:
              build:
                runs-on: ubuntu-latest
                steps:
                  - uses: actions/checkout@{sha}
            """,
            "GHA-001",
        )
        assert f.passed

    def test_docker_ref_ignored(self):
        f = _run(
            """
            on: push
            jobs:
              build:
                runs-on: ubuntu-latest
                steps:
                  - uses: docker://alpine:3.19
            """,
            "GHA-001",
        )
        assert f.passed

    def test_local_ref_ignored(self):
        f = _run(
            """
            on: push
            jobs:
              build:
                runs-on: ubuntu-latest
                steps:
                  - uses: ./.github/actions/local
            """,
            "GHA-001",
        )
        assert f.passed


class TestGHA002PullRequestTarget:
    def test_checkout_of_head_ref_fails(self):
        f = _run(
            """
            on: pull_request_target
            jobs:
              build:
                runs-on: ubuntu-latest
                steps:
                  - uses: actions/checkout@v4
                    with:
                      ref: ${{ github.event.pull_request.head.sha }}
            """,
            "GHA-002",
        )
        assert not f.passed
        assert f.severity == Severity.CRITICAL

    def test_checkout_of_head_ref_ref_value_fails(self):
        f = _run(
            """
            on: pull_request_target
            jobs:
              build:
                runs-on: ubuntu-latest
                steps:
                  - uses: actions/checkout@v4
                    with:
                      ref: ${{ github.event.pull_request.head.ref }}
            """,
            "GHA-002",
        )
        assert not f.passed

    def test_pull_request_target_without_head_checkout_passes(self):
        f = _run(
            """
            on: pull_request_target
            jobs:
              label:
                runs-on: ubuntu-latest
                steps:
                  - uses: actions/checkout@v4
            """,
            "GHA-002",
        )
        assert f.passed

    def test_plain_pull_request_passes(self):
        f = _run(
            """
            on: pull_request
            jobs:
              build:
                runs-on: ubuntu-latest
                steps:
                  - uses: actions/checkout@v4
                    with:
                      ref: ${{ github.event.pull_request.head.sha }}
            """,
            "GHA-002",
        )
        assert f.passed


class TestGHA003ScriptInjection:
    def test_pr_title_in_run_fails(self):
        f = _run(
            """
            on: pull_request_target
            jobs:
              build:
                runs-on: ubuntu-latest
                steps:
                  - run: echo "${{ github.event.pull_request.title }}"
            """,
            "GHA-003",
        )
        assert not f.passed
        assert f.severity == Severity.HIGH

    def test_issue_body_in_run_fails(self):
        f = _run(
            """
            on: issues
            jobs:
              build:
                runs-on: ubuntu-latest
                steps:
                  - run: echo "${{ github.event.issue.body }}"
            """,
            "GHA-003",
        )
        assert not f.passed

    def test_run_via_env_passes(self):
        f = _run(
            """
            on: pull_request_target
            jobs:
              build:
                runs-on: ubuntu-latest
                steps:
                  - env:
                      TITLE: ${{ github.event.pull_request.title }}
                    run: echo "$TITLE"
            """,
            "GHA-003",
        )
        assert f.passed


class TestGHA004Permissions:
    def test_missing_permissions_fails(self):
        f = _run(
            """
            on: push
            jobs:
              build:
                runs-on: ubuntu-latest
                steps:
                  - run: echo hi
            """,
            "GHA-004",
        )
        assert not f.passed
        assert f.severity == Severity.MEDIUM

    def test_top_level_permissions_passes(self):
        f = _run(
            """
            on: push
            permissions:
              contents: read
            jobs:
              build:
                runs-on: ubuntu-latest
                steps:
                  - run: echo hi
            """,
            "GHA-004",
        )
        assert f.passed

    def test_every_job_permissions_passes(self):
        f = _run(
            """
            on: push
            jobs:
              build:
                runs-on: ubuntu-latest
                permissions:
                  contents: read
                steps:
                  - run: echo hi
            """,
            "GHA-004",
        )
        assert f.passed


class TestGHA005AwsCredentials:
    def test_static_access_keys_in_with_fails(self):
        f = _run(
            """
            on: push
            jobs:
              deploy:
                runs-on: ubuntu-latest
                steps:
                  - uses: aws-actions/configure-aws-credentials@v4
                    with:
                      aws-access-key-id: ${{ secrets.AWS_ACCESS_KEY_ID }}
                      aws-secret-access-key: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
                      aws-region: us-east-1
            """,
            "GHA-005",
        )
        assert not f.passed

    def test_oidc_role_passes(self):
        f = _run(
            """
            on: push
            jobs:
              deploy:
                runs-on: ubuntu-latest
                steps:
                  - uses: aws-actions/configure-aws-credentials@v4
                    with:
                      role-to-assume: arn:aws:iam::123:role/gh-oidc
                      aws-region: us-east-1
            """,
            "GHA-005",
        )
        assert f.passed

    def test_env_access_key_reference_fails(self):
        f = _run(
            """
            on: push
            jobs:
              deploy:
                runs-on: ubuntu-latest
                steps:
                  - env:
                      AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ACCESS_KEY_ID }}
                    run: aws s3 ls
            """,
            "GHA-005",
        )
        assert not f.passed

    def test_workflow_without_aws_passes(self):
        f = _run(
            """
            on: push
            jobs:
              build:
                runs-on: ubuntu-latest
                steps:
                  - run: echo hi
            """,
            "GHA-005",
        )
        assert f.passed


class TestContextLoading:
    def test_loads_yaml_files_from_directory(self, tmp_path):
        wf_dir = tmp_path / "workflows"
        wf_dir.mkdir()
        (wf_dir / "a.yml").write_text("on: push\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo\n")
        (wf_dir / "b.yaml").write_text("on: push\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo\n")
        (wf_dir / "ignored.txt").write_text("not yaml")
        ctx = GitHubContext.from_path(wf_dir)
        assert len(ctx.workflows) == 2

    def test_single_file_path_supported(self, tmp_path):
        wf = tmp_path / "wf.yml"
        wf.write_text("on: push\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo\n")
        ctx = GitHubContext.from_path(wf)
        assert len(ctx.workflows) == 1

    def test_missing_path_raises(self, tmp_path):
        with pytest.raises(ValueError):
            GitHubContext.from_path(tmp_path / "nope")

    def test_invalid_yaml_is_skipped(self, tmp_path):
        wf_dir = tmp_path / "workflows"
        wf_dir.mkdir()
        (wf_dir / "bad.yml").write_text(":not: [valid")
        (wf_dir / "good.yml").write_text("on: push\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo\n")
        ctx = GitHubContext.from_path(wf_dir)
        assert [w.path.endswith("good.yml") for w in ctx.workflows] == [True]


class TestProvider:
    def test_requires_gha_path(self):
        with pytest.raises(ValueError):
            GitHubProvider().build_context()

    def test_registered(self):
        from pipeline_check.core import providers
        assert "github" in providers.available()
        assert providers.get("github").check_classes == [WorkflowChecks]
