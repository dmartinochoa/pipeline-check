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

    def test_finding_carries_incident_refs_from_rule(self):
        """The orchestrator backfills ``finding.incident_refs`` from
        the rule's ``incident_refs`` so reporters and ``--explain``
        consumers see the same citations regardless of which rule
        path emitted the finding."""
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
        assert f.incident_refs, "GHA-001 should carry populated incident_refs"
        assert any("tj-actions" in ref for ref in f.incident_refs)

    def test_finding_carries_exploit_example_from_rule(self):
        """Same backfill machinery that copies ``incident_refs`` also
        copies ``exploit_example`` from the rule into the finding so
        the JSON / HTML / SARIF reporters can render the proof-of-
        exploit snippet without re-resolving the rule."""
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
        assert f.exploit_example is not None, (
            "GHA-001 should carry a populated exploit_example"
        )
        # Snippet shows both the vulnerable tag-pinned ref and the safe
        # SHA-pinned ref so a reviewer can see the diff.
        assert "tj-actions/changed-files@v45" in f.exploit_example
        assert "tj-actions/changed-files@a284dc1814e3fdd1a3a7f16c11f02e2cd5a98f93" in f.exploit_example

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

    def test_services_options_with_untrusted_context_fails(self):
        # Widening, zizmor proposal #1128.
        # services.<name>.options passes to docker create's argv;
        # ``${{ ... }}`` interpolation of an untrusted context here
        # is a shell-injection sink.
        f = _run(
            """
            on: issues
            jobs:
              build:
                runs-on: ubuntu-latest
                services:
                  db:
                    image: postgres:15
                    options: --hostname=${{ github.event.issue.title }}
                steps:
                  - run: echo build
            """,
            "GHA-003",
        )
        assert not f.passed
        assert "services" in f.description

    def test_services_env_with_untrusted_context_fails(self):
        # services.<name>.env values become container env vars at
        # ``docker create`` time; ``${{ ... }}`` interpolation reaches
        # the docker argv.
        f = _run(
            """
            on: pull_request
            jobs:
              build:
                runs-on: ubuntu-latest
                services:
                  db:
                    image: postgres:15
                    env:
                      FOO: ${{ github.event.pull_request.head.label }}
                steps:
                  - run: echo build
            """,
            "GHA-003",
        )
        assert not f.passed

    def test_services_options_with_safe_string_passes(self):
        f = _run(
            """
            on: push
            jobs:
              build:
                runs-on: ubuntu-latest
                services:
                  db:
                    image: postgres:15
                    options: --health-cmd=pg_isready
                steps:
                  - run: echo build
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

    def test_reusable_workflow_caller_id_token_write_passes(self):
        # Reusable-workflow callers (``jobs.<id>.uses:``) cannot
        # carry ``steps:``. The id-token grant is forwarded to the
        # called workflow, which is the actual OIDC consumer.
        # GHA-004 must not flag the caller as "id-token: write with
        # no OIDC step" or every legitimate slsa-github-generator /
        # attest-build-provenance call would FP.
        f = _run(
            """
            on: push
            permissions:
              contents: read
            jobs:
              provenance:
                permissions:
                  id-token: write
                  contents: write
                uses: slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@v2.1.0
                with:
                  base64-subjects: deadbeef
            """,
            "GHA-004",
        )
        assert f.passed

    def test_docker_build_push_action_with_provenance_passes(self):
        # docker/build-push-action requests an OIDC token when
        # ``provenance: true`` or ``sbom: true`` is set, both of which
        # are signed via Sigstore. GHA-004 must not flag the surrounding
        # job as "id-token: write with no OIDC step".
        f = _run(
            """
            on: push
            permissions:
              contents: read
            jobs:
              publish:
                runs-on: ubuntu-latest
                permissions:
                  id-token: write
                  packages: write
                  contents: read
                steps:
                  - uses: actions/checkout@v4
                  - uses: docker/build-push-action@v7
                    with:
                      push: true
                      provenance: true
                      sbom: true
            """,
            "GHA-004",
        )
        assert f.passed

    def test_docker_build_push_action_without_provenance_fails(self):
        # build-push-action without ``provenance:`` / ``sbom:`` doesn't
        # consume the id-token; granting ``id-token: write`` here is
        # still unjustified.
        f = _run(
            """
            on: push
            permissions:
              contents: read
            jobs:
              publish:
                runs-on: ubuntu-latest
                permissions:
                  id-token: write
                  packages: write
                  contents: read
                steps:
                  - uses: actions/checkout@v4
                  - uses: docker/build-push-action@v7
                    with:
                      push: true
            """,
            "GHA-004",
        )
        assert not f.passed

    def test_scorecard_action_id_token_write_passes(self):
        # ossf/scorecard-action consumes id-token: write when
        # publish_results=true (the OpenSSF Scorecard API auths the
        # publish call via OIDC). GHA-004 must not FP on it.
        f = _run(
            """
            on: push
            permissions:
              contents: read
            jobs:
              analysis:
                permissions:
                  security-events: write
                  id-token: write
                  contents: read
                  actions: read
                runs-on: ubuntu-latest
                steps:
                  - uses: actions/checkout@v4
                  - uses: ossf/scorecard-action@v2.4.3
                    with:
                      publish_results: true
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

    def test_localstack_sentinel_passes(self):
        # LocalStack / Moto integration tests pair AWS_ENDPOINT_URL
        # at localhost with the literal ``test`` access keys; that
        # combination cannot authenticate against real AWS, so the
        # rule must not flag it as a long-lived-key violation.
        f = _run(
            """
            on: workflow_dispatch
            jobs:
              integration:
                runs-on: ubuntu-latest
                steps:
                  - env:
                      AWS_ACCESS_KEY_ID: test
                      AWS_SECRET_ACCESS_KEY: test
                      AWS_DEFAULT_REGION: us-east-1
                      AWS_ENDPOINT_URL: http://localhost:4566
                    run: pytest tests/integration/
            """,
            "GHA-005",
        )
        assert f.passed, (
            "LocalStack env (AWS_ENDPOINT_URL=localhost + sentinel keys) "
            "must not trigger GHA-005"
        )

    def test_real_aws_static_keys_still_fail_even_if_value_is_test(self):
        # ``AWS_ACCESS_KEY_ID: test`` WITHOUT a localhost endpoint is
        # not a LocalStack signal — could be a real key copy-pasted
        # from a doc fixture. Must still fire.
        f = _run(
            """
            on: push
            jobs:
              deploy:
                runs-on: ubuntu-latest
                steps:
                  - env:
                      AWS_ACCESS_KEY_ID: test
                      AWS_SECRET_ACCESS_KEY: test
                    run: aws s3 ls
            """,
            "GHA-005",
        )
        assert not f.passed


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
