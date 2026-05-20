"""Per-rule tests for GHA-062 (sibling IaC OIDC subject broadness).

Each test writes the workflow + sidecar IaC files to a tmp directory
so the rule's filesystem walker exercises real disk I/O.
"""
from __future__ import annotations

import json
import textwrap
from pathlib import Path

import yaml

from pipeline_check.core.checks.github.base import GitHubContext, Workflow
from pipeline_check.core.checks.github.rules import gha062_oidc_iac_subject as mod
from pipeline_check.core.checks.github.workflows import WorkflowChecks


def _ctx_from_disk(workflow_path: Path) -> GitHubContext:
    text = workflow_path.read_text(encoding="utf-8")
    data = yaml.safe_load(text)
    return GitHubContext([Workflow(path=str(workflow_path), data=data or {})])


def _run(workflow_path: Path):
    # Clear the per-scan IaC cache between cases — the test harness
    # invokes the rule multiple times against different tmp roots.
    mod._IAC_SCAN_CACHE.clear()
    ctx = _ctx_from_disk(workflow_path)
    for f in WorkflowChecks(ctx).run():
        if f.check_id == "GHA-062":
            return f
    raise AssertionError("GHA-062 not in orchestrator output")


_OIDC_WORKFLOW = textwrap.dedent("""
    name: deploy
    on:
      push:
        branches: [main]
    permissions:
      id-token: write
      contents: read
    jobs:
      deploy:
        runs-on: ubuntu-latest
        environment: production
        steps:
          - uses: actions/checkout@v4
          - uses: aws-actions/configure-aws-credentials@v4
            with:
              role-to-assume: arn:aws:iam::123456789012:role/prod
              aws-region: us-east-1
""")


def _make_repo(tmp_path: Path) -> Path:
    """Lay out a repo-like tree with .github/workflows/ inside tmp_path."""
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    wf = workflows / "deploy.yml"
    wf.write_text(_OIDC_WORKFLOW, encoding="utf-8")
    return wf


class TestGHA062OIDCSidecar:
    def test_fails_on_aws_trust_policy_with_wildcard_repo(self, tmp_path: Path):
        wf = _make_repo(tmp_path)
        (tmp_path / "iac").mkdir()
        (tmp_path / "iac" / "trust-policy.json").write_text(
            json.dumps({
                "Statement": [{
                    "Effect": "Allow",
                    "Principal": {
                        "Federated": (
                            "arn:aws:iam::123456789012:oidc-provider/"
                            "token.actions.githubusercontent.com"
                        ),
                    },
                    "Action": "sts:AssumeRoleWithWebIdentity",
                    "Condition": {
                        "StringEquals": {
                            "token.actions.githubusercontent.com:aud":
                                "sts.amazonaws.com",
                        },
                        "StringLike": {
                            "token.actions.githubusercontent.com:sub":
                                "repo:*",
                        },
                    },
                }],
            }),
            encoding="utf-8",
        )
        f = _run(wf)
        assert not f.passed
        assert "repo:*" in f.description

    def test_fails_on_aws_trust_policy_with_org_wildcard(self, tmp_path: Path):
        wf = _make_repo(tmp_path)
        (tmp_path / "iam-trust-policy.json").write_text(
            json.dumps({
                "Statement": [{
                    "Effect": "Allow",
                    "Principal": {
                        "Federated":
                            "arn:aws:iam::123456789012:oidc-provider/"
                            "token.actions.githubusercontent.com",
                    },
                    "Action": "sts:AssumeRoleWithWebIdentity",
                    "Condition": {
                        "StringLike": {
                            "token.actions.githubusercontent.com:sub":
                                "repo:myorg/*",
                        },
                    },
                }],
            }),
            encoding="utf-8",
        )
        f = _run(wf)
        assert not f.passed
        assert "myorg/" in f.description

    def test_passes_on_aws_trust_policy_pinned_to_specific_repo(
        self, tmp_path: Path,
    ):
        wf = _make_repo(tmp_path)
        (tmp_path / "trust-policy.json").write_text(
            json.dumps({
                "Statement": [{
                    "Effect": "Allow",
                    "Principal": {
                        "Federated":
                            "arn:aws:iam::123456789012:oidc-provider/"
                            "token.actions.githubusercontent.com",
                    },
                    "Action": "sts:AssumeRoleWithWebIdentity",
                    "Condition": {
                        "StringLike": {
                            "token.actions.githubusercontent.com:sub":
                                "repo:myorg/myrepo:ref:refs/heads/*",
                        },
                    },
                }],
            }),
            encoding="utf-8",
        )
        f = _run(wf)
        assert f.passed

    def test_passes_on_aws_trust_policy_unrelated_principal(
        self, tmp_path: Path,
    ):
        # An IAM trust policy that doesn't reference the GHA OIDC
        # provider is out of scope; even an overly broad sub claim
        # against e.g. GitLab OIDC isn't this rule's domain.
        wf = _make_repo(tmp_path)
        (tmp_path / "trust-policy.json").write_text(
            json.dumps({
                "Statement": [{
                    "Effect": "Allow",
                    "Principal": {
                        "Federated":
                            "arn:aws:iam::123456789012:oidc-provider/"
                            "gitlab.com",
                    },
                    "Action": "sts:AssumeRoleWithWebIdentity",
                    "Condition": {
                        "StringLike": {
                            "gitlab.com:sub": "repo:*",
                        },
                    },
                }],
            }),
            encoding="utf-8",
        )
        f = _run(wf)
        assert f.passed

    def test_fails_on_gcp_wif_terraform_org_prefix(self, tmp_path: Path):
        wf = _make_repo(tmp_path)
        (tmp_path / "iac").mkdir()
        (tmp_path / "iac" / "wif.tf").write_text(
            textwrap.dedent("""
                resource "google_iam_workload_identity_pool_provider" "github" {
                  workload_identity_pool_provider_id = "github"
                  attribute_condition = "attribute.repository.startsWith('myorg/')"
                  oidc { issuer_uri = "https://token.actions.githubusercontent.com" }
                }
            """),
            encoding="utf-8",
        )
        f = _run(wf)
        assert not f.passed
        assert "myorg/" in f.description

    def test_passes_on_gcp_wif_terraform_specific_repo_equality(
        self, tmp_path: Path,
    ):
        wf = _make_repo(tmp_path)
        (tmp_path / "wif.tf").write_text(
            textwrap.dedent("""
                resource "google_iam_workload_identity_pool_provider" "github" {
                  workload_identity_pool_provider_id = "github"
                  attribute_condition = "attribute.repository == 'myorg/myrepo'"
                  oidc { issuer_uri = "https://token.actions.githubusercontent.com" }
                }
            """),
            encoding="utf-8",
        )
        f = _run(wf)
        assert f.passed

    def test_passes_when_workflow_does_not_use_oidc_step(
        self, tmp_path: Path,
    ):
        # No configure-aws-credentials / google-github-actions/auth in
        # the workflow → the sidecar audit doesn't run, even if a
        # broad trust-policy.json is present.
        workflows = tmp_path / ".github" / "workflows"
        workflows.mkdir(parents=True)
        wf = workflows / "build.yml"
        wf.write_text(
            "name: build\non: push\njobs:\n  b:\n    runs-on: ubuntu-latest\n"
            "    steps: [{run: make}]\n",
            encoding="utf-8",
        )
        (tmp_path / "trust-policy.json").write_text(
            json.dumps({
                "Statement": [{
                    "Effect": "Allow",
                    "Principal": {
                        "Federated":
                            "arn:aws:iam::123456789012:oidc-provider/"
                            "token.actions.githubusercontent.com",
                    },
                    "Action": "sts:AssumeRoleWithWebIdentity",
                    "Condition": {
                        "StringLike": {
                            "token.actions.githubusercontent.com:sub":
                                "repo:*",
                        },
                    },
                }],
            }),
            encoding="utf-8",
        )
        f = _run(wf)
        assert f.passed

    def test_passes_when_no_iac_sidecar_present(self, tmp_path: Path):
        wf = _make_repo(tmp_path)
        # Only a stray, non-OIDC trust-policy-looking file: doesn't
        # parse as a GHA-OIDC trust statement.
        (tmp_path / "trust-policy.json").write_text(
            json.dumps({"name": "not a policy doc"}),
            encoding="utf-8",
        )
        f = _run(wf)
        assert f.passed

    def test_skips_node_modules_and_heavy_dirs(self, tmp_path: Path):
        wf = _make_repo(tmp_path)
        # An evil trust-policy under node_modules must NOT be reached
        # by the walker (avoids pathological scans on real repos).
        bad = tmp_path / "node_modules" / "evil"
        bad.mkdir(parents=True)
        (bad / "trust-policy.json").write_text(
            json.dumps({
                "Statement": [{
                    "Effect": "Allow",
                    "Principal": {
                        "Federated":
                            "arn:aws:iam::123456789012:oidc-provider/"
                            "token.actions.githubusercontent.com",
                    },
                    "Condition": {
                        "StringLike": {
                            "token.actions.githubusercontent.com:sub":
                                "repo:*",
                        },
                    },
                }],
            }),
            encoding="utf-8",
        )
        f = _run(wf)
        assert f.passed
