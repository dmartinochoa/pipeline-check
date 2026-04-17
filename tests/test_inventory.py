"""Tests for the component inventory feature (--inventory flag)."""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from click.testing import CliRunner

from pipeline_check.cli import scan
from pipeline_check.core import providers as _providers
from pipeline_check.core.checks.cloudformation.base import CloudFormationContext
from pipeline_check.core.checks.terraform.base import TerraformContext
from pipeline_check.core.inventory import Component
from pipeline_check.core.reporter import report_inventory_terminal, report_json
from pipeline_check.core.scanner import Scanner


# ─── Component dataclass ────────────────────────────────────────────────────

def test_component_to_dict_round_trip():
    c = Component(
        provider="terraform", type="aws_iam_role", identifier="ci",
        source="aws_iam_role.ci", metadata={"arn": "arn:aws:iam::1:role/ci"},
    )
    d = c.to_dict()
    assert d == {
        "provider": "terraform",
        "type": "aws_iam_role",
        "identifier": "ci",
        "source": "aws_iam_role.ci",
        "metadata": {"arn": "arn:aws:iam::1:role/ci"},
    }


# ─── BaseProvider.inventory default ────────────────────────────────────────

def test_baseprovider_default_inventory_is_empty():
    from pipeline_check.core.providers.base import BaseProvider

    class _Dummy(BaseProvider):
        NAME = "dummy"

        def build_context(self, **_):
            return None

        @property
        def check_classes(self):
            return []

    assert _Dummy().inventory(object()) == []


# ─── Terraform inventory ───────────────────────────────────────────────────

def _tf_plan(resources):
    return {
        "planned_values": {
            "root_module": {"resources": resources, "child_modules": []}
        }
    }


def test_terraform_inventory_lists_resources():
    plan = _tf_plan([
        {
            "address": "aws_codebuild_project.app", "mode": "managed",
            "type": "aws_codebuild_project", "name": "app", "values": {},
        },
        {
            "address": "aws_iam_role.ci", "mode": "managed",
            "type": "aws_iam_role", "name": "ci", "values": {},
        },
    ])
    ctx = TerraformContext(plan)
    provider = _providers.get("terraform")
    inv = provider.inventory(ctx)
    assert len(inv) == 2
    assert {c.type for c in inv} == {"aws_codebuild_project", "aws_iam_role"}
    assert {c.identifier for c in inv} == {"app", "ci"}
    assert all(c.provider == "terraform" for c in inv)


def test_terraform_inventory_empty_plan():
    ctx = TerraformContext(_tf_plan([]))
    assert _providers.get("terraform").inventory(ctx) == []


# ─── CloudFormation inventory ──────────────────────────────────────────────

def _cfn_ctx(resources):
    ctx = CloudFormationContext.__new__(CloudFormationContext)
    ctx._templates = [("<test>", {"Resources": resources})]
    from pipeline_check.core.checks.cloudformation.base import _iter_resources
    ctx._resources = list(_iter_resources(ctx._templates))
    return ctx


def test_cloudformation_inventory_preserves_lifecycle_metadata():
    ctx = _cfn_ctx({
        "Bucket": {
            "Type": "AWS::S3::Bucket",
            "DeletionPolicy": "Retain",
            "UpdateReplacePolicy": "Retain",
            "Properties": {"BucketName": "foo"},
        },
        "Role": {"Type": "AWS::IAM::Role", "Properties": {}},
    })
    inv = _providers.get("cloudformation").inventory(ctx)
    by_id = {c.identifier: c for c in inv}
    assert set(by_id) == {"Bucket", "Role"}
    assert by_id["Bucket"].type == "AWS::S3::Bucket"
    # Lifecycle attrs appear alongside any per-type metadata — containment check.
    assert by_id["Bucket"].metadata["DeletionPolicy"] == "Retain"
    assert by_id["Bucket"].metadata["UpdateReplacePolicy"] == "Retain"
    assert by_id["Bucket"].metadata["bucket_name"] == "foo"


def test_cloudformation_inventory_captures_iam_role_stats():
    ctx = _cfn_ctx({
        "R": {
            "Type": "AWS::IAM::Role",
            "Properties": {
                "PermissionsBoundary": "arn:aws:iam::1:policy/pb",
                "ManagedPolicyArns": ["arn:aws:iam::aws:policy/ReadOnlyAccess"],
                "Policies": [{"PolicyName": "inline", "PolicyDocument": {}}],
            },
        },
    })
    inv = _providers.get("cloudformation").inventory(ctx)
    m = inv[0].metadata
    assert m["permissions_boundary"] is True
    assert m["managed_policy_count"] == 1
    assert m["inline_policy_count"] == 1


def test_cloudformation_inventory_normalises_tags():
    ctx = _cfn_ctx({
        "B": {
            "Type": "AWS::S3::Bucket",
            "Properties": {
                "BucketName": "x",
                "Tags": [
                    {"Key": "Environment", "Value": "prod"},
                    {"Key": "Owner", "Value": "team-a"},
                ],
            },
        },
    })
    inv = _providers.get("cloudformation").inventory(ctx)
    assert inv[0].metadata["tags"] == {"Environment": "prod", "Owner": "team-a"}


# ─── GitHub workflow inventory ─────────────────────────────────────────────

def test_github_inventory_from_path(tmp_path):
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    (wf_dir / "ci.yml").write_text(
        "name: CI\non: [push, pull_request]\n"
        "permissions:\n  contents: read\n"
        "jobs:\n  build:\n    runs-on: ubuntu-latest\n    environment: prod\n    steps: []\n"
    )
    (wf_dir / "release.yml").write_text(
        "name: Release\non: [push]\njobs:\n  publish:\n    runs-on: ubuntu-latest\n    steps: []\n"
    )
    scanner = Scanner(pipeline="github", gha_path=str(wf_dir))
    inv = scanner.inventory()
    assert len(inv) == 2
    assert {c.identifier for c in inv} == {"CI", "Release"}
    build = next(c for c in inv if c.identifier == "CI")
    assert build.metadata["jobs"] == ["build"]
    assert build.metadata["runners"] == ["ubuntu-latest"]
    assert build.metadata["environments"] == ["prod"]
    assert set(build.metadata["triggers"]) == {"push", "pull_request"}
    assert build.metadata["permissions"] == "scoped"


# ─── Jenkins inventory ─────────────────────────────────────────────────────

def test_jenkins_inventory_preserves_stages_and_libraries(tmp_path):
    jf = tmp_path / "Jenkinsfile"
    jf.write_text(
        "@Library('shared-pipeline@v1.4.2') _\n"
        "pipeline {\n"
        "  agent any\n"
        "  stages {\n"
        "    stage('Build') { steps { sh 'make build' } }\n"
        "    stage('Deploy') { steps { sh 'make deploy' } }\n"
        "  }\n"
        "}\n"
    )
    scanner = Scanner(pipeline="jenkins", jenkinsfile_path=str(jf))
    inv = scanner.inventory()
    assert len(inv) == 1
    c = inv[0]
    assert c.type == "jenkinsfile"
    assert c.metadata.get("stages") == ["Build", "Deploy"]
    assert c.metadata.get("library_refs") == ["shared-pipeline@v1.4.2"]


# ─── GitLab / Bitbucket / Azure / CircleCI ─────────────────────────────────

def test_gitlab_inventory_lists_jobs(tmp_path):
    cfg = tmp_path / ".gitlab-ci.yml"
    cfg.write_text(
        "stages:\n  - build\n  - test\n"
        "build-job:\n  stage: build\n  script:\n    - make build\n"
        "test-job:\n  stage: test\n  script:\n    - make test\n"
    )
    scanner = Scanner(pipeline="gitlab", gitlab_path=str(cfg))
    inv = scanner.inventory()
    assert len(inv) == 1
    assert sorted(inv[0].metadata.get("jobs", [])) == ["build-job", "test-job"]


def test_bitbucket_inventory_lists_categories(tmp_path):
    cfg = tmp_path / "bitbucket-pipelines.yml"
    cfg.write_text(
        "pipelines:\n"
        "  default:\n"
        "    - step:\n        script:\n          - echo default\n"
        "  branches:\n"
        "    main:\n"
        "      - step:\n          script:\n            - echo main\n"
    )
    scanner = Scanner(pipeline="bitbucket", bitbucket_path=str(cfg))
    inv = scanner.inventory()
    assert len(inv) == 1
    assert "default" in inv[0].metadata.get("categories", [])
    assert "branches" in inv[0].metadata.get("categories", [])


def test_azure_inventory_lists_stages(tmp_path):
    cfg = tmp_path / "azure-pipelines.yml"
    cfg.write_text(
        "name: app\n"
        "stages:\n"
        "  - stage: Build\n    jobs:\n      - job: b\n        steps: []\n"
        "  - stage: Deploy\n    jobs:\n      - job: d\n        steps: []\n"
    )
    scanner = Scanner(pipeline="azure", azure_path=str(cfg))
    inv = scanner.inventory()
    assert len(inv) == 1
    assert inv[0].identifier == "app"
    assert inv[0].metadata.get("stages") == ["Build", "Deploy"]


def test_circleci_inventory_lists_jobs_and_workflows(tmp_path):
    cfg_dir = tmp_path / ".circleci"
    cfg_dir.mkdir()
    (cfg_dir / "config.yml").write_text(
        "version: 2.1\n"
        "jobs:\n"
        "  build:\n    docker: [{image: cimg/base:stable}]\n    steps: [checkout]\n"
        "workflows:\n"
        "  main:\n    jobs: [build]\n"
    )
    scanner = Scanner(pipeline="circleci", circleci_path=str(cfg_dir / "config.yml"))
    inv = scanner.inventory()
    assert len(inv) == 1
    assert inv[0].metadata.get("jobs") == ["build"]
    assert inv[0].metadata.get("workflows") == ["main"]


# ─── JSON reporter ─────────────────────────────────────────────────────────

def test_json_report_omits_inventory_when_not_supplied():
    out = report_json([], score_result={"score": 100, "grade": "A"}, tool_version="x")
    payload = json.loads(out)
    assert "inventory" not in payload


def test_json_report_includes_empty_inventory_when_supplied():
    out = report_json(
        [], score_result={"score": 100, "grade": "A"},
        tool_version="x", inventory=[],
    )
    payload = json.loads(out)
    assert payload["inventory"] == []


def test_json_report_serialises_components():
    comp = Component(provider="terraform", type="aws_s3_bucket", identifier="art",
                     source="aws_s3_bucket.art")
    out = report_json([], {"score": 100, "grade": "A"}, tool_version="x", inventory=[comp])
    payload = json.loads(out)
    assert payload["inventory"] == [{
        "provider": "terraform",
        "type": "aws_s3_bucket",
        "identifier": "art",
        "source": "aws_s3_bucket.art",
        "metadata": {},
    }]


# ─── Terminal reporter ─────────────────────────────────────────────────────

def test_inventory_terminal_empty_shows_placeholder(capsys):
    from rich.console import Console
    console = Console()
    report_inventory_terminal([], console=console)
    captured = capsys.readouterr()
    assert "no components" in captured.out.lower()


def test_inventory_terminal_renders_rows(capsys):
    from rich.console import Console
    console = Console(width=200)
    comp = Component(provider="cloudformation", type="AWS::S3::Bucket",
                     identifier="Art", source="AWS::S3::Bucket.Art")
    report_inventory_terminal([comp], console=console)
    captured = capsys.readouterr()
    assert "AWS::S3::Bucket" in captured.out
    assert "Art" in captured.out


# ─── CLI integration ───────────────────────────────────────────────────────

_CFN_TEMPLATE = (
    "Resources:\n"
    "  Bucket:\n"
    "    Type: AWS::S3::Bucket\n"
    "    DeletionPolicy: Retain\n"
    "    Properties:\n"
    "      BucketName: art\n"
)


def _extract_json_payload(output: str) -> dict:
    """Isolate the trailing JSON object from CliRunner output.

    The CLI emits an ``[auto] using --cfn-template ...`` banner on stderr
    which the default CliRunner merges into stdout. Split on the first
    ``{`` and parse from there.
    """
    start = output.find("{")
    assert start != -1, f"No JSON object in output: {output!r}"
    return json.loads(output[start:])


def test_cli_inventory_flag_adds_inventory_to_json(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "template.yml").write_text(_CFN_TEMPLATE)
    result = CliRunner().invoke(
        scan,
        ["--pipeline", "cloudformation", "--output", "json", "--inventory"],
    )
    assert result.exit_code in (0, 1), result.output
    payload = _extract_json_payload(result.output)
    assert "inventory" in payload
    assert any(
        c["type"] == "AWS::S3::Bucket" and c["identifier"] == "Bucket"
        for c in payload["inventory"]
    )


def test_cli_without_inventory_flag_omits_inventory(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "template.yml").write_text(_CFN_TEMPLATE)
    result = CliRunner().invoke(
        scan,
        ["--pipeline", "cloudformation", "--output", "json"],
    )
    assert result.exit_code in (0, 1), result.output
    payload = _extract_json_payload(result.output)
    assert "inventory" not in payload


# ─── AWS runtime inventory ────────────────────────────────────────────────

# ─── Richer metadata on other providers ─────────────────────────────────────

def test_terraform_inventory_enriches_codebuild_metadata():
    plan = _tf_plan([
        {
            "address": "aws_codebuild_project.app", "mode": "managed",
            "type": "aws_codebuild_project", "name": "app",
            "values": {
                "environment": [{
                    "image": "aws/codebuild/standard:7.0",
                    "compute_type": "BUILD_GENERAL1_SMALL",
                    "privileged_mode": True,
                }],
                "source": [{"type": "GITHUB"}],
                "build_timeout": 60,
                "tags": {"Env": "prod"},
            },
        },
    ])
    comp = _providers.get("terraform").inventory(TerraformContext(plan))[0]
    assert comp.metadata["image"] == "aws/codebuild/standard:7.0"
    assert comp.metadata["compute_type"] == "BUILD_GENERAL1_SMALL"
    assert comp.metadata["privileged_mode"] is True
    assert comp.metadata["source_type"] == "GITHUB"
    assert comp.metadata["timeout_minutes"] == 60
    assert comp.metadata["tags"] == {"Env": "prod"}


def test_terraform_inventory_enriches_lambda_metadata():
    plan = _tf_plan([
        {
            "address": "aws_lambda_function.fn", "mode": "managed",
            "type": "aws_lambda_function", "name": "fn",
            "values": {
                "runtime": "python3.12",
                "handler": "app.handler",
                "code_signing_config_arn": "arn:aws:lambda:us-east-1:1:csc:x",
            },
        },
    ])
    comp = _providers.get("terraform").inventory(TerraformContext(plan))[0]
    assert comp.metadata["runtime"] == "python3.12"
    assert comp.metadata["handler"] == "app.handler"
    assert comp.metadata["code_signing_config_arn"] == "arn:aws:lambda:us-east-1:1:csc:x"


def test_jenkins_inventory_captures_agent_and_guards(tmp_path):
    jf = tmp_path / "Jenkinsfile"
    jf.write_text(
        "pipeline {\n"
        "  agent { docker { image 'maven:3.9' } }\n"
        "  options {\n"
        "    timeout(time: 30, unit: 'MINUTES')\n"
        "    buildDiscarder(logRotator(numToKeepStr: '10'))\n"
        "  }\n"
        "  stages { stage('Build') { steps { sh 'mvn package' } } }\n"
        "}\n"
    )
    scanner = Scanner(pipeline="jenkins", jenkinsfile_path=str(jf))
    inv = scanner.inventory()
    m = inv[0].metadata
    assert m["agent"] == "docker:maven:3.9"
    assert m["has_timeout"] is True
    assert m["has_build_discarder"] is True


def test_jenkins_inventory_detects_agent_any(tmp_path):
    jf = tmp_path / "Jenkinsfile"
    jf.write_text(
        "pipeline {\n  agent any\n  stages { stage('x') { steps { echo 'hi' } } }\n}\n"
    )
    scanner = Scanner(pipeline="jenkins", jenkinsfile_path=str(jf))
    inv = scanner.inventory()
    assert inv[0].metadata["agent"] == "any"
    assert inv[0].metadata["has_timeout"] is False


# ─── --inventory-type filter ────────────────────────────────────────────────

def test_scanner_inventory_type_filter_exact_match():
    plan = _tf_plan([
        {"address": "aws_iam_role.r", "mode": "managed",
         "type": "aws_iam_role", "name": "r", "values": {}},
        {"address": "aws_s3_bucket.b", "mode": "managed",
         "type": "aws_s3_bucket", "name": "b", "values": {}},
    ])
    scanner = Scanner.__new__(Scanner)
    scanner.pipeline = "terraform"
    scanner._provider = _providers.get("terraform")
    scanner._context = TerraformContext(plan)
    inv = scanner.inventory(type_patterns=["aws_iam_role"])
    assert [c.type for c in inv] == ["aws_iam_role"]


def test_scanner_inventory_type_filter_glob():
    plan = _tf_plan([
        {"address": "aws_iam_role.r", "mode": "managed",
         "type": "aws_iam_role", "name": "r", "values": {}},
        {"address": "aws_iam_user.u", "mode": "managed",
         "type": "aws_iam_user", "name": "u", "values": {}},
        {"address": "aws_s3_bucket.b", "mode": "managed",
         "type": "aws_s3_bucket", "name": "b", "values": {}},
    ])
    scanner = Scanner.__new__(Scanner)
    scanner.pipeline = "terraform"
    scanner._provider = _providers.get("terraform")
    scanner._context = TerraformContext(plan)
    inv = scanner.inventory(type_patterns=["aws_iam_*"])
    assert {c.type for c in inv} == {"aws_iam_role", "aws_iam_user"}


def test_scanner_inventory_type_filter_multiple_patterns():
    plan = _tf_plan([
        {"address": "aws_iam_role.r", "mode": "managed",
         "type": "aws_iam_role", "name": "r", "values": {}},
        {"address": "aws_kms_key.k", "mode": "managed",
         "type": "aws_kms_key", "name": "k", "values": {}},
        {"address": "aws_s3_bucket.b", "mode": "managed",
         "type": "aws_s3_bucket", "name": "b", "values": {}},
    ])
    scanner = Scanner.__new__(Scanner)
    scanner.pipeline = "terraform"
    scanner._provider = _providers.get("terraform")
    scanner._context = TerraformContext(plan)
    inv = scanner.inventory(type_patterns=["aws_iam_role", "aws_kms_*"])
    assert {c.type for c in inv} == {"aws_iam_role", "aws_kms_key"}


# ─── --inventory-only mode ─────────────────────────────────────────────────

def test_cli_inventory_only_skips_checks(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "template.yml").write_text(_CFN_TEMPLATE)
    result = CliRunner().invoke(
        scan,
        ["--pipeline", "cloudformation", "--output", "json", "--inventory-only"],
    )
    assert result.exit_code in (0, 1), result.output
    payload = _extract_json_payload(result.output)
    # inventory present
    assert "inventory" in payload
    assert payload["inventory"]
    # findings skipped
    assert payload["findings"] == []


def test_cli_inventory_type_implies_inventory(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "template.yml").write_text(_CFN_TEMPLATE)
    result = CliRunner().invoke(
        scan, [
            "--pipeline", "cloudformation", "--output", "json",
            "--inventory-type", "AWS::S3::*",
        ],
    )
    assert result.exit_code in (0, 1), result.output
    payload = _extract_json_payload(result.output)
    assert "inventory" in payload
    # Only S3 resources remain after the filter.
    assert all(c["type"].startswith("AWS::S3::") for c in payload["inventory"])


def test_aws_inventory_emits_degraded_when_service_unreachable():
    """Services that fail enumeration should surface as *_degraded
    components rather than silently dropping the entry."""
    from botocore.exceptions import ClientError

    session = MagicMock()

    def _client(svc, **_kw):
        client = MagicMock()
        # All paginators raise — simulates total API denial.
        client.get_paginator.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": ""}}, "op",
        )
        # For services that aren't paginator-driven (sts, etc.) just
        # return the MagicMock so attribute lookups don't raise.
        return client

    session.client.side_effect = _client
    provider = _providers.get("aws")
    inv = provider.inventory(session)
    # Every service should report a *_degraded marker; asserting two
    # is enough to confirm the pattern works.
    degraded_types = {c.type for c in inv if c.type.endswith("_degraded")}
    assert "codebuild_degraded" in degraded_types
    assert "iam_degraded" in degraded_types
