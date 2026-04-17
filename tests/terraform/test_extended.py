"""Phase-1 Terraform parity tests — CB-008/009/010, CT-*, CWL-*, SM-*, IAM-008."""
from __future__ import annotations

import json

from pipeline_check.core.checks.terraform.base import TerraformContext
from pipeline_check.core.checks.terraform.extended import ExtendedChecks


def _plan(resources):
    return {
        "planned_values": {
            "root_module": {"resources": resources, "child_modules": []}
        }
    }


def _r(addr, rtype, name, values):
    return {"address": addr, "mode": "managed", "type": rtype, "name": name, "values": values}


def _run(resources):
    return ExtendedChecks(TerraformContext(_plan(resources))).run()


# ---------- CB-008 ----------

def test_cb008_inline_fails():
    project = _r("aws_codebuild_project.p", "aws_codebuild_project", "p", {
        "source": [{"type": "GITHUB", "buildspec": "version: 0.2\nphases: {}"}],
    })
    f = next(x for x in _run([project]) if x.check_id == "CB-008")
    assert not f.passed


def test_cb008_repo_path_passes():
    project = _r("aws_codebuild_project.p", "aws_codebuild_project", "p", {
        "source": [{"type": "GITHUB", "buildspec": "ci/build.yml"}],
    })
    f = next(x for x in _run([project]) if x.check_id == "CB-008")
    assert f.passed


# ---------- CB-009 ----------

def test_cb009_tag_only_fails():
    project = _r("aws_codebuild_project.p", "aws_codebuild_project", "p", {
        "environment": [{"image": "ghcr.io/org/img:v1"}],
    })
    f = next(x for x in _run([project]) if x.check_id == "CB-009")
    assert not f.passed


def test_cb009_digest_passes():
    digest = "@sha256:" + "a" * 64
    project = _r("aws_codebuild_project.p", "aws_codebuild_project", "p", {
        "environment": [{"image": f"ghcr.io/org/img{digest}"}],
    })
    f = next(x for x in _run([project]) if x.check_id == "CB-009")
    assert f.passed


# ---------- CB-010 ----------

def test_cb010_pr_without_actor_fails():
    project = _r("aws_codebuild_project.p", "aws_codebuild_project", "p", {"source": [{}]})
    webhook = _r("aws_codebuild_webhook.w", "aws_codebuild_webhook", "w", {
        "project_name": "p",
        "filter_group": [{"filter": [
            {"type": "EVENT", "pattern": "PULL_REQUEST_CREATED"},
        ]}],
    })
    # The project's display name must match project_name on webhook.
    project["values"]["name"] = "p"
    f = next(x for x in _run([project, webhook]) if x.check_id == "CB-010")
    assert not f.passed


def test_cb010_pr_with_actor_passes():
    project = _r("aws_codebuild_project.p", "aws_codebuild_project", "p", {
        "name": "p", "source": [{}],
    })
    webhook = _r("aws_codebuild_webhook.w", "aws_codebuild_webhook", "w", {
        "project_name": "p",
        "filter_group": [{"filter": [
            {"type": "EVENT", "pattern": "PULL_REQUEST_CREATED"},
            {"type": "ACTOR_ACCOUNT_ID", "pattern": "123"},
        ]}],
    })
    f = next(x for x in _run([project, webhook]) if x.check_id == "CB-010")
    assert f.passed


# ---------- CT-001..003 ----------

def test_ct001_no_trail_fails():
    f = next(x for x in _run([]) if x.check_id == "CT-001")
    assert not f.passed


def test_ct001_with_trail_passes():
    trail = _r("aws_cloudtrail.t", "aws_cloudtrail", "t", {
        "enable_log_file_validation": True, "is_multi_region_trail": True,
    })
    f = next(x for x in _run([trail]) if x.check_id == "CT-001")
    assert f.passed


def test_ct002_validation_disabled_fails():
    trail = _r("aws_cloudtrail.t", "aws_cloudtrail", "t", {"enable_log_file_validation": False})
    f = next(x for x in _run([trail]) if x.check_id == "CT-002")
    assert not f.passed


def test_ct003_single_region_fails():
    trail = _r("aws_cloudtrail.t", "aws_cloudtrail", "t", {"is_multi_region_trail": False})
    f = next(x for x in _run([trail]) if x.check_id == "CT-003")
    assert not f.passed


# ---------- CWL-001/002 ----------

def test_cwl001_no_retention_fails():
    lg = _r("aws_cloudwatch_log_group.lg", "aws_cloudwatch_log_group", "lg", {
        "name": "/aws/codebuild/foo",
    })
    f = next(x for x in _run([lg]) if x.check_id == "CWL-001")
    assert not f.passed


def test_cwl002_no_kms_fails():
    lg = _r("aws_cloudwatch_log_group.lg", "aws_cloudwatch_log_group", "lg", {
        "name": "/aws/codebuild/foo", "retention_in_days": 30,
    })
    f = next(x for x in _run([lg]) if x.check_id == "CWL-002")
    assert not f.passed


def test_cwl_non_codebuild_skipped():
    lg = _r("aws_cloudwatch_log_group.lg", "aws_cloudwatch_log_group", "lg", {
        "name": "/aws/lambda/foo",
    })
    assert not any(x.check_id.startswith("CWL") for x in _run([lg]))


# ---------- SM-001/002 ----------

def test_sm001_no_rotation_fails():
    secret = _r("aws_secretsmanager_secret.s", "aws_secretsmanager_secret", "s", {"name": "my-secret"})
    f = next(x for x in _run([secret]) if x.check_id == "SM-001")
    assert not f.passed


def test_sm001_with_rotation_passes():
    secret = _r("aws_secretsmanager_secret.s", "aws_secretsmanager_secret", "s", {"name": "my-secret"})
    rotation = _r("aws_secretsmanager_secret_rotation.r", "aws_secretsmanager_secret_rotation", "r", {
        "secret_id": "my-secret",
    })
    f = next(x for x in _run([secret, rotation]) if x.check_id == "SM-001")
    assert f.passed


def test_sm002_wildcard_fails():
    doc = json.dumps({"Statement": [{"Effect": "Allow", "Principal": "*", "Action": "*"}]})
    policy = _r("aws_secretsmanager_secret_policy.p", "aws_secretsmanager_secret_policy", "p", {"policy": doc})
    f = next(x for x in _run([policy]) if x.check_id == "SM-002")
    assert not f.passed


# ---------- IAM-008 ----------

_GH_OIDC = "arn:aws:iam::1:oidc-provider/token.actions.githubusercontent.com"


def test_iam008_oidc_pinned_passes():
    doc = json.dumps({"Statement": [{
        "Effect": "Allow",
        "Principal": {"Federated": _GH_OIDC},
        "Action": "sts:AssumeRoleWithWebIdentity",
        "Condition": {
            "StringEquals": {"token.actions.githubusercontent.com:aud": "sts.amazonaws.com"},
            "StringLike": {"token.actions.githubusercontent.com:sub": "repo:org/repo:*"},
        },
    }]})
    role = _r("aws_iam_role.r", "aws_iam_role", "r", {"assume_role_policy": doc})
    f = next(x for x in _run([role]) if x.check_id == "IAM-008")
    assert f.passed


def test_iam008_missing_audience_fails():
    doc = json.dumps({"Statement": [{
        "Effect": "Allow",
        "Principal": {"Federated": _GH_OIDC},
        "Action": "sts:AssumeRoleWithWebIdentity",
    }]})
    role = _r("aws_iam_role.r", "aws_iam_role", "r", {"assume_role_policy": doc})
    f = next(x for x in _run([role]) if x.check_id == "IAM-008")
    assert not f.passed


def test_iam008_non_oidc_skipped():
    doc = json.dumps({"Statement": [{
        "Effect": "Allow",
        "Principal": {"Service": "codebuild.amazonaws.com"},
        "Action": "sts:AssumeRole",
    }]})
    role = _r("aws_iam_role.r", "aws_iam_role", "r", {"assume_role_policy": doc})
    assert not any(x.check_id == "IAM-008" for x in _run([role]))
