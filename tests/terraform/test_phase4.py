"""Phase-4 Terraform tests — SIGN-001, EB-002, CW-001, TF-001/002/003."""
from __future__ import annotations

from pipeline_check.core.checks.terraform.base import TerraformContext
from pipeline_check.core.checks.terraform.phase4 import Phase4Checks


def _plan(resources):
    return {"planned_values": {"root_module": {"resources": resources, "child_modules": []}}}


def _r(addr, rtype, name, values):
    return {"address": addr, "mode": "managed", "type": rtype, "name": name, "values": values}


def _run(resources):
    return Phase4Checks(TerraformContext(_plan(resources))).run()


# ──────────────────────────────────────────────────────────────────────
# SIGN-001 — Lambda code-signing needs a matching signer profile
# ──────────────────────────────────────────────────────────────────────

def test_sign001_missing_profile_fails():
    fn = _r("aws_lambda_function.f", "aws_lambda_function", "f", {
        "code_signing_config_arn": "arn:aws:lambda:::code-signing-config/x",
    })
    f = next(x for x in _run([fn]) if x.check_id == "SIGN-001")
    assert not f.passed


def test_sign001_lambda_profile_passes():
    fn = _r("aws_lambda_function.f", "aws_lambda_function", "f", {
        "code_signing_config_arn": "arn:aws:lambda:::code-signing-config/x",
    })
    prof = _r("aws_signer_signing_profile.p", "aws_signer_signing_profile", "p", {
        "platform_id": "AWSLambda-SHA384-ECDSA",
    })
    f = next(x for x in _run([fn, prof]) if x.check_id == "SIGN-001")
    assert f.passed


def test_sign001_non_lambda_profile_fails():
    fn = _r("aws_lambda_function.f", "aws_lambda_function", "f", {
        "code_signing_config_arn": "arn:aws:lambda:::code-signing-config/x",
    })
    prof = _r("aws_signer_signing_profile.p", "aws_signer_signing_profile", "p", {
        "platform_id": "Notation-OCI-SHA384-ECDSA",
    })
    f = next(x for x in _run([fn, prof]) if x.check_id == "SIGN-001")
    assert not f.passed


def test_sign001_no_signed_lambda_suppressed():
    fn = _r("aws_lambda_function.f", "aws_lambda_function", "f", {})
    assert not any(x.check_id == "SIGN-001" for x in _run([fn]))


# ──────────────────────────────────────────────────────────────────────
# EB-002 — EventBridge target ARN wildcard
# ──────────────────────────────────────────────────────────────────────

def test_eb002_wildcard_target_fails():
    t = _r("aws_cloudwatch_event_target.t", "aws_cloudwatch_event_target", "t", {
        "arn": "arn:aws:lambda:us-east-1:1:function:*",
    })
    f = next(x for x in _run([t]) if x.check_id == "EB-002")
    assert not f.passed


def test_eb002_specific_target_passes():
    t = _r("aws_cloudwatch_event_target.t", "aws_cloudwatch_event_target", "t", {
        "arn": "arn:aws:lambda:us-east-1:1:function:build-failed-notifier",
    })
    assert not any(x.check_id == "EB-002" for x in _run([t]))


# ──────────────────────────────────────────────────────────────────────
# CW-001 — alarm on CodeBuild FailedBuilds
# ──────────────────────────────────────────────────────────────────────

def test_cw001_no_codebuild_suppressed():
    assert not any(x.check_id == "CW-001" for x in _run([]))


def test_cw001_no_matching_alarm_fails():
    cb = _r("aws_codebuild_project.p", "aws_codebuild_project", "p", {"name": "p"})
    alarm = _r("aws_cloudwatch_metric_alarm.a", "aws_cloudwatch_metric_alarm", "a", {
        "namespace": "AWS/Lambda", "metric_name": "Errors",
    })
    f = next(x for x in _run([cb, alarm]) if x.check_id == "CW-001")
    assert not f.passed


def test_cw001_matching_alarm_passes():
    cb = _r("aws_codebuild_project.p", "aws_codebuild_project", "p", {"name": "p"})
    alarm = _r("aws_cloudwatch_metric_alarm.a", "aws_cloudwatch_metric_alarm", "a", {
        "namespace": "AWS/CodeBuild", "metric_name": "FailedBuilds",
    })
    f = next(x for x in _run([cb, alarm]) if x.check_id == "CW-001")
    assert f.passed


# ──────────────────────────────────────────────────────────────────────
# TF-001 — aws_iam_access_key as code
# ──────────────────────────────────────────────────────────────────────

def test_tf001_access_key_fails():
    k = _r("aws_iam_access_key.k", "aws_iam_access_key", "k", {"user": "ci-bot"})
    f = next(x for x in _run([k]) if x.check_id == "TF-001")
    assert not f.passed
    assert "ci-bot" in f.description


def test_tf001_no_access_key_silent():
    assert not any(x.check_id == "TF-001" for x in _run([]))


# ──────────────────────────────────────────────────────────────────────
# TF-002 — hardcoded secret shape in resource values
# ──────────────────────────────────────────────────────────────────────

def test_tf002_rds_inline_password_fails():
    db = _r("aws_db_instance.db", "aws_db_instance", "db", {
        "identifier": "prod",
        "master_password": "Tr0ub4dor-2026-HardcodedActuallyLong",
    })
    f = next(x for x in _run([db]) if x.check_id == "TF-002")
    assert not f.passed
    assert "master_password" in f.description


def test_tf002_vendor_token_in_rds_fails():
    db = _r("aws_db_instance.db", "aws_db_instance", "db", {
        "identifier": "prod",
        "tags": {"rotator": "AKIAABCDEFGHIJKLMNOP"},
    })
    f = next(x for x in _run([db]) if x.check_id == "TF-002")
    assert not f.passed


def test_tf002_placeholder_suppressed():
    db = _r("aws_db_instance.db", "aws_db_instance", "db", {
        "master_password": "<your-password-here>",
    })
    assert not any(x.check_id == "TF-002" for x in _run([db]))


def test_tf002_interpolation_suppressed():
    db = _r("aws_db_instance.db", "aws_db_instance", "db", {
        "master_password": "${random_password.db.result}",
    })
    assert not any(x.check_id == "TF-002" for x in _run([db]))


def test_tf002_lambda_skipped():
    fn = _r("aws_lambda_function.f", "aws_lambda_function", "f", {
        "environment": [{"variables": {"DB_PASSWORD": "SuperSecretLongPassword123"}}],
    })
    assert not any(x.check_id == "TF-002" for x in _run([fn]))


def test_tf002_secretsmanager_secret_version_literal_fails():
    # ``secret_string`` on an aws_secretsmanager_secret_version often
    # carries a literal token pasted during local dev — now scanned.
    sv = _r("aws_secretsmanager_secret_version.v", "aws_secretsmanager_secret_version", "v", {
        "secret_string": "ghp_abcdefghijklmnopqrstuvwxyz0123456789",
    })
    f = next(x for x in _run([sv]) if x.check_id == "TF-002")
    assert not f.passed


# ──────────────────────────────────────────────────────────────────────
# TF-003 — CodeBuild VPC shares its VPC with a public subnet
# ──────────────────────────────────────────────────────────────────────

def test_tf003_public_subnet_in_vpc_fails():
    cb = _r("aws_codebuild_project.p", "aws_codebuild_project", "p", {
        "name": "p",
        "vpc_config": [{"vpc_id": "vpc-aaa", "subnets": ["subnet-x"], "security_group_ids": ["sg-x"]}],
    })
    sn = _r("aws_subnet.pub", "aws_subnet", "pub", {
        "vpc_id": "vpc-aaa", "map_public_ip_on_launch": True,
    })
    f = next(x for x in _run([cb, sn]) if x.check_id == "TF-003")
    assert not f.passed


def test_tf003_private_only_vpc_passes():
    cb = _r("aws_codebuild_project.p", "aws_codebuild_project", "p", {
        "name": "p",
        "vpc_config": [{"vpc_id": "vpc-aaa", "subnets": ["subnet-x"], "security_group_ids": ["sg-x"]}],
    })
    sn = _r("aws_subnet.priv", "aws_subnet", "priv", {
        "vpc_id": "vpc-aaa", "map_public_ip_on_launch": False,
    })
    f = next(x for x in _run([cb, sn]) if x.check_id == "TF-003")
    assert f.passed


def test_tf003_no_vpc_config_silent():
    cb = _r("aws_codebuild_project.p", "aws_codebuild_project", "p", {"name": "p"})
    assert not any(x.check_id == "TF-003" for x in _run([cb]))


def test_tf003_unresolved_vpc_id_silent():
    cb = _r("aws_codebuild_project.p", "aws_codebuild_project", "p", {
        "name": "p",
        "vpc_config": [{"subnets": ["subnet-x"], "security_group_ids": ["sg-x"]}],
    })
    assert not any(x.check_id == "TF-003" for x in _run([cb]))
