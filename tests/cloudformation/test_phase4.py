"""CFN Phase-4 tests — SIGN-001, EB-002, CW-001, CF-001/002/003."""
from __future__ import annotations

from pipeline_check.core.checks.cloudformation.phase4 import Phase4Checks
from tests.cloudformation.conftest import make_context, r


def _run(resources: dict):
    return Phase4Checks(make_context(resources)).run()


# ──────────────────────────────────────────────────────────────────────
# SIGN-001
# ──────────────────────────────────────────────────────────────────────

def test_sign001_missing_profile_fails():
    out = _run({
        "Fn": r("Fn", "AWS::Lambda::Function", {
            "CodeSigningConfigArn": "arn:aws:lambda:::code-signing-config/x",
        }),
    })
    f = next(x for x in out if x.check_id == "SIGN-001")
    assert not f.passed


def test_sign001_lambda_profile_passes():
    out = _run({
        "Fn": r("Fn", "AWS::Lambda::Function", {
            "CodeSigningConfigArn": "arn:aws:lambda:::code-signing-config/x",
        }),
        "P": r("P", "AWS::Signer::SigningProfile", {
            "PlatformId": "AWSLambda-SHA384-ECDSA",
        }),
    })
    f = next(x for x in out if x.check_id == "SIGN-001")
    assert f.passed


def test_sign001_non_lambda_profile_fails():
    out = _run({
        "Fn": r("Fn", "AWS::Lambda::Function", {
            "CodeSigningConfigArn": "arn:aws:lambda:::code-signing-config/x",
        }),
        "P": r("P", "AWS::Signer::SigningProfile", {
            "PlatformId": "Notation-OCI-SHA384-ECDSA",
        }),
    })
    f = next(x for x in out if x.check_id == "SIGN-001")
    assert not f.passed


def test_sign001_no_signed_lambda_suppressed():
    out = _run({"Fn": r("Fn", "AWS::Lambda::Function", {})})
    assert not any(x.check_id == "SIGN-001" for x in out)


# ──────────────────────────────────────────────────────────────────────
# EB-002
# ──────────────────────────────────────────────────────────────────────

def test_eb002_wildcard_target_fails():
    out = _run({
        "R": r("R", "AWS::Events::Rule", {
            "Targets": [{"Id": "t1", "Arn": "arn:aws:lambda:us-east-1:1:function:*"}],
        }),
    })
    f = next(x for x in out if x.check_id == "EB-002")
    assert not f.passed
    assert "t1" in f.resource


def test_eb002_specific_target_passes():
    out = _run({
        "R": r("R", "AWS::Events::Rule", {
            "Targets": [{"Id": "t1", "Arn": "arn:aws:lambda:us-east-1:1:function:notifier"}],
        }),
    })
    assert not any(x.check_id == "EB-002" for x in out)


def test_eb002_intrinsic_target_silent():
    # Unresolved {"Fn::GetAtt": [...]} — cannot reason about prefix.
    out = _run({
        "R": r("R", "AWS::Events::Rule", {
            "Targets": [{"Id": "t1", "Arn": {"Fn::GetAtt": ["Fn", "Arn"]}}],
        }),
    })
    assert not any(x.check_id == "EB-002" for x in out)


def test_eb002_resolved_sub_wildcard_fails():
    # Fn::Sub with a literal template resolves to a string — the
    # wildcard should now be caught instead of silently skipped.
    out = _run({
        "R": r("R", "AWS::Events::Rule", {
            "Targets": [{"Id": "t1", "Arn": {
                "Fn::Sub": "arn:aws:lambda:us-east-1:1:function:*"
            }}],
        }),
    })
    f = next(x for x in out if x.check_id == "EB-002")
    assert not f.passed


def test_eb002_ref_to_wildcard_parameter_fails():
    from pipeline_check.core.checks.cloudformation.base import CloudFormationContext
    from pipeline_check.core.checks.cloudformation.phase4 import Phase4Checks

    template = {
        "Parameters": {"TargetArn": {"Default": "arn:aws:sns:us-east-1:1:*"}},
        "Resources": {
            "R": r("R", "AWS::Events::Rule", {
                "Targets": [{"Id": "t1", "Arn": {"Ref": "TargetArn"}}],
            }),
        },
    }
    ctx = CloudFormationContext([("<in-memory>", template)])
    f = next(x for x in Phase4Checks(ctx).run() if x.check_id == "EB-002")
    assert not f.passed


# ──────────────────────────────────────────────────────────────────────
# CW-001
# ──────────────────────────────────────────────────────────────────────

def test_cw001_no_codebuild_suppressed():
    assert not any(x.check_id == "CW-001" for x in _run({}))


def test_cw001_no_matching_alarm_fails():
    out = _run({
        "P": r("P", "AWS::CodeBuild::Project", {"Name": "p"}),
        "A": r("A", "AWS::CloudWatch::Alarm", {
            "Namespace": "AWS/Lambda", "MetricName": "Errors",
        }),
    })
    f = next(x for x in out if x.check_id == "CW-001")
    assert not f.passed


def test_cw001_matching_alarm_passes():
    out = _run({
        "P": r("P", "AWS::CodeBuild::Project", {"Name": "p"}),
        "A": r("A", "AWS::CloudWatch::Alarm", {
            "Namespace": "AWS/CodeBuild", "MetricName": "FailedBuilds",
        }),
    })
    f = next(x for x in out if x.check_id == "CW-001")
    assert f.passed


# ──────────────────────────────────────────────────────────────────────
# CF-001 — AWS::IAM::AccessKey
# ──────────────────────────────────────────────────────────────────────

def test_cf001_access_key_fails():
    out = _run({"K": r("K", "AWS::IAM::AccessKey", {"UserName": "ci-bot"})})
    f = next(x for x in out if x.check_id == "CF-001")
    assert not f.passed
    assert "ci-bot" in f.description


def test_cf001_no_access_key_silent():
    assert not any(x.check_id == "CF-001" for x in _run({}))


# ──────────────────────────────────────────────────────────────────────
# CF-002 — hard-coded secrets in data-store properties
# ──────────────────────────────────────────────────────────────────────

def test_cf002_rds_inline_password_fails():
    out = _run({
        "DB": r("DB", "AWS::RDS::DBInstance", {
            "DBInstanceIdentifier": "prod",
            "MasterUserPassword": "Tr0ub4dor-2026-HardcodedLiteral",
        }),
    })
    f = next(x for x in out if x.check_id == "CF-002")
    assert not f.passed
    assert "MasterUserPassword" in f.description


def test_cf002_vendor_token_in_rds_fails():
    out = _run({
        "DB": r("DB", "AWS::RDS::DBInstance", {
            "DBInstanceIdentifier": "prod",
            "Tags": [{"Key": "rotator", "Value": "AKIAABCDEFGHIJKLMNOP"}],
        }),
    })
    f = next(x for x in out if x.check_id == "CF-002")
    assert not f.passed


def test_cf002_placeholder_suppressed():
    out = _run({
        "DB": r("DB", "AWS::RDS::DBInstance", {
            "MasterUserPassword": "<your-password-here>",
        }),
    })
    assert not any(x.check_id == "CF-002" for x in out)


def test_cf002_intrinsic_suppressed():
    # Dynamic reference or Ref / GetAtt — cannot be a literal secret.
    out = _run({
        "DB": r("DB", "AWS::RDS::DBInstance", {
            "MasterUserPassword": {"Ref": "DbPassword"},
        }),
    })
    assert not any(x.check_id == "CF-002" for x in out)


def test_cf002_lambda_skipped():
    out = _run({
        "Fn": r("Fn", "AWS::Lambda::Function", {
            "Environment": {"Variables": {"DB_PASSWORD": "SuperSecretLongPassword123"}},
        }),
    })
    assert not any(x.check_id == "CF-002" for x in out)


# ──────────────────────────────────────────────────────────────────────
# CF-003 — CodeBuild VPC shares VPC with public subnet
# ──────────────────────────────────────────────────────────────────────

def test_cf003_public_subnet_in_vpc_fails():
    out = _run({
        "P": r("P", "AWS::CodeBuild::Project", {
            "Name": "p",
            "VpcConfig": {"VpcId": "vpc-aaa", "Subnets": ["subnet-x"], "SecurityGroupIds": ["sg-x"]},
        }),
        "Pub": r("Pub", "AWS::EC2::Subnet", {
            "VpcId": "vpc-aaa", "MapPublicIpOnLaunch": True,
        }),
    })
    f = next(x for x in out if x.check_id == "CF-003")
    assert not f.passed


def test_cf003_private_only_vpc_passes():
    out = _run({
        "P": r("P", "AWS::CodeBuild::Project", {
            "Name": "p",
            "VpcConfig": {"VpcId": "vpc-aaa", "Subnets": ["subnet-x"], "SecurityGroupIds": ["sg-x"]},
        }),
        "Priv": r("Priv", "AWS::EC2::Subnet", {
            "VpcId": "vpc-aaa", "MapPublicIpOnLaunch": False,
        }),
    })
    f = next(x for x in out if x.check_id == "CF-003")
    assert f.passed


def test_cf003_no_vpc_config_silent():
    out = _run({"P": r("P", "AWS::CodeBuild::Project", {"Name": "p"})})
    assert not any(x.check_id == "CF-003" for x in out)


def test_cf003_intrinsic_vpc_id_silent():
    out = _run({
        "P": r("P", "AWS::CodeBuild::Project", {
            "Name": "p",
            "VpcConfig": {"VpcId": {"Ref": "VpcIdParam"}, "Subnets": ["subnet-x"], "SecurityGroupIds": ["sg-x"]},
        }),
    })
    assert not any(x.check_id == "CF-003" for x in out)


def test_cf003_ref_vpc_id_resolved_via_parameter_fails():
    from pipeline_check.core.checks.cloudformation.base import CloudFormationContext
    from pipeline_check.core.checks.cloudformation.phase4 import Phase4Checks

    # Both the CodeBuild project's VpcId and the public subnet's VpcId
    # are {"Ref": "VpcId"} — with a parameter default of "vpc-aaa" the
    # resolver should match them and flag the shared-VPC case.
    template = {
        "Parameters": {"VpcId": {"Default": "vpc-aaa"}},
        "Resources": {
            "P": r("P", "AWS::CodeBuild::Project", {
                "Name": "p",
                "VpcConfig": {"VpcId": {"Ref": "VpcId"},
                              "Subnets": ["subnet-x"],
                              "SecurityGroupIds": ["sg-x"]},
            }),
            "Pub": r("Pub", "AWS::EC2::Subnet", {
                "VpcId": {"Ref": "VpcId"}, "MapPublicIpOnLaunch": True,
            }),
        },
    }
    ctx = CloudFormationContext([("<in-memory>", template)])
    f = next(x for x in Phase4Checks(ctx).run() if x.check_id == "CF-003")
    assert not f.passed
