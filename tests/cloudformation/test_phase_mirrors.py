"""Tests for CFN Phase 1-3 parity modules (extended.py, services.py, phase3.py)."""
from __future__ import annotations

import json

from pipeline_check.core.checks.cloudformation.extended import ExtendedChecks
from pipeline_check.core.checks.cloudformation.phase3 import Phase3Checks
from pipeline_check.core.checks.cloudformation.services import ServiceChecks
from tests.cloudformation.conftest import make_context, r

_GH_OIDC = "arn:aws:iam::1:oidc-provider/token.actions.githubusercontent.com"
_FAILED_PATTERN = {
    "detail-type": ["CodePipeline Pipeline Execution State Change"],
    "detail": {"state": ["FAILED"]},
}


# ───────── Phase 1: extended.py ─────────

def test_cb008_inline_buildspec_fails():
    ctx = make_context({
        "P": r("P", "AWS::CodeBuild::Project", {
            "Name": "p",
            "Source": {"Type": "GITHUB", "BuildSpec": "version: 0.2\nphases:\n  build: {}"},
        }),
    })
    f = next(x for x in ExtendedChecks(ctx).run() if x.check_id == "CB-008")
    assert f.passed is False


def test_cb008_repo_path_passes():
    ctx = make_context({
        "P": r("P", "AWS::CodeBuild::Project", {
            "Name": "p", "Source": {"Type": "GITHUB", "BuildSpec": "ci/build.yml"},
        }),
    })
    f = next(x for x in ExtendedChecks(ctx).run() if x.check_id == "CB-008")
    assert f.passed is True


def test_cb009_tag_pinned_fails():
    ctx = make_context({
        "P": r("P", "AWS::CodeBuild::Project", {
            "Name": "p", "Environment": {"Image": "ghcr.io/corp/builder:v1"},
        }),
    })
    f = next(x for x in ExtendedChecks(ctx).run() if x.check_id == "CB-009")
    assert f.passed is False


def test_cb009_digest_passes():
    digest = "@sha256:" + "a" * 64
    ctx = make_context({
        "P": r("P", "AWS::CodeBuild::Project", {
            "Name": "p", "Environment": {"Image": f"ghcr.io/corp/builder{digest}"},
        }),
    })
    f = next(x for x in ExtendedChecks(ctx).run() if x.check_id == "CB-009")
    assert f.passed is True


def test_cb010_pr_without_actor_fails():
    ctx = make_context({
        "P": r("P", "AWS::CodeBuild::Project", {
            "Name": "p",
            "Triggers": {
                "Webhook": True,
                "FilterGroups": [[
                    {"Type": "EVENT", "Pattern": "PULL_REQUEST_CREATED"},
                ]],
            },
        }),
    })
    f = next(x for x in ExtendedChecks(ctx).run() if x.check_id == "CB-010")
    assert f.passed is False


def test_ct001_no_trail_fails():
    ctx = make_context({})
    f = next(x for x in ExtendedChecks(ctx).run() if x.check_id == "CT-001")
    assert f.passed is False


def test_ct001_with_trail_passes():
    ctx = make_context({
        "T": r("T", "AWS::CloudTrail::Trail", {
            "EnableLogFileValidation": True, "IsMultiRegionTrail": True,
        }),
    })
    f = next(x for x in ExtendedChecks(ctx).run() if x.check_id == "CT-001")
    assert f.passed is True


def test_ct002_validation_intrinsic_fails():
    """An unresolved !If should count as NOT true (shift-left strict)."""
    ctx = make_context({
        "T": r("T", "AWS::CloudTrail::Trail", {
            "EnableLogFileValidation": {"Fn::If": ["IsProd", True, False]},
            "IsMultiRegionTrail": True,
        }),
    })
    f = next(x for x in ExtendedChecks(ctx).run() if x.check_id == "CT-002")
    assert f.passed is False


def test_ct003_single_region_fails():
    ctx = make_context({
        "T": r("T", "AWS::CloudTrail::Trail", {
            "EnableLogFileValidation": True, "IsMultiRegionTrail": False,
        }),
    })
    f = next(x for x in ExtendedChecks(ctx).run() if x.check_id == "CT-003")
    assert f.passed is False


def test_cwl001_no_retention_fails():
    ctx = make_context({
        "LG": r("LG", "AWS::Logs::LogGroup", {"LogGroupName": "/aws/codebuild/foo"}),
    })
    f = next(x for x in ExtendedChecks(ctx).run() if x.check_id == "CWL-001")
    assert f.passed is False


def test_cwl002_kms_configured_passes():
    ctx = make_context({
        "LG": r("LG", "AWS::Logs::LogGroup", {
            "LogGroupName": "/aws/codebuild/foo",
            "RetentionInDays": 30,
            "KmsKeyId": "arn:aws:kms:us-east-1:1:key/abc",
        }),
    })
    findings = [x for x in ExtendedChecks(ctx).run() if x.check_id in ("CWL-001", "CWL-002")]
    assert all(f.passed for f in findings)


def test_cwl_non_codebuild_skipped():
    ctx = make_context({
        "LG": r("LG", "AWS::Logs::LogGroup", {"LogGroupName": "/aws/lambda/foo"}),
    })
    assert not any(x.check_id.startswith("CWL") for x in ExtendedChecks(ctx).run())


def test_sm001_no_rotation_fails():
    ctx = make_context({
        "S": r("S", "AWS::SecretsManager::Secret", {"Name": "db-pw"}),
    })
    f = next(x for x in ExtendedChecks(ctx).run() if x.check_id == "SM-001")
    assert f.passed is False


def test_sm001_with_rotation_passes():
    ctx = make_context({
        "S": r("S", "AWS::SecretsManager::Secret", {"Name": "db-pw"}),
        "R": r("R", "AWS::SecretsManager::RotationSchedule", {
            "SecretId": {"Ref": "S"},
        }),
    })
    f = next(x for x in ExtendedChecks(ctx).run() if x.check_id == "SM-001")
    assert f.passed is True


def test_sm002_wildcard_principal_fails():
    policy = {"Statement": [{"Effect": "Allow", "Principal": "*", "Action": "secretsmanager:GetSecretValue"}]}
    ctx = make_context({
        "P": r("P", "AWS::SecretsManager::ResourcePolicy", {
            "SecretId": {"Ref": "S"}, "ResourcePolicy": policy,
        }),
    })
    f = next(x for x in ExtendedChecks(ctx).run() if x.check_id == "SM-002")
    assert f.passed is False


def test_iam008_oidc_missing_audience_fails():
    trust = {"Statement": [{
        "Effect": "Allow",
        "Principal": {"Federated": _GH_OIDC},
        "Action": "sts:AssumeRoleWithWebIdentity",
    }]}
    ctx = make_context({
        "R": r("R", "AWS::IAM::Role", {"AssumeRolePolicyDocument": trust}),
    })
    f = next(x for x in ExtendedChecks(ctx).run() if x.check_id == "IAM-008")
    assert f.passed is False


def test_iam008_oidc_pinned_passes():
    trust = {"Statement": [{
        "Effect": "Allow",
        "Principal": {"Federated": _GH_OIDC},
        "Action": "sts:AssumeRoleWithWebIdentity",
        "Condition": {
            "StringEquals": {"token.actions.githubusercontent.com:aud": "sts.amazonaws.com"},
            "StringLike": {"token.actions.githubusercontent.com:sub": "repo:corp/*"},
        },
    }]}
    ctx = make_context({
        "R": r("R", "AWS::IAM::Role", {"AssumeRolePolicyDocument": trust}),
    })
    f = next(x for x in ExtendedChecks(ctx).run() if x.check_id == "IAM-008")
    assert f.passed is True


def test_iam008_non_oidc_skipped():
    trust = {"Statement": [{
        "Effect": "Allow",
        "Principal": {"Service": "codebuild.amazonaws.com"},
        "Action": "sts:AssumeRole",
    }]}
    ctx = make_context({
        "R": r("R", "AWS::IAM::Role", {"AssumeRolePolicyDocument": trust}),
    })
    assert not any(x.check_id == "IAM-008" for x in ExtendedChecks(ctx).run())


# ───────── Phase 2: services.py ─────────

def test_ca001_no_cmk_fails():
    ctx = make_context({
        "D": r("D", "AWS::CodeArtifact::Domain", {"DomainName": "corp"}),
    })
    f = next(x for x in ServiceChecks(ctx).run() if x.check_id == "CA-001")
    assert f.passed is False


def test_ca001_cmk_passes():
    ctx = make_context({
        "D": r("D", "AWS::CodeArtifact::Domain", {
            "DomainName": "corp",
            "EncryptionKey": "arn:aws:kms:us-east-1:1:key/abc",
        }),
    })
    f = next(x for x in ServiceChecks(ctx).run() if x.check_id == "CA-001")
    assert f.passed is True


def test_ca002_public_upstream_fails():
    ctx = make_context({
        "R": r("R", "AWS::CodeArtifact::Repository", {
            "RepositoryName": "r",
            "DomainName": "corp",
            "ExternalConnections": ["public:npmjs"],
        }),
    })
    f = next(x for x in ServiceChecks(ctx).run() if x.check_id == "CA-002")
    assert f.passed is False


def test_ca003_wildcard_policy_fails():
    ctx = make_context({
        "D": r("D", "AWS::CodeArtifact::Domain", {
            "DomainName": "corp",
            "PermissionsPolicyDocument": {
                "Statement": [{"Effect": "Allow", "Principal": "*", "Action": "*"}],
            },
        }),
    })
    f = next(x for x in ServiceChecks(ctx).run() if x.check_id == "CA-003")
    assert f.passed is False


def test_ca004_wildcard_action_and_resource_fails():
    ctx = make_context({
        "R": r("R", "AWS::CodeArtifact::Repository", {
            "RepositoryName": "r",
            "DomainName": "corp",
            "PermissionsPolicyDocument": {
                "Statement": [{
                    "Effect": "Allow",
                    "Principal": {"AWS": "arn:aws:iam::1:root"},
                    "Action": "codeartifact:*", "Resource": "*",
                }],
            },
        }),
    })
    f = next(x for x in ServiceChecks(ctx).run() if x.check_id == "CA-004")
    assert f.passed is False


def test_ccm002_default_kms_fails():
    ctx = make_context({
        "R": r("R", "AWS::CodeCommit::Repository", {
            "RepositoryName": "app",
            "KmsKeyId": "alias/aws/codecommit",
        }),
    })
    f = next(x for x in ServiceChecks(ctx).run() if x.check_id == "CCM-002")
    assert f.passed is False


def test_ccm002_cmk_passes():
    ctx = make_context({
        "R": r("R", "AWS::CodeCommit::Repository", {
            "RepositoryName": "app",
            "KmsKeyId": "arn:aws:kms:us-east-1:1:key/cc",
        }),
    })
    f = next(x for x in ServiceChecks(ctx).run() if x.check_id == "CCM-002")
    assert f.passed is True


def test_lmb001_no_signing_fails():
    ctx = make_context({
        "F": r("F", "AWS::Lambda::Function", {"FunctionName": "fn"}),
    })
    f = next(x for x in ServiceChecks(ctx).run() if x.check_id == "LMB-001")
    assert f.passed is False


def test_lmb002_none_url_auth_fails():
    ctx = make_context({
        "F": r("F", "AWS::Lambda::Function", {"FunctionName": "fn"}),
        "U": r("U", "AWS::Lambda::Url", {
            "TargetFunctionArn": {"Ref": "F"},
            "AuthType": "NONE",
        }),
    })
    f = next(x for x in ServiceChecks(ctx).run() if x.check_id == "LMB-002")
    assert f.passed is False


def test_lmb003_secret_env_fails():
    ctx = make_context({
        "F": r("F", "AWS::Lambda::Function", {
            "FunctionName": "fn",
            "Environment": {"Variables": {"DB_PASSWORD": "leaked"}},
        }),
    })
    f = next(x for x in ServiceChecks(ctx).run() if x.check_id == "LMB-003")
    assert f.passed is False


def test_lmb004_wildcard_principal_unscoped_fails():
    ctx = make_context({
        "P": r("P", "AWS::Lambda::Permission", {
            "FunctionName": {"Ref": "F"},
            "Principal": "*",
            "Action": "lambda:InvokeFunction",
        }),
    })
    f = next(x for x in ServiceChecks(ctx).run() if x.check_id == "LMB-004")
    assert f.passed is False


def test_lmb004_scoped_wildcard_passes():
    ctx = make_context({
        "P": r("P", "AWS::Lambda::Permission", {
            "FunctionName": {"Ref": "F"},
            "Principal": "*",
            "Action": "lambda:InvokeFunction",
            "SourceArn": "arn:aws:execute-api:::x",
        }),
    })
    f = next(x for x in ServiceChecks(ctx).run() if x.check_id == "LMB-004")
    assert f.passed is True


def test_kms001_rotation_off_fails():
    ctx = make_context({
        "K": r("K", "AWS::KMS::Key", {"EnableKeyRotation": False, "KeyPolicy": {"Statement": []}}),
    })
    f = next(x for x in ServiceChecks(ctx).run() if x.check_id == "KMS-001")
    assert f.passed is False


def test_kms002_wildcard_fails():
    ctx = make_context({
        "K": r("K", "AWS::KMS::Key", {
            "EnableKeyRotation": True,
            "KeyPolicy": {"Statement": [{
                "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::1:root"},
                "Action": "kms:*",
            }]},
        }),
    })
    f = next(x for x in ServiceChecks(ctx).run() if x.check_id == "KMS-002")
    assert f.passed is False


def test_ssm001_secret_string_fails():
    ctx = make_context({
        "P": r("P", "AWS::SSM::Parameter", {"Name": "/app/DB_PASSWORD", "Type": "String"}),
    })
    f = next(x for x in ServiceChecks(ctx).run() if x.check_id == "SSM-001")
    assert f.passed is False


# ───────── Phase 3: phase3.py ─────────

def test_ecr006_untrusted_fails():
    ctx = make_context({
        "R": r("R", "AWS::ECR::PullThroughCacheRule", {
            "UpstreamRegistryUrl": "registry-1.docker.io",
            "EcrRepositoryPrefix": "docker",
        }),
    })
    f = next(x for x in Phase3Checks(ctx).run() if x.check_id == "ECR-006")
    assert f.passed is False


def test_ecr006_k8s_trusted_passes():
    ctx = make_context({
        "R": r("R", "AWS::ECR::PullThroughCacheRule", {
            "UpstreamRegistryUrl": "registry.k8s.io",
            "EcrRepositoryPrefix": "k8s",
        }),
    })
    f = next(x for x in Phase3Checks(ctx).run() if x.check_id == "ECR-006")
    assert f.passed is True


def test_pbac003_open_egress_fails():
    ctx = make_context({
        "SG": r("SG", "AWS::EC2::SecurityGroup", {
            "SecurityGroupEgress": [{
                "IpProtocol": "-1",
                "FromPort": 0, "ToPort": 0,
                "CidrIp": "0.0.0.0/0",
            }],
        }),
    })
    f = next(x for x in Phase3Checks(ctx).run() if x.check_id == "PBAC-003")
    assert f.passed is False


def test_pbac005_shared_role_fails():
    ctx = make_context({
        "P": r("P", "AWS::CodePipeline::Pipeline", {
            "Name": "p", "RoleArn": {"Ref": "TopRole"},
            "Stages": [{
                "Name": "Source",
                "Actions": [{"Name": "S", "RoleArn": {"Ref": "TopRole"}, "ActionTypeId": {}}],
            }],
        }),
    })
    f = next(x for x in Phase3Checks(ctx).run() if x.check_id == "PBAC-005")
    assert f.passed is False


def test_cp005_prod_no_approval_fails():
    ctx = make_context({
        "P": r("P", "AWS::CodePipeline::Pipeline", {
            "Name": "p",
            "Stages": [
                {"Name": "Source", "Actions": [{"Name": "s", "ActionTypeId": {}}]},
                {"Name": "DeployProd", "Actions": [{"Name": "d", "ActionTypeId": {"Category": "Deploy"}}]},
            ],
        }),
    })
    f = next(x for x in Phase3Checks(ctx).run() if x.check_id == "CP-005")
    assert f.passed is False


def test_cp007_v2_open_pr_fails():
    ctx = make_context({
        "P": r("P", "AWS::CodePipeline::Pipeline", {
            "Name": "p", "PipelineType": "V2",
            "Triggers": [{
                "ProviderType": "CodeStarSourceConnection",
                "GitConfiguration": {
                    "PullRequest": [{"Branches": {"Includes": ["*"]}}],
                },
            }],
            "Stages": [],
        }),
    })
    f = next(x for x in Phase3Checks(ctx).run() if x.check_id == "CP-007")
    assert f.passed is False


def test_eb001_no_matching_rule_fails():
    ctx = make_context({
        "R": r("R", "AWS::Events::Rule", {
            "EventPattern": {"detail-type": ["EC2 Instance State-change Notification"]},
        }),
    })
    f = next(x for x in Phase3Checks(ctx).run() if x.check_id == "EB-001")
    assert f.passed is False


def test_eb001_with_matching_rule_passes():
    ctx = make_context({
        "R": r("R", "AWS::Events::Rule", {"EventPattern": _FAILED_PATTERN}),
    })
    f = next(x for x in Phase3Checks(ctx).run() if x.check_id == "EB-001")
    assert f.passed is True


def test_eb001_string_event_pattern():
    ctx = make_context({
        "R": r("R", "AWS::Events::Rule", {"EventPattern": json.dumps(_FAILED_PATTERN)}),
    })
    f = next(x for x in Phase3Checks(ctx).run() if x.check_id == "EB-001")
    assert f.passed is True
