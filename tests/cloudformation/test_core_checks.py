"""Unit tests for the seven core CFN service modules (CB/CP/CD/ECR/IAM/PBAC/S3)."""
from __future__ import annotations

from pipeline_check.core.checks.cloudformation.codebuild import CodeBuildChecks
from pipeline_check.core.checks.cloudformation.codedeploy import CodeDeployChecks
from pipeline_check.core.checks.cloudformation.codepipeline import CodePipelineChecks
from pipeline_check.core.checks.cloudformation.ecr import ECRChecks
from pipeline_check.core.checks.cloudformation.iam import IAMChecks
from pipeline_check.core.checks.cloudformation.pbac import PBACChecks
from pipeline_check.core.checks.cloudformation.s3 import S3Checks
from tests.cloudformation.conftest import make_context, r

# ─── CodeBuild ──────────────────────────────────────────────────────────────

def _cb_props(**overrides):
    props = {
        "Name": "my-project",
        "ServiceRole": "arn:aws:iam::111111111111:role/svc",
        "Environment": {
            "Image": "aws/codebuild/standard:7.0",
            "EnvironmentVariables": [],
        },
        "LogsConfig": {
            "CloudWatchLogs": {"Status": "ENABLED"},
            "S3Logs": {"Status": "DISABLED"},
        },
        "TimeoutInMinutes": 60,
        "Source": {"Type": "NO_SOURCE"},
    }
    props.update(overrides)
    return props


def test_cb001_plaintext_secret_fails():
    env = {
        "Image": "aws/codebuild/standard:7.0",
        "EnvironmentVariables": [
            {"Name": "DB_PASSWORD", "Type": "PLAINTEXT", "Value": "leaked"},
        ],
    }
    ctx = make_context({
        "P": r("P", "AWS::CodeBuild::Project", _cb_props(Environment=env)),
    })
    findings = CodeBuildChecks(ctx).run()
    cb001 = next(f for f in findings if f.check_id == "CB-001")
    assert cb001.passed is False


def test_cb001_secrets_manager_type_passes():
    env = {
        "Image": "aws/codebuild/standard:7.0",
        "EnvironmentVariables": [
            {"Name": "DB_PASSWORD", "Type": "SECRETS_MANAGER", "Value": "my-secret"},
        ],
    }
    ctx = make_context({
        "P": r("P", "AWS::CodeBuild::Project", _cb_props(Environment=env)),
    })
    findings = CodeBuildChecks(ctx).run()
    assert next(f for f in findings if f.check_id == "CB-001").passed is True


def test_cb002_privileged_fails():
    env = {"Image": "aws/codebuild/standard:7.0", "PrivilegedMode": True}
    ctx = make_context({"P": r("P", "AWS::CodeBuild::Project", _cb_props(Environment=env))})
    findings = CodeBuildChecks(ctx).run()
    assert next(f for f in findings if f.check_id == "CB-002").passed is False


def test_cb003_both_logs_disabled_fails():
    logs = {
        "CloudWatchLogs": {"Status": "DISABLED"},
        "S3Logs": {"Status": "DISABLED"},
    }
    ctx = make_context({"P": r("P", "AWS::CodeBuild::Project", _cb_props(LogsConfig=logs))})
    findings = CodeBuildChecks(ctx).run()
    assert next(f for f in findings if f.check_id == "CB-003").passed is False


def test_cb004_max_timeout_fails():
    ctx = make_context({"P": r("P", "AWS::CodeBuild::Project", _cb_props(TimeoutInMinutes=480))})
    findings = CodeBuildChecks(ctx).run()
    assert next(f for f in findings if f.check_id == "CB-004").passed is False


def test_cb005_outdated_image_fails():
    env = {"Image": "aws/codebuild/standard:1.0"}
    ctx = make_context({"P": r("P", "AWS::CodeBuild::Project", _cb_props(Environment=env))})
    findings = CodeBuildChecks(ctx).run()
    assert next(f for f in findings if f.check_id == "CB-005").passed is False


def test_cb006_oauth_source_fails():
    source = {"Type": "GITHUB", "Auth": {"Type": "OAUTH"}, "Location": "https://..."}
    ctx = make_context({"P": r("P", "AWS::CodeBuild::Project", _cb_props(Source=source))})
    findings = CodeBuildChecks(ctx).run()
    assert next(f for f in findings if f.check_id == "CB-006").passed is False


def test_cb006_codeconnections_passes():
    source = {"Type": "GITHUB", "Auth": {"Type": "CODECONNECTIONS"}}
    ctx = make_context({"P": r("P", "AWS::CodeBuild::Project", _cb_props(Source=source))})
    findings = CodeBuildChecks(ctx).run()
    assert next(f for f in findings if f.check_id == "CB-006").passed is True


def test_cb007_webhook_without_filter_fails():
    triggers = {"Webhook": True}
    ctx = make_context({"P": r("P", "AWS::CodeBuild::Project", _cb_props(Triggers=triggers))})
    findings = CodeBuildChecks(ctx).run()
    assert next(f for f in findings if f.check_id == "CB-007").passed is False


def test_cb007_webhook_with_filter_passes():
    triggers = {
        "Webhook": True,
        "FilterGroups": [[{"Type": "EVENT", "Pattern": "PUSH"}]],
    }
    ctx = make_context({"P": r("P", "AWS::CodeBuild::Project", _cb_props(Triggers=triggers))})
    findings = CodeBuildChecks(ctx).run()
    assert next(f for f in findings if f.check_id == "CB-007").passed is True


# ─── CodePipeline ───────────────────────────────────────────────────────────

def test_cp001_deploy_without_approval_fails():
    stages = [
        {"Name": "Source", "Actions": [{"ActionTypeId": {"Category": "Source"}}]},
        {"Name": "Deploy", "Actions": [{"ActionTypeId": {"Category": "Deploy"}}]},
    ]
    ctx = make_context({
        "P": r("P", "AWS::CodePipeline::Pipeline", {"Name": "pipe", "Stages": stages}),
    })
    f = next(f for f in CodePipelineChecks(ctx).run() if f.check_id == "CP-001")
    assert f.passed is False


def test_cp001_deploy_with_prior_approval_passes():
    stages = [
        {"Name": "Source", "Actions": [{"ActionTypeId": {"Category": "Source"}}]},
        {"Name": "Approve", "Actions": [{"ActionTypeId": {"Category": "Approval"}}]},
        {"Name": "Deploy", "Actions": [{"ActionTypeId": {"Category": "Deploy"}}]},
    ]
    ctx = make_context({
        "P": r("P", "AWS::CodePipeline::Pipeline", {"Name": "pipe", "Stages": stages}),
    })
    f = next(f for f in CodePipelineChecks(ctx).run() if f.check_id == "CP-001")
    assert f.passed is True


def test_cp002_no_encryption_key_fails():
    ctx = make_context({
        "P": r("P", "AWS::CodePipeline::Pipeline", {
            "Name": "pipe",
            "ArtifactStore": {"Type": "S3", "Location": "buck"},
            "Stages": [],
        }),
    })
    f = next(f for f in CodePipelineChecks(ctx).run() if f.check_id == "CP-002")
    assert f.passed is False


def test_cp003_polling_fails():
    stages = [{
        "Name": "Source",
        "Actions": [{
            "Name": "S",
            "ActionTypeId": {"Category": "Source"},
            "Configuration": {"PollForSourceChanges": "true"},
        }],
    }]
    ctx = make_context({
        "P": r("P", "AWS::CodePipeline::Pipeline", {"Name": "pipe", "Stages": stages}),
    })
    f = next(f for f in CodePipelineChecks(ctx).run() if f.check_id == "CP-003")
    assert f.passed is False


def test_cp004_legacy_github_fails():
    stages = [{
        "Name": "Source",
        "Actions": [{
            "Name": "S",
            "ActionTypeId": {"Category": "Source", "Owner": "ThirdParty", "Provider": "GitHub"},
        }],
    }]
    ctx = make_context({
        "P": r("P", "AWS::CodePipeline::Pipeline", {"Name": "pipe", "Stages": stages}),
    })
    f = next(f for f in CodePipelineChecks(ctx).run() if f.check_id == "CP-004")
    assert f.passed is False


# ─── CodeDeploy ─────────────────────────────────────────────────────────────

def test_cd001_no_rollback_fails():
    ctx = make_context({
        "G": r("G", "AWS::CodeDeploy::DeploymentGroup", {
            "ApplicationName": "A", "DeploymentGroupName": "G",
        }),
    })
    f = next(x for x in CodeDeployChecks(ctx).run() if x.check_id == "CD-001")
    assert f.passed is False


def test_cd002_all_at_once_fails():
    ctx = make_context({
        "G": r("G", "AWS::CodeDeploy::DeploymentGroup", {
            "ApplicationName": "A", "DeploymentGroupName": "G",
            "DeploymentConfigName": "CodeDeployDefault.AllAtOnce",
        }),
    })
    f = next(x for x in CodeDeployChecks(ctx).run() if x.check_id == "CD-002")
    assert f.passed is False


def test_cd003_alarms_configured_passes():
    ctx = make_context({
        "G": r("G", "AWS::CodeDeploy::DeploymentGroup", {
            "ApplicationName": "A", "DeploymentGroupName": "G",
            "AlarmConfiguration": {"Enabled": True, "Alarms": [{"Name": "Errors"}]},
        }),
    })
    f = next(x for x in CodeDeployChecks(ctx).run() if x.check_id == "CD-003")
    assert f.passed is True


# ─── ECR ────────────────────────────────────────────────────────────────────

def test_ecr001_scan_on_push_disabled_fails():
    ctx = make_context({
        "R": r("R", "AWS::ECR::Repository", {
            "RepositoryName": "r",
            "ImageScanningConfiguration": {"ScanOnPush": False},
        }),
    })
    f = next(x for x in ECRChecks(ctx).run() if x.check_id == "ECR-001")
    assert f.passed is False


def test_ecr002_immutable_passes():
    ctx = make_context({
        "R": r("R", "AWS::ECR::Repository", {
            "RepositoryName": "r",
            "ImageTagMutability": "IMMUTABLE",
        }),
    })
    f = next(x for x in ECRChecks(ctx).run() if x.check_id == "ECR-002")
    assert f.passed is True


def test_ecr003_wildcard_principal_fails():
    policy = {"Statement": [{"Effect": "Allow", "Principal": "*", "Action": "ecr:*"}]}
    ctx = make_context({
        "R": r("R", "AWS::ECR::Repository", {
            "RepositoryName": "r",
            "RepositoryPolicyText": policy,
        }),
    })
    f = next(x for x in ECRChecks(ctx).run() if x.check_id == "ECR-003")
    assert f.passed is False


def test_ecr005_aes256_fails():
    ctx = make_context({
        "R": r("R", "AWS::ECR::Repository", {
            "RepositoryName": "r",
            "EncryptionConfiguration": {"EncryptionType": "AES256"},
        }),
    })
    f = next(x for x in ECRChecks(ctx).run() if x.check_id == "ECR-005")
    assert f.passed is False


# ─── IAM ────────────────────────────────────────────────────────────────────

_CICD_TRUST = {
    "Statement": [{
        "Effect": "Allow",
        "Principal": {"Service": "codebuild.amazonaws.com"},
        "Action": "sts:AssumeRole",
    }],
}


def test_iam001_admin_access_fails():
    ctx = make_context({
        "R": r("R", "AWS::IAM::Role", {
            "AssumeRolePolicyDocument": _CICD_TRUST,
            "ManagedPolicyArns": ["arn:aws:iam::aws:policy/AdministratorAccess"],
        }),
    })
    f = next(x for x in IAMChecks(ctx).run() if x.check_id == "IAM-001")
    assert f.passed is False


def test_iam002_wildcard_action_inline_fails():
    policies = [{
        "PolicyName": "p",
        "PolicyDocument": {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]},
    }]
    ctx = make_context({
        "R": r("R", "AWS::IAM::Role", {
            "AssumeRolePolicyDocument": _CICD_TRUST,
            "Policies": policies,
        }),
    })
    f = next(x for x in IAMChecks(ctx).run() if x.check_id == "IAM-002")
    assert f.passed is False


def test_iam003_no_boundary_fails():
    ctx = make_context({
        "R": r("R", "AWS::IAM::Role", {"AssumeRolePolicyDocument": _CICD_TRUST}),
    })
    f = next(x for x in IAMChecks(ctx).run() if x.check_id == "IAM-003")
    assert f.passed is False


def test_iam003_boundary_passes():
    ctx = make_context({
        "R": r("R", "AWS::IAM::Role", {
            "AssumeRolePolicyDocument": _CICD_TRUST,
            "PermissionsBoundary": "arn:aws:iam::1:policy/pb",
        }),
    })
    f = next(x for x in IAMChecks(ctx).run() if x.check_id == "IAM-003")
    assert f.passed is True


def test_iam004_passrole_wildcard_fails():
    policies = [{
        "PolicyName": "pass",
        "PolicyDocument": {"Statement": [{
            "Effect": "Allow", "Action": "iam:PassRole", "Resource": "*",
        }]},
    }]
    ctx = make_context({
        "R": r("R", "AWS::IAM::Role", {
            "AssumeRolePolicyDocument": _CICD_TRUST, "Policies": policies,
        }),
    })
    f = next(x for x in IAMChecks(ctx).run() if x.check_id == "IAM-004")
    assert f.passed is False


def test_iam005_external_trust_no_externalid_fails():
    trust = {
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "codebuild.amazonaws.com"},
                "Action": "sts:AssumeRole",
            },
            {
                "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::999:root"},
                "Action": "sts:AssumeRole",
            },
        ],
    }
    ctx = make_context({
        "R": r("R", "AWS::IAM::Role", {"AssumeRolePolicyDocument": trust}),
    })
    f = next(x for x in IAMChecks(ctx).run() if x.check_id == "IAM-005")
    assert f.passed is False


# ─── PBAC ───────────────────────────────────────────────────────────────────

def test_pbac001_no_vpc_fails():
    ctx = make_context({
        "P": r("P", "AWS::CodeBuild::Project", {"Name": "p"}),
    })
    f = next(x for x in PBACChecks(ctx).run() if x.check_id == "PBAC-001")
    assert f.passed is False


def test_pbac002_shared_role_fails():
    role = {"Ref": "SharedRole"}
    ctx = make_context({
        "P1": r("P1", "AWS::CodeBuild::Project", {"Name": "p1", "ServiceRole": role}),
        "P2": r("P2", "AWS::CodeBuild::Project", {"Name": "p2", "ServiceRole": role}),
    })
    findings = [x for x in PBACChecks(ctx).run() if x.check_id == "PBAC-002"]
    assert any(not x.passed for x in findings)


# ─── S3 ─────────────────────────────────────────────────────────────────────

def test_s3_no_pipeline_emits_nothing():
    ctx = make_context({
        "B": r("B", "AWS::S3::Bucket", {"BucketName": "b"}),
    })
    assert S3Checks(ctx).run() == []


def test_s3001_public_access_block_missing_fails():
    ctx = make_context({
        "Pipe": r("Pipe", "AWS::CodePipeline::Pipeline", {
            "Name": "p",
            "ArtifactStore": {"Type": "S3", "Location": {"Ref": "Bucket"}},
            "Stages": [],
        }),
        "Bucket": r("Bucket", "AWS::S3::Bucket", {"BucketName": "art"}),
    })
    f = next(x for x in S3Checks(ctx).run() if x.check_id == "S3-001")
    assert f.passed is False


def test_s3_full_secure_passes():
    ctx = make_context({
        "Pipe": r("Pipe", "AWS::CodePipeline::Pipeline", {
            "Name": "p",
            "ArtifactStore": {"Type": "S3", "Location": {"Ref": "Bucket"}},
            "Stages": [],
        }),
        "Bucket": r("Bucket", "AWS::S3::Bucket", {
            "BucketName": "art",
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True, "IgnorePublicAcls": True,
                "BlockPublicPolicy": True, "RestrictPublicBuckets": True,
            },
            "BucketEncryption": {
                "ServerSideEncryptionConfiguration": [{
                    "ServerSideEncryptionByDefault": {"SSEAlgorithm": "aws:kms"},
                }],
            },
            "VersioningConfiguration": {"Status": "Enabled"},
            "LoggingConfiguration": {"DestinationBucketName": "log-bucket"},
        }),
        "Policy": r("Policy", "AWS::S3::BucketPolicy", {
            "Bucket": {"Ref": "Bucket"},
            "PolicyDocument": {
                "Statement": [{
                    "Effect": "Deny", "Action": "s3:*",
                    "Principal": "*",
                    "Condition": {"Bool": {"aws:SecureTransport": "false"}},
                }],
            },
        }),
    })
    findings = S3Checks(ctx).run()
    failed = [f for f in findings if not f.passed]
    assert failed == [], [f.check_id for f in failed]
