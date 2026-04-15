"""End-to-end integration test: full mock AWS pipeline through the Scanner.

Two scenarios are tested:
  - SECURE   — every service is correctly configured; all checks should pass.
  - INSECURE — every service is deliberately misconfigured; every check that
               has a clear failure condition should fail.

A third suite verifies OWASP CI/CD Top 10 coverage across the full finding set.
"""

import json
from unittest.mock import MagicMock

import pytest
from botocore.exceptions import ClientError

from pipeline_check.core import providers as _providers
from pipeline_check.core.scanner import Scanner
from pipeline_check.core.checks.aws.base import Severity
from tests.aws.conftest import make_paginator


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _client_error(code):
    return ClientError({"Error": {"Code": code, "Message": ""}}, "op")


def _cicd_trust(service="codebuild.amazonaws.com"):
    return {
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": service},
            "Action": "sts:AssumeRole",
        }]
    }


_SHARED_ROLE = "arn:aws:iam::123456789:role/shared-build-role"
_SECURE_VPC = {"vpcId": "vpc-abc123", "subnets": ["subnet-1"], "securityGroupIds": ["sg-1"]}


def _make_codebuild_client(
    *,
    plaintext_secret=False,
    privileged=False,
    logging_enabled=True,
    timeout=60,
    image="aws/codebuild/standard:7.0",
    vpc_config=_SECURE_VPC,
    service_role="arn:aws:iam::123456789:role/my-build-role",
    extra_projects=None,
):
    client = MagicMock()
    env_vars = (
        [{"name": "DB_PASSWORD", "type": "PLAINTEXT", "value": "s3cr3t"}]
        if plaintext_secret
        else []
    )
    project = {
        "name": "my-build",
        "serviceRole": service_role,
        "environment": {
            "environmentVariables": env_vars,
            "privilegedMode": privileged,
            "image": image,
        },
        "logsConfig": {
            "cloudWatchLogs": {"status": "ENABLED" if logging_enabled else "DISABLED"},
            "s3Logs": {"status": "DISABLED"},
        },
        "timeoutInMinutes": timeout,
    }
    if vpc_config is not None:
        project["vpcConfig"] = vpc_config

    projects = [project] + (extra_projects or [])
    names = [p["name"] for p in projects]
    # Both CodeBuildChecks and PBACChecks iterate this paginator, so yield a
    # fresh iterator on every paginate() call instead of a single consumed one.
    _pages = [{"projects": names}]
    paginator = MagicMock()
    paginator.paginate.side_effect = lambda **kw: iter(_pages)
    client.get_paginator.return_value = paginator
    client.batch_get_projects.return_value = {"projects": projects}
    return client


def _make_codepipeline_client(
    *,
    approval_before_deploy=True,
    kms_encrypted=True,
    event_driven=True,
    artifact_bucket="artifact-bucket",
):
    client = MagicMock()

    source_action = {
        "name": "Source",
        "actionTypeId": {"category": "Source", "owner": "AWS", "provider": "CodeCommit", "version": "1"},
        "configuration": {"PollForSourceChanges": "false" if event_driven else "true"},
    }
    build_action = {
        "name": "Build",
        "actionTypeId": {"category": "Build", "owner": "AWS", "provider": "CodeBuild", "version": "1"},
        "configuration": {},
    }
    approval_action = {
        "name": "Approve",
        "actionTypeId": {"category": "Approval", "owner": "AWS", "provider": "Manual", "version": "1"},
        "configuration": {},
    }
    deploy_action = {
        "name": "Deploy",
        "actionTypeId": {"category": "Deploy", "owner": "AWS", "provider": "CodeDeploy", "version": "1"},
        "configuration": {},
    }

    if approval_before_deploy:
        stages = [
            {"actions": [source_action]},
            {"actions": [build_action]},
            {"actions": [approval_action]},
            {"actions": [deploy_action]},
        ]
    else:
        stages = [
            {"actions": [source_action]},
            {"actions": [build_action]},
            {"actions": [deploy_action]},
        ]

    artifact_store = {"type": "S3", "location": artifact_bucket}
    if kms_encrypted:
        artifact_store["encryptionKey"] = {
            "id": "arn:aws:kms:us-east-1:123456789:key/abc123",
            "type": "KMS",
        }

    pipeline = {
        "name": "my-pipeline",
        "stages": stages,
        "artifactStore": artifact_store,
    }

    # S3Checks also calls this client to discover artifact buckets, so the
    # paginator must produce a fresh iterator on every paginate() call rather
    # than a single consumed iterator.
    _pages = [{"pipelines": [{"name": "my-pipeline"}]}]
    paginator = MagicMock()
    paginator.paginate.side_effect = lambda **kw: iter(_pages)
    client.get_paginator.return_value = paginator
    client.get_pipeline.return_value = {"pipeline": pipeline}
    return client


def _make_codedeploy_client(
    *,
    rollback_on_failure=True,
    deployment_config="CodeDeployDefault.LambdaCanary10Percent5Minutes",
    alarms_enabled=True,
):
    client = MagicMock()

    group = {
        "deploymentGroupName": "my-group",
        "autoRollbackConfiguration": {
            "enabled": rollback_on_failure,
            "events": ["DEPLOYMENT_FAILURE"] if rollback_on_failure else [],
        },
        "deploymentConfigName": deployment_config,
        "alarmConfiguration": {
            "enabled": alarms_enabled,
            "alarms": [{"name": "HighErrorRate"}] if alarms_enabled else [],
        },
    }

    def get_paginator(operation):
        if operation == "list_applications":
            return make_paginator([{"applications": ["my-app"]}])
        if operation == "list_deployment_groups":
            p = MagicMock()
            p.paginate.return_value = iter([{"deploymentGroups": ["my-group"]}])
            return p
        raise ValueError(f"Unexpected paginator: {operation}")

    client.get_paginator.side_effect = get_paginator
    client.batch_get_deployment_groups.return_value = {"deploymentGroupsInfo": [group]}
    return client


def _make_ecr_client(
    *,
    scan_on_push=True,
    immutable_tags=True,
    public_policy=False,
    lifecycle_policy=True,
    kms_encryption=True,
):
    client = MagicMock()

    if kms_encryption:
        enc_cfg = {
            "encryptionType": "KMS",
            "kmsKey": "arn:aws:kms:us-east-1:123456789:key/abc",
        }
    else:
        enc_cfg = {"encryptionType": "AES256"}

    repo = {
        "repositoryName": "my-repo",
        "repositoryArn": "arn:aws:ecr:us-east-1:123456789:repository/my-repo",
        "imageScanningConfiguration": {"scanOnPush": scan_on_push},
        "imageTagMutability": "IMMUTABLE" if immutable_tags else "MUTABLE",
        "encryptionConfiguration": enc_cfg,
    }

    paginator = make_paginator([{"repositories": [repo]}])
    client.get_paginator.return_value = paginator

    if public_policy:
        policy = json.dumps({
            "Statement": [{"Effect": "Allow", "Principal": "*", "Action": "ecr:GetDownloadUrlForLayer"}]
        })
        client.get_repository_policy.return_value = {"policyText": policy}
    else:
        client.get_repository_policy.side_effect = _client_error("RepositoryPolicyNotFoundException")

    if lifecycle_policy:
        client.get_lifecycle_policy.return_value = {"lifecyclePolicyText": "{}"}
    else:
        client.get_lifecycle_policy.side_effect = _client_error("LifecyclePolicyNotFoundException")

    return client


def _make_iam_client(
    *,
    admin_access=False,
    wildcard_inline=False,
    permission_boundary=True,
):
    client = MagicMock()

    role = {
        "RoleName": "codebuild-role",
        "RoleId": "AROA123",
        "Arn": "arn:aws:iam::123456789:role/codebuild-role",
        "Path": "/",
        "AssumeRolePolicyDocument": _cicd_trust("codebuild.amazonaws.com"),
    }
    if permission_boundary:
        role["PermissionsBoundary"] = {
            "PermissionsBoundaryArn": "arn:aws:iam::123456789:policy/CICDBoundary",
            "PermissionsBoundaryType": "Policy",
        }

    paginator = make_paginator([{"Roles": [role]}])
    client.get_paginator.return_value = paginator

    attached = []
    if admin_access:
        attached.append({
            "PolicyName": "AdministratorAccess",
            "PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess",
        })
    client.list_attached_role_policies.return_value = {"AttachedPolicies": attached}

    if wildcard_inline:
        client.list_role_policies.return_value = {"PolicyNames": ["WildcardPolicy"]}
        client.get_role_policy.return_value = {
            "PolicyDocument": {
                "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]
            }
        }
    else:
        client.list_role_policies.return_value = {"PolicyNames": []}

    return client


_SECURE_TRANSPORT_POLICY = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Deny",
        "Principal": "*",
        "Action": "s3:*",
        "Resource": "arn:aws:s3:::artifact-bucket/*",
        "Condition": {"Bool": {"aws:SecureTransport": "false"}},
    }],
})


def _make_s3_client(
    *,
    public_access_blocked=True,
    encrypted=True,
    versioning_enabled=True,
    logging_enabled=True,
    secure_transport_deny=True,
):
    client = MagicMock()

    if public_access_blocked:
        pub_block = {
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        }
    else:
        pub_block = {
            "BlockPublicAcls": False,
            "IgnorePublicAcls": False,
            "BlockPublicPolicy": False,
            "RestrictPublicBuckets": False,
        }
    client.get_public_access_block.return_value = {"PublicAccessBlockConfiguration": pub_block}

    if encrypted:
        client.get_bucket_encryption.return_value = {
            "ServerSideEncryptionConfiguration": {
                "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "aws:kms"}}]
            }
        }
    else:
        client.get_bucket_encryption.return_value = {
            "ServerSideEncryptionConfiguration": {"Rules": []}
        }

    client.get_bucket_versioning.return_value = {
        "Status": "Enabled" if versioning_enabled else "Suspended"
    }

    if logging_enabled:
        client.get_bucket_logging.return_value = {"LoggingEnabled": {"TargetBucket": "log-bucket"}}
    else:
        client.get_bucket_logging.return_value = {}

    if secure_transport_deny:
        client.get_bucket_policy.return_value = {"Policy": _SECURE_TRANSPORT_POLICY}
    else:
        client.get_bucket_policy.side_effect = _client_error("NoSuchBucketPolicy")

    return client


def _make_session(
    codebuild_client,
    codepipeline_client,
    codedeploy_client,
    ecr_client,
    iam_client,
    s3_client,
):
    """Wire all service clients into a single mock boto3 Session."""
    _map = {
        "codebuild": codebuild_client,
        "codepipeline": codepipeline_client,
        "codedeploy": codedeploy_client,
        "ecr": ecr_client,
        "iam": iam_client,
        "s3": s3_client,
    }
    session = MagicMock()
    session.client.side_effect = lambda svc, **kw: _map[svc]
    return session


def _make_scanner(session) -> Scanner:
    """Inject a pre-built session into a Scanner without touching boto3."""
    scanner = Scanner.__new__(Scanner)
    scanner.pipeline = "aws"
    scanner._context = session
    scanner._check_classes = _providers.get("aws").check_classes
    return scanner


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def secure_session():
    return _make_session(
        codebuild_client=_make_codebuild_client(),
        codepipeline_client=_make_codepipeline_client(artifact_bucket="artifact-bucket"),
        codedeploy_client=_make_codedeploy_client(),
        ecr_client=_make_ecr_client(),
        iam_client=_make_iam_client(),
        s3_client=_make_s3_client(),
    )


@pytest.fixture()
def insecure_session():
    # A second project sharing the same role triggers PBAC-002.
    shared_role_project = {
        "name": "my-build-2",
        "serviceRole": _SHARED_ROLE,
        "environment": {
            "environmentVariables": [],
            "privilegedMode": False,
            "image": "aws/codebuild/standard:7.0",
        },
        "logsConfig": {"cloudWatchLogs": {"status": "ENABLED"}, "s3Logs": {"status": "DISABLED"}},
        "timeoutInMinutes": 60,
        # no vpcConfig → also fails PBAC-001
    }
    return _make_session(
        codebuild_client=_make_codebuild_client(
            plaintext_secret=True,
            privileged=True,
            logging_enabled=False,
            timeout=480,
            image="aws/codebuild/standard:1.0",
            vpc_config=None,            # PBAC-001: no VPC
            service_role=_SHARED_ROLE,  # PBAC-002: shared role
            extra_projects=[shared_role_project],
        ),
        codepipeline_client=_make_codepipeline_client(
            approval_before_deploy=False,
            kms_encrypted=False,
            event_driven=False,
            artifact_bucket="artifact-bucket",
        ),
        codedeploy_client=_make_codedeploy_client(
            rollback_on_failure=False,
            deployment_config="CodeDeployDefault.AllAtOnce",
            alarms_enabled=False,
        ),
        ecr_client=_make_ecr_client(
            scan_on_push=False,
            immutable_tags=False,
            public_policy=True,
            lifecycle_policy=False,
            kms_encryption=False,
        ),
        iam_client=_make_iam_client(
            admin_access=True,
            wildcard_inline=True,
            permission_boundary=False,
        ),
        s3_client=_make_s3_client(
            public_access_blocked=False,
            encrypted=False,
            versioning_enabled=False,
            logging_enabled=False,
            secure_transport_deny=False,
        ),
    )


# ---------------------------------------------------------------------------
# Secure pipeline — all checks should pass
# ---------------------------------------------------------------------------

class TestSecurePipeline:
    def test_no_failures(self, secure_session):
        findings = _make_scanner(secure_session).run()
        failed = [f for f in findings if not f.passed]
        assert failed == [], (
            f"Expected no failures on a secure pipeline, got: "
            f"{[(f.check_id, f.title) for f in failed]}"
        )

    def test_all_services_produce_findings(self, secure_session):
        findings = _make_scanner(secure_session).run()
        check_prefixes = {f.check_id.split("-")[0] for f in findings}
        assert check_prefixes == {"CB", "CP", "CD", "ECR", "IAM", "PBAC", "S3"}


# ---------------------------------------------------------------------------
# Insecure pipeline — every configured failure should be detected
# ---------------------------------------------------------------------------

class TestInsecurePipeline:
    @pytest.fixture(autouse=True)
    def _findings(self, insecure_session):
        self.findings = _make_scanner(insecure_session).run()
        self.failed = {f.check_id for f in self.findings if not f.passed}

    # CodeBuild
    def test_cb001_plaintext_secret_detected(self):
        assert "CB-001" in self.failed

    def test_cb002_privileged_mode_detected(self):
        assert "CB-002" in self.failed

    def test_cb003_missing_logging_detected(self):
        assert "CB-003" in self.failed

    def test_cb004_unconstrained_timeout_detected(self):
        assert "CB-004" in self.failed

    def test_cb005_outdated_image_detected(self):
        assert "CB-005" in self.failed

    # CodePipeline
    def test_cp001_missing_approval_detected(self):
        assert "CP-001" in self.failed

    def test_cp002_unencrypted_artifact_store_detected(self):
        assert "CP-002" in self.failed

    def test_cp003_polling_source_detected(self):
        assert "CP-003" in self.failed

    # CodeDeploy
    def test_cd001_no_rollback_detected(self):
        assert "CD-001" in self.failed

    def test_cd002_all_at_once_detected(self):
        assert "CD-002" in self.failed

    def test_cd003_no_alarms_detected(self):
        assert "CD-003" in self.failed

    # ECR
    def test_ecr001_no_scan_on_push_detected(self):
        assert "ECR-001" in self.failed

    def test_ecr002_mutable_tags_detected(self):
        assert "ECR-002" in self.failed

    def test_ecr003_public_policy_detected(self):
        assert "ECR-003" in self.failed

    def test_ecr004_no_lifecycle_policy_detected(self):
        assert "ECR-004" in self.failed

    # IAM
    def test_iam001_admin_access_detected(self):
        assert "IAM-001" in self.failed

    def test_iam002_wildcard_inline_detected(self):
        assert "IAM-002" in self.failed

    def test_iam003_no_boundary_detected(self):
        assert "IAM-003" in self.failed

    # S3
    def test_s3001_public_access_not_blocked_detected(self):
        assert "S3-001" in self.failed

    def test_s3002_no_encryption_detected(self):
        assert "S3-002" in self.failed

    def test_s3003_no_versioning_detected(self):
        assert "S3-003" in self.failed

    def test_s3004_no_logging_detected(self):
        assert "S3-004" in self.failed

    # PBAC
    def test_pbac001_no_vpc_detected(self):
        assert "PBAC-001" in self.failed

    def test_pbac002_shared_role_detected(self):
        assert "PBAC-002" in self.failed

    def test_severity_distribution_includes_critical(self):
        critical = [f for f in self.findings if not f.passed and f.severity == Severity.CRITICAL]
        assert len(critical) >= 3, "Expected at least 3 CRITICAL failures on an insecure pipeline"


# ---------------------------------------------------------------------------
# OWASP CI/CD Top 10 coverage
# ---------------------------------------------------------------------------

# All 10 OWASP CI/CD risks are now covered.
_EXPECTED_OWASP_COVERAGE = {
    "CICD-SEC-1",   # Insufficient Flow Control Mechanisms   (CP-001, CD-001, CD-002)
    "CICD-SEC-2",   # Inadequate Identity and Access Mgmt    (IAM-001, IAM-002, IAM-003)
    "CICD-SEC-3",   # Dependency Chain Abuse                 (ECR-001)
    "CICD-SEC-4",   # Poisoned Pipeline Execution            (CP-003)
    "CICD-SEC-5",   # Insufficient PBAC                      (PBAC-001, PBAC-002)
    "CICD-SEC-6",   # Insufficient Credential Hygiene        (CB-001)
    "CICD-SEC-7",   # Insecure System Configuration          (CB-002, CB-004, CB-005, ECR-004)
    "CICD-SEC-8",   # Ungoverned Usage of 3rd-Party Services (ECR-003)
    "CICD-SEC-9",   # Improper Artifact Integrity Validation (CP-002, ECR-002, S3-001–003)
    "CICD-SEC-10",  # Insufficient Logging and Visibility    (CB-003, CD-003, S3-004)
}


class TestOWASPCoverage:
    @pytest.fixture(autouse=True)
    def _findings(self, insecure_session):
        self.findings = _make_scanner(insecure_session).run()

    @staticmethod
    def _owasp_ids(finding):
        return {
            c.control_id for c in finding.controls
            if c.standard == "owasp_cicd_top_10"
        }

    def test_expected_owasp_risks_are_covered(self):
        covered: set[str] = set()
        for f in self.findings:
            covered |= self._owasp_ids(f)
        missing = _EXPECTED_OWASP_COVERAGE - covered
        assert not missing, f"OWASP risks not covered by any check: {missing}"

    def test_each_finding_references_an_owasp_risk(self):
        for f in self.findings:
            owasp = self._owasp_ids(f)
            assert owasp, f"{f.check_id} has no OWASP mapping"
            for cid in owasp:
                assert cid.startswith("CICD-SEC-"), (
                    f"{f.check_id} has unexpected OWASP control id: {cid!r}"
                )

    @pytest.mark.parametrize("risk", sorted(_EXPECTED_OWASP_COVERAGE))
    def test_risk_has_at_least_one_check(self, risk):
        matching = [f for f in self.findings if risk in self._owasp_ids(f)]
        assert matching, f"No findings found for {risk}"
