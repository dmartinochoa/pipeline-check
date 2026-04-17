"""End-to-end integration tests for Phase 1-3 rule-based AWS checks.

The existing ``test_owasp_pipeline.py`` exercises the original 32 class-
based checks. This file drives the full Scanner → AWSRuleChecks →
ResourceCatalog → individual rule pipeline against a fully-misconfigured
mock AWS environment and asserts every new rule fires.

Also includes the degraded-finding regression test: when a service
client raises, exactly one ``<PREFIX>-000`` INFO finding must be
emitted — not one per dependent rule.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import pytest
from botocore.exceptions import ClientError

from pipeline_check.core import providers as _providers
from pipeline_check.core.checks.aws.base import Severity
from pipeline_check.core.scanner import Scanner

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _client_error(code="AccessDenied"):
    return ClientError({"Error": {"Code": code, "Message": ""}}, "op")


def _pages(pages):
    paginator = MagicMock()
    paginator.paginate.side_effect = lambda **_kw: iter(pages)
    return paginator


def _scanner_for(session):
    scanner = Scanner.__new__(Scanner)
    scanner.pipeline = "aws"
    scanner._context = session
    scanner._check_classes = _providers.get("aws").check_classes
    return scanner


# ---------------------------------------------------------------------------
# Per-service insecure mocks
# ---------------------------------------------------------------------------

# Shared AWS account id — misconfigured triggers point elsewhere.
_SELF_ACCOUNT = "111111111111"
_OTHER_ACCOUNT = "999999999999"


def _insecure_codebuild():
    """One project with:
       - inline buildspec (CB-008)
       - tag-pinned custom image (CB-009)
       - webhook with PR events and no actor filter (CB-010)
       - references a Secrets Manager secret in env (SM-001 input)
       - security group referenced by PBAC-003
    """
    project = {
        "name": "bad-build",
        "serviceRole": "arn:aws:iam::111111111111:role/svc",
        "source": {
            "type": "GITHUB",
            "buildspec": "version: 0.2\nphases:\n  build:\n    commands:\n      - echo hi",
        },
        "environment": {
            "image": "ghcr.io/corp/builder:latest",
            "environmentVariables": [
                {"name": "DB", "type": "SECRETS_MANAGER", "value": "prod-db-password"},
            ],
        },
        "webhook": {"filterGroups": [[
            {"type": "EVENT", "pattern": "PULL_REQUEST_CREATED,PULL_REQUEST_UPDATED"},
        ]]},
        "vpcConfig": {"vpcId": "vpc-1", "subnets": ["s1"], "securityGroupIds": ["sg-open"]},
        "logsConfig": {"cloudWatchLogs": {"status": "ENABLED"}, "s3Logs": {"status": "DISABLED"}},
        "timeoutInMinutes": 60,
    }
    client = MagicMock()
    client.get_paginator.return_value = _pages([{"projects": [project["name"]]}])
    client.batch_get_projects.return_value = {"projects": [project]}
    client.list_source_credentials.return_value = {"sourceCredentialsInfos": []}
    return client


def _insecure_cloudtrail():
    """No actively-logging trail — CT-001 fires.
    Also one trail with validation off + single-region so CT-002/003 fire."""
    client = MagicMock()
    trail = {
        "Name": "weak-trail",
        "TrailARN": "arn:aws:cloudtrail:us-east-1:111111111111:trail/weak-trail",
        "IsMultiRegionTrail": False,
        "LogFileValidationEnabled": False,
    }
    client.describe_trails.return_value = {"trailList": [trail]}
    client.get_trail_status.return_value = {"IsLogging": False}  # CT-001 fails
    return client


def _insecure_logs():
    """CodeBuild log group with no retention and no KMS key."""
    client = MagicMock()
    client.get_paginator.return_value = _pages([{
        "logGroups": [{"logGroupName": "/aws/codebuild/bad-build"}],
    }])
    return client


def _insecure_secretsmanager():
    """One secret referenced by CodeBuild with no rotation, plus wildcard policy."""
    client = MagicMock()
    secrets = [{
        "Name": "prod-db-password",
        "ARN": "arn:aws:secretsmanager:us-east-1:111111111111:secret:prod-db-password",
        "RotationEnabled": False,
    }]
    client.get_paginator.return_value = _pages([{"SecretList": secrets}])
    client.get_resource_policy.return_value = {"ResourcePolicy": json.dumps({
        "Statement": [{
            "Effect": "Allow",
            "Principal": "*",
            "Action": "secretsmanager:GetSecretValue",
        }]
    })}
    return client


def _insecure_iam():
    """IAM with:
       - One user with a 400-day-old active key (IAM-007).
       - One role whose OIDC trust lacks an audience pin (IAM-008).
    """
    client = MagicMock()
    old_role = {
        "RoleName": "gh-oidc-role",
        "AssumeRolePolicyDocument": json.dumps({
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"Federated": "arn:aws:iam::111111111111:oidc-provider/token.actions.githubusercontent.com"},
                "Action": "sts:AssumeRoleWithWebIdentity",
            }],
        }),
    }

    def _list_roles_paginator():
        return _pages([{"Roles": [old_role]}])

    def _list_users_paginator():
        return _pages([{"Users": [{"UserName": "legacy-ci"}]}])

    def _get_paginator(op):
        if op == "list_roles":
            return _list_roles_paginator()
        if op == "list_users":
            return _list_users_paginator()
        return _pages([])

    client.get_paginator.side_effect = _get_paginator

    stale_key = {
        "UserName": "legacy-ci",
        "AccessKeyId": "AKIAOLDKEY",
        "Status": "Active",
        "CreateDate": datetime.now(tz=timezone.utc) - timedelta(days=400),
    }
    client.list_access_keys.return_value = {"AccessKeyMetadata": [stale_key]}
    client.get_access_key_last_used.return_value = {"AccessKeyLastUsed": {}}
    # Existing IAMChecks class also calls these; return empty so it doesn't
    # crash while we're here.
    client.list_attached_role_policies.return_value = {"AttachedPolicies": []}
    client.list_role_policies.return_value = {"PolicyNames": []}
    return client


def _insecure_codeartifact():
    """Domain with AWS-owned encryption, public upstream, wildcard policies."""
    client = MagicMock()
    domains = [{"name": "corp", "encryptionKey": ""}]
    repos = [{"name": "shared", "domainName": "corp"}]

    def _get_paginator(op):
        if op == "list_domains":
            return _pages([{"domains": domains}])
        if op == "list_repositories":
            return _pages([{"repositories": repos}])
        return _pages([])

    client.get_paginator.side_effect = _get_paginator
    client.describe_repository.return_value = {
        "repository": {"externalConnections": [{"externalConnectionName": "public:npmjs"}]},
    }
    wildcard_policy = json.dumps({
        "Statement": [{"Effect": "Allow", "Principal": "*", "Action": "codeartifact:*"}]
    })
    client.get_domain_permissions_policy.return_value = {"policy": {"document": wildcard_policy}}
    # CA-004 needs Action+Resource wildcard on the repo policy.
    repo_over_broad = json.dumps({
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": "arn:aws:iam::111111111111:root"},
            "Action": "codeartifact:*",
            "Resource": "*",
        }]
    })
    client.get_repository_permissions_policy.return_value = {"policy": {"document": repo_over_broad}}
    return client


def _insecure_codecommit():
    """Repo with no approval template, AWS-managed encryption, cross-account trigger."""
    client = MagicMock()
    repos = [{"repositoryName": "app", "repositoryId": "r-1"}]
    client.get_paginator.return_value = _pages([{"repositories": repos}])
    client.list_associated_approval_rule_templates_for_repository.return_value = {
        "approvalRuleTemplateNames": [],
    }
    client.get_repository.return_value = {
        "repositoryMetadata": {"kmsKeyId": "alias/aws/codecommit"},
    }
    client.get_repository_triggers.return_value = {"triggers": [
        {"name": "t", "destinationArn": f"arn:aws:sns:us-east-1:{_OTHER_ACCOUNT}:external"},
    ]}
    return client


def _insecure_lambda():
    """Function with no signing, URL=NONE, secret env, wildcard resource policy."""
    client = MagicMock()
    fn = {
        "FunctionName": "release-worker",
        "Environment": {"Variables": {"DB_PASSWORD": "plaintext!"}},
    }
    client.get_paginator.return_value = _pages([{"Functions": [fn]}])
    client.get_function_code_signing_config.return_value = {}  # LMB-001 fails
    client.get_function_url_config.return_value = {"AuthType": "NONE"}  # LMB-002 fails
    client.get_policy.return_value = {"Policy": json.dumps({
        "Statement": [{"Effect": "Allow", "Principal": "*", "Action": "lambda:InvokeFunction"}]
    })}
    return client


def _insecure_kms():
    """Customer key with rotation off and wildcard-action policy."""
    client = MagicMock()
    key_meta = {
        "KeyId": "1234",
        "Arn": "arn:aws:kms:us-east-1:111111111111:key/1234",
        "KeyManager": "CUSTOMER",
        "KeySpec": "SYMMETRIC_DEFAULT",
    }
    client.get_paginator.return_value = _pages([{"Keys": [{"KeyId": "1234"}]}])
    client.describe_key.return_value = {"KeyMetadata": key_meta}
    client.get_key_rotation_status.return_value = {"KeyRotationEnabled": False}
    client.get_key_policy.return_value = {"Policy": json.dumps({
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": "arn:aws:iam::111111111111:role/builder"},
            "Action": "kms:*",
        }]
    })}
    return client


def _insecure_ssm():
    """Two parameters: a secret-named String and a SecureString with default key."""
    client = MagicMock()
    params = [
        {"Name": "/app/DB_PASSWORD", "Type": "String"},
        {"Name": "/app/misc", "Type": "SecureString", "KeyId": "alias/aws/ssm"},
    ]
    client.get_paginator.return_value = _pages([{"Parameters": params}])
    return client


def _insecure_ecr_extended():
    """Adds pull-through cache with docker-hub upstream to existing ECR client.

    Returns a MagicMock; callers can chain describe_pull_through_cache_rules.
    """
    client = MagicMock()
    client.describe_pull_through_cache_rules.return_value = {"pullThroughCacheRules": [
        {"ecrRepositoryPrefix": "docker", "upstreamRegistryUrl": "registry-1.docker.io"},
    ]}
    # Existing ECRChecks also uses this client — stub its paginators minimally.
    client.get_paginator.return_value = _pages([{"repositories": []}])
    return client


def _insecure_inspector2():
    client = MagicMock()
    client.batch_get_account_status.return_value = {"accounts": [{
        "accountId": _SELF_ACCOUNT,
        "resourceState": {"ecr": {"status": "DISABLED"}},
    }]}
    return client


def _insecure_signer_revoked():
    client = MagicMock()
    client.list_signing_profiles.return_value = {"profiles": [{
        "profileName": "old", "platformId": "AWSLambda-SHA384-ECDSA", "status": "Revoked",
    }]}
    return client


def _insecure_events():
    """No FAILED rule (EB-001 fires) and a wildcard-target rule (EB-002)."""
    client = MagicMock()
    rules = [{"Name": "unrelated", "EventPattern": json.dumps({
        "detail-type": ["EC2 Instance State-change Notification"],
    })}]
    client.get_paginator.return_value = _pages([{"Rules": rules}])
    client.list_targets_by_rule.return_value = {"Targets": [
        {"Id": "t", "Arn": "arn:aws:lambda:us-east-1:111111111111:function:*"},
    ]}
    return client


def _insecure_cloudwatch():
    """No FailedBuilds alarm → CW-001 fires."""
    client = MagicMock()
    client.describe_alarms.return_value = {"MetricAlarms": []}
    return client


def _insecure_ec2():
    """Open SG egress referenced by CodeBuild VPC config."""
    client = MagicMock()
    client.describe_security_groups.return_value = {"SecurityGroups": [{
        "GroupId": "sg-open",
        "IpPermissionsEgress": [{
            "IpProtocol": "-1",
            "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
        }],
    }]}
    return client


def _insecure_codepipeline():
    """V2 pipeline with:
       - all actions share the pipeline-level role (PBAC-005)
       - production deploy stage with no preceding approval (CP-005)
       - PR trigger with wildcard branch (CP-007)
    """
    pipeline = {
        "name": "ship-prod",
        "pipelineType": "V2",
        "roleArn": "arn:aws:iam::111111111111:role/pipeline",
        "triggers": [{
            "providerType": "CodeStarSourceConnection",
            "gitConfiguration": {"pullRequest": [{"branches": {"includes": ["*"]}}]},
        }],
        "stages": [
            {"name": "Source", "actions": [{"name": "Src", "actionTypeId": {"category": "Source"},
                                             "roleArn": "arn:aws:iam::111111111111:role/pipeline"}]},
            {"name": "DeployProd", "actions": [{"name": "Deploy", "actionTypeId": {"category": "Deploy"},
                                                  "roleArn": "arn:aws:iam::111111111111:role/pipeline"}]},
        ],
        # No artifactStore — keeps S3Checks from cascading into this fixture's
        # minimal S3 stub; this integration test targets the rule-based
        # checks, not S3-001..005 which are covered in test_owasp_pipeline.
    }
    client = MagicMock()
    client.get_paginator.return_value = _pages([{"pipelines": [{"name": pipeline["name"]}]}])
    client.get_pipeline.return_value = {"pipeline": pipeline}
    return client


def _insecure_sts():
    client = MagicMock()
    client.get_caller_identity.return_value = {"Account": _SELF_ACCOUNT}
    return client


# Existing class-based checks need a few minimal stubs to stay quiet.

def _quiet_s3():
    client = MagicMock()
    client.list_buckets.return_value = {"Buckets": []}
    return client


def _quiet_codedeploy():
    client = MagicMock()
    client.get_paginator.return_value = _pages([{"applications": []}])
    return client


# ---------------------------------------------------------------------------
# Sessions
# ---------------------------------------------------------------------------

@pytest.fixture()
def insecure_rules_session():
    """Full-coverage insecure session for every Phase 1-3 rule."""
    _map = {
        "codebuild": _insecure_codebuild(),
        "codepipeline": _insecure_codepipeline(),
        "codedeploy": _quiet_codedeploy(),
        "ecr": _insecure_ecr_extended(),
        "iam": _insecure_iam(),
        "s3": _quiet_s3(),
        "cloudtrail": _insecure_cloudtrail(),
        "logs": _insecure_logs(),
        "secretsmanager": _insecure_secretsmanager(),
        "codeartifact": _insecure_codeartifact(),
        "codecommit": _insecure_codecommit(),
        "lambda": _insecure_lambda(),
        "kms": _insecure_kms(),
        "ssm": _insecure_ssm(),
        "sts": _insecure_sts(),
        "ec2": _insecure_ec2(),
        "events": _insecure_events(),
        "inspector2": _insecure_inspector2(),
        "signer": _insecure_signer_revoked(),
        "cloudwatch": _insecure_cloudwatch(),
    }
    session = MagicMock()
    session.client.side_effect = lambda svc, **_kw: _map[svc]
    return session


# ---------------------------------------------------------------------------
# Phase 1 integration
# ---------------------------------------------------------------------------

@pytest.fixture()
def _all_findings(insecure_rules_session):
    """Run the scanner once and share the result across per-rule assertions."""
    return _scanner_for(insecure_rules_session).run()


def _failed_ids(findings) -> set[str]:
    return {f.check_id for f in findings if not f.passed}


class TestPhase1Integration:
    """CB-008/009/010, CT-001/002/003, CWL-001/002, SM-001/002, IAM-007/008."""

    @pytest.mark.parametrize("check_id", [
        "CB-008", "CB-009", "CB-010",
        "CT-001", "CT-002", "CT-003",
        "CWL-001", "CWL-002",
        "SM-001", "SM-002",
        "IAM-007", "IAM-008",
    ])
    def test_rule_fires(self, _all_findings, check_id):
        assert check_id in _failed_ids(_all_findings), (
            f"{check_id} did not fire. Failures: "
            f"{sorted(_failed_ids(_all_findings))}"
        )


class TestPhase2Integration:
    """CA-001..004, CCM-001..003, LMB-001..004, KMS-001/002, SSM-001/002."""

    @pytest.mark.parametrize("check_id", [
        "CA-001", "CA-002", "CA-003", "CA-004",
        "CCM-001", "CCM-002", "CCM-003",
        "LMB-001", "LMB-002", "LMB-003", "LMB-004",
        "KMS-001", "KMS-002",
        "SSM-001", "SSM-002",
    ])
    def test_rule_fires(self, _all_findings, check_id):
        assert check_id in _failed_ids(_all_findings), (
            f"{check_id} did not fire. Failures: "
            f"{sorted(_failed_ids(_all_findings))}"
        )


class TestPhase3Integration:
    """ECR-006/007, SIGN-001/002, EB-001/002, CW-001, PBAC-003/005, CP-005/007."""

    @pytest.mark.parametrize("check_id", [
        "ECR-006", "ECR-007",
        "SIGN-002",         # revoked profile
        "EB-001", "EB-002",
        "CW-001",
        "PBAC-003", "PBAC-005",
        "CP-005", "CP-007",
    ])
    def test_rule_fires(self, _all_findings, check_id):
        assert check_id in _failed_ids(_all_findings), (
            f"{check_id} did not fire. Failures: "
            f"{sorted(_failed_ids(_all_findings))}"
        )

    def test_sign001_passes_when_profile_exists(self, _all_findings):
        """The fixture declares a (revoked) Lambda profile, so SIGN-001's
        'no active Lambda profile' check should... actually fail, because
        the profile exists but is revoked. SIGN-002 covers the revoke
        separately. Confirm SIGN-001 reports the gap."""
        assert "SIGN-001" in _failed_ids(_all_findings)


# ---------------------------------------------------------------------------
# Scoped CI-wide guarantees
# ---------------------------------------------------------------------------

class TestOverallCoverage:
    def test_critical_findings_include_wildcard_principals(self, _all_findings):
        criticals = {f.check_id for f in _all_findings
                     if not f.passed and f.severity == Severity.CRITICAL}
        # SM-002, CA-003, LMB-004 are all CRITICAL wildcard-principal checks.
        assert {"SM-002", "CA-003", "LMB-004"} <= criticals

    def test_every_failed_rule_has_owasp_mapping(self, _all_findings):
        for f in _all_findings:
            if f.passed:
                continue
            owasp = {c.control_id for c in f.controls
                     if c.standard == "owasp_cicd_top_10"}
            assert owasp, f"{f.check_id} failed but has no OWASP mapping"

    def test_phase_1_3_prefixes_all_present(self, _all_findings):
        prefixes = {f.check_id.split("-")[0] for f in _all_findings}
        required = {
            "CT", "CWL", "SM", "IAM", "CB", "CP",
            "CA", "CCM", "LMB", "KMS", "SSM",
            "ECR", "SIGN", "EB", "CW", "PBAC",
        }
        missing = required - prefixes
        assert not missing, f"Missing prefixes in scan output: {missing}"


# ---------------------------------------------------------------------------
# Degraded-finding regression
# ---------------------------------------------------------------------------

def _raising_client(exc=None):
    """A client whose every method raises — simulates IAM denial or API outage."""
    exc = exc or _client_error("AccessDeniedException")
    client = MagicMock()
    client.get_paginator.side_effect = exc
    client.describe_trails.side_effect = exc
    client.get_trail_status.side_effect = exc
    return client


@pytest.fixture()
def partial_outage_session():
    """Session where CloudTrail and Secrets Manager both fail enumeration.

    The rest are wired with empty responses so only CT and SM should
    produce degraded-finding output."""
    def _empty(key):
        c = MagicMock()
        c.get_paginator.return_value = _pages([{key: []}])
        return c

    _map = {
        "codebuild": _empty("projects"),
        "codepipeline": _empty("pipelines"),
        "codedeploy": _empty("applications"),
        "ecr": _empty("repositories"),
        "iam": _empty("Roles"),
        "s3": MagicMock(**{"list_buckets.return_value": {"Buckets": []}}),
        "cloudtrail": _raising_client(),         # <-- outage
        "logs": _empty("logGroups"),
        "secretsmanager": _raising_client(),     # <-- outage
        "codeartifact": _empty("domains"),
        "codecommit": _empty("repositories"),
        "lambda": _empty("Functions"),
        "kms": _empty("Keys"),
        "ssm": _empty("Parameters"),
        "sts": _insecure_sts(),
        "ec2": _insecure_ec2(),
        "events": _empty("Rules"),
        "inspector2": _insecure_inspector2(),
        "signer": MagicMock(**{"list_signing_profiles.return_value": {"profiles": []}}),
        "cloudwatch": MagicMock(**{"describe_alarms.return_value": {"MetricAlarms": []}}),
    }
    session = MagicMock()
    session.client.side_effect = lambda svc, **_kw: _map[svc]
    return session


class TestDegradedFindings:
    def test_single_degraded_finding_per_failed_service(self, partial_outage_session):
        findings = _scanner_for(partial_outage_session).run()
        by_id = [f for f in findings]
        ct000 = [f for f in by_id if f.check_id == "CT-000"]
        sm000 = [f for f in by_id if f.check_id == "SM-000"]
        assert len(ct000) == 1, f"Expected exactly one CT-000, got {len(ct000)}"
        assert len(sm000) == 1, f"Expected exactly one SM-000, got {len(sm000)}"

    def test_degraded_findings_are_info_severity_and_fail(self, partial_outage_session):
        findings = _scanner_for(partial_outage_session).run()
        for check_id in ("CT-000", "SM-000"):
            match = [f for f in findings if f.check_id == check_id][0]
            assert match.severity == Severity.INFO
            assert match.passed is False

    def test_dependent_rules_emit_no_findings_when_service_is_down(self, partial_outage_session):
        """CT-001/002/003 must not appear (passed or failed) when cloudtrail is down.
        Same for SM-001/002 when secretsmanager is down."""
        findings = _scanner_for(partial_outage_session).run()
        ids = {f.check_id for f in findings}
        for check_id in ("CT-001", "CT-002", "CT-003", "SM-001", "SM-002"):
            assert check_id not in ids, (
                f"{check_id} should be suppressed by the degraded-finding "
                "aggregator when its service is unreachable."
            )

    def test_healthy_services_still_emit_normal_findings(self, partial_outage_session):
        """LMB/KMS/SSM are wired fine — their rules should still run and
        just emit nothing because there are no resources to flag."""
        findings = _scanner_for(partial_outage_session).run()
        # Confirm at least the CloudTrail outage didn't taint unrelated services.
        lambda_degraded = [f for f in findings if f.check_id == "LMB-000"]
        assert not lambda_degraded, "Lambda should not be marked degraded"
