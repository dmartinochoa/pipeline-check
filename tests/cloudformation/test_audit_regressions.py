"""Regression tests from the rule audit (CloudFormation FP fixes).

Each test pins a false positive the audit found: a documented-safe
CloudFormation idiom that the check used to flag. Grouped here so the
audit's CloudFormation coverage is auditable in one place.
"""
from __future__ import annotations

from pipeline_check.core.checks.cloudformation import phase4
from pipeline_check.core.checks.cloudformation.services import (
    ServiceChecks,
    _principal_is_only_account_root,
)

from .conftest import make_context, r


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
