"""Unit tests for IAM IAM-001..IAM-006 rule modules."""
from __future__ import annotations

from unittest.mock import MagicMock

from botocore.exceptions import ClientError

from pipeline_check.core.checks.aws._catalog import ResourceCatalog
from pipeline_check.core.checks.aws.base import Severity
from pipeline_check.core.checks.aws.rules import (
    iam001_admin_access as iam001,
)
from pipeline_check.core.checks.aws.rules import (
    iam002_wildcard_action as iam002,
)
from pipeline_check.core.checks.aws.rules import (
    iam003_permission_boundary as iam003,
)
from pipeline_check.core.checks.aws.rules import (
    iam004_passrole as iam004,
)
from pipeline_check.core.checks.aws.rules import (
    iam005_external_trust as iam005,
)
from pipeline_check.core.checks.aws.rules import (
    iam006_sensitive_wildcard as iam006,
)
from pipeline_check.core.checks.aws.workflows import AWSRuleChecks
from tests.aws.conftest import make_paginator


def _client_error(code="AccessDeniedException"):
    return ClientError({"Error": {"Code": code, "Message": "msg"}}, "op")


_CB_TRUST = {
    "Statement": [{
        "Effect": "Allow",
        "Principal": {"Service": "codebuild.amazonaws.com"},
        "Action": "sts:AssumeRole",
    }]
}

_ADMIN_ARN = "arn:aws:iam::aws:policy/AdministratorAccess"


def _role(name="my-role", trust=None, boundary_arn=None):
    r = {
        "RoleName": name,
        "RoleId": "AROA123",
        "Arn": f"arn:aws:iam::123:role/{name}",
        "AssumeRolePolicyDocument": trust or _CB_TRUST,
        "Path": "/",
    }
    if boundary_arn:
        r["PermissionsBoundary"] = {
            "PermissionsBoundaryArn": boundary_arn,
            "PermissionsBoundaryType": "Policy",
        }
    return r


def _catalog(
    roles,
    attached_policies=None,
    inline_names=None,
    inline_docs=None,
    attached_error=False,
    inline_error=False,
):
    session = MagicMock()
    client = MagicMock()
    session.client.return_value = client

    paginator = make_paginator([{"Roles": roles}])
    client.get_paginator.return_value = paginator

    if attached_error:
        client.list_attached_role_policies.side_effect = _client_error()
    else:
        client.list_attached_role_policies.return_value = {
            "AttachedPolicies": [
                {"PolicyName": p, "PolicyArn": p} for p in (attached_policies or [])
            ]
        }
    if inline_error:
        client.list_role_policies.side_effect = _client_error()
    else:
        client.list_role_policies.return_value = {
            "PolicyNames": inline_names or []
        }
    if inline_docs:
        def get_role_policy(RoleName, PolicyName):
            return {"PolicyDocument": inline_docs.get(PolicyName, {})}
        client.get_role_policy.side_effect = get_role_policy

    return ResourceCatalog(session)


class TestIAM001AdminAccess:
    def test_admin_access_attached_fails(self):
        cat = _catalog([_role()], attached_policies=[_ADMIN_ARN])
        f = iam001.check(cat)[0]
        assert not f.passed
        assert f.severity == Severity.CRITICAL

    def test_no_admin_access_passes(self):
        cat = _catalog([_role()], attached_policies=["arn:aws:iam::aws:policy/ReadOnlyAccess"])
        assert iam001.check(cat)[0].passed

    def test_no_attached_policies_passes(self):
        assert iam001.check(_catalog([_role()]))[0].passed


class TestIAM002WildcardInline:
    def test_wildcard_action_fails(self):
        doc = {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
        cat = _catalog([_role()], inline_names=["MyPolicy"], inline_docs={"MyPolicy": doc})
        f = iam002.check(cat)[0]
        assert not f.passed
        assert f.severity == Severity.HIGH

    def test_specific_action_passes(self):
        doc = {"Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]}
        cat = _catalog([_role()], inline_names=["MyPolicy"], inline_docs={"MyPolicy": doc})
        assert iam002.check(cat)[0].passed

    def test_deny_wildcard_does_not_fail(self):
        doc = {"Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}]}
        cat = _catalog([_role()], inline_names=["MyPolicy"], inline_docs={"MyPolicy": doc})
        assert iam002.check(cat)[0].passed

    def test_no_inline_policies_passes(self):
        assert iam002.check(_catalog([_role()]))[0].passed


class TestIAM003PermissionBoundary:
    def test_no_boundary_fails(self):
        f = iam003.check(_catalog([_role()]))[0]
        assert not f.passed
        assert f.severity == Severity.MEDIUM

    def test_with_boundary_passes(self):
        cat = _catalog([_role(boundary_arn="arn:aws:iam::123:policy/Boundary")])
        assert iam003.check(cat)[0].passed


class TestIAM004PassRoleWildcard:
    def test_passrole_wildcard_fails(self):
        doc = {"Statement": [{"Effect": "Allow", "Action": "iam:PassRole", "Resource": "*"}]}
        cat = _catalog([_role()], inline_names=["p"], inline_docs={"p": doc})
        f = iam004.check(cat)[0]
        assert not f.passed
        assert f.severity == Severity.HIGH

    def test_passrole_scoped_passes(self):
        doc = {"Statement": [{"Effect": "Allow", "Action": "iam:PassRole",
                              "Resource": "arn:aws:iam::123:role/target"}]}
        cat = _catalog([_role()], inline_names=["p"], inline_docs={"p": doc})
        assert iam004.check(cat)[0].passed

    def test_iam_wildcard_star_resource_fails(self):
        doc = {"Statement": [{"Effect": "Allow", "Action": "iam:*", "Resource": "*"}]}
        cat = _catalog([_role()], inline_names=["p"], inline_docs={"p": doc})
        assert not iam004.check(cat)[0].passed


class TestIAM005ExternalTrust:
    def test_external_aws_principal_without_externalid_fails(self):
        trust = {"Statement": [
            {"Effect": "Allow", "Principal": {"Service": "codebuild.amazonaws.com"},
             "Action": "sts:AssumeRole"},
            {"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::999:root"},
             "Action": "sts:AssumeRole"},
        ]}
        f = iam005.check(_catalog([_role(trust=trust)]))[0]
        assert not f.passed
        assert f.severity == Severity.HIGH

    def test_external_aws_principal_with_externalid_passes(self):
        trust = {"Statement": [
            {"Effect": "Allow", "Principal": {"Service": "codebuild.amazonaws.com"},
             "Action": "sts:AssumeRole"},
            {"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::999:root"},
             "Action": "sts:AssumeRole",
             "Condition": {"StringEquals": {"sts:ExternalId": "shared-secret"}}},
        ]}
        assert iam005.check(_catalog([_role(trust=trust)]))[0].passed

    def test_service_only_trust_passes(self):
        assert iam005.check(_catalog([_role()]))[0].passed


class TestIAM006SensitiveWildcardResource:
    def test_sensitive_action_wildcard_resource_fails(self):
        doc = {"Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]}
        cat = _catalog([_role()], inline_names=["p"], inline_docs={"p": doc})
        f = iam006.check(cat)[0]
        assert not f.passed
        assert f.severity == Severity.MEDIUM

    def test_scoped_resource_passes(self):
        doc = {"Statement": [{"Effect": "Allow", "Action": "kms:Decrypt",
                              "Resource": "arn:aws:kms:us-east-1:123:key/abc"}]}
        cat = _catalog([_role()], inline_names=["p"], inline_docs={"p": doc})
        assert iam006.check(cat)[0].passed

    def test_wildcard_action_skipped(self):
        doc = {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
        cat = _catalog([_role()], inline_names=["p"], inline_docs={"p": doc})
        assert iam006.check(cat)[0].passed

    def test_non_sensitive_action_passes(self):
        doc = {"Statement": [{"Effect": "Allow", "Action": "cloudwatch:PutMetricData",
                              "Resource": "*"}]}
        cat = _catalog([_role()], inline_names=["p"], inline_docs={"p": doc})
        assert iam006.check(cat)[0].passed


class TestNoCicdRoles:
    def test_non_cicd_roles_are_skipped(self):
        non_cicd_trust = {
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"Service": "ec2.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }]
        }
        cat = _catalog([_role(trust=non_cicd_trust)])
        for rule in (iam001, iam002, iam003, iam004, iam005, iam006):
            assert rule.check(cat) == []


class TestErrorHandling:
    def test_list_roles_access_denied_yields_single_iam000(self):
        session = MagicMock()
        def _pick(svc, **_):
            if svc == "iam":
                c = MagicMock()
                p = MagicMock()
                p.paginate.side_effect = _client_error()
                c.get_paginator.return_value = p
                return c
            c = MagicMock()
            empty = MagicMock()
            empty.paginate.return_value = iter([])
            c.get_paginator.return_value = empty
            return c
        session.client.side_effect = _pick

        findings = AWSRuleChecks(session).run()
        iam_000 = [f for f in findings if f.check_id == "IAM-000"]
        assert len(iam_000) == 1
        assert not iam_000[0].passed
        assert not any(
            f.check_id.startswith("IAM-") and f.check_id != "IAM-000"
            for f in findings
        )

    def test_list_attached_policies_error_fails_iam001(self):
        cat = _catalog([_role()], attached_error=True, inline_names=[])
        assert not iam001.check(cat)[0].passed

    def test_list_role_policies_error_surfaces_in_iam002(self):
        cat = _catalog([_role()], attached_policies=[], inline_error=True)
        assert not iam002.check(cat)[0].passed

    def test_multiple_roles_produce_findings_for_each(self):
        cat = _catalog([_role("role-a"), _role("role-b")])
        resources = {f.resource for f in iam001.check(cat)}
        assert "role-a" in resources
        assert "role-b" in resources


class TestCustomerManagedPolicyWalk:
    """Exercise the customer-managed attachment branch of iam_role_policy_docs."""

    def _catalog(self, attached_policy_arn, policy_doc, get_policy_error=False):
        session = MagicMock()
        client = MagicMock()
        session.client.return_value = client
        paginator = make_paginator([{"Roles": [_role()]}])
        client.get_paginator.return_value = paginator
        client.list_attached_role_policies.return_value = {
            "AttachedPolicies": [{"PolicyName": "p", "PolicyArn": attached_policy_arn}]
        }
        client.list_role_policies.return_value = {"PolicyNames": []}
        if get_policy_error:
            client.get_policy.side_effect = _client_error()
        else:
            client.get_policy.return_value = {"Policy": {"DefaultVersionId": "v1"}}
        client.get_policy_version.return_value = {
            "PolicyVersion": {"Document": policy_doc}
        }
        return ResourceCatalog(session)

    def test_customer_managed_wildcard_detected(self):
        doc = {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
        cat = self._catalog("arn:aws:iam::123:policy/custom", doc)
        assert not iam002.check(cat)[0].passed

    def test_aws_managed_policy_skipped(self):
        doc = {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
        cat = self._catalog("arn:aws:iam::aws:policy/ReadOnlyAccess", doc)
        assert iam002.check(cat)[0].passed

    def test_get_policy_error_skipped(self):
        cat = self._catalog("arn:aws:iam::123:policy/c", {}, get_policy_error=True)
        # No docs collected \u2192 IAM-002 passes (no error propagated since inline succeeded).
        assert iam002.check(cat)[0].passed
