"""Unit tests for IAM checks."""

from unittest.mock import MagicMock

from pipeline_check.core.checks.base import Severity
from pipeline_check.core.checks.iam import IAMChecks
from tests.conftest import make_paginator

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
        r["PermissionsBoundary"] = {"PermissionsBoundaryArn": boundary_arn, "PermissionsBoundaryType": "Policy"}
    return r


def _make_check(roles, attached_policies=None, inline_names=None, inline_docs=None):
    session = MagicMock()
    client = MagicMock()
    session.client.return_value = client

    paginator = make_paginator([{"Roles": roles}])
    client.get_paginator.return_value = paginator

    client.list_attached_role_policies.return_value = {
        "AttachedPolicies": [{"PolicyName": p, "PolicyArn": p} for p in (attached_policies or [])]
    }
    client.list_role_policies.return_value = {
        "PolicyNames": inline_names or []
    }
    if inline_docs:
        def get_role_policy(RoleName, PolicyName):
            return {"PolicyDocument": inline_docs.get(PolicyName, {})}
        client.get_role_policy.side_effect = get_role_policy

    return IAMChecks(session)


class TestIAM001AdminAccess:
    def test_admin_access_attached_fails(self):
        findings = _make_check([_role()], attached_policies=[_ADMIN_ARN]).run()
        iam001 = next(f for f in findings if f.check_id == "IAM-001")
        assert not iam001.passed
        assert iam001.severity == Severity.CRITICAL

    def test_no_admin_access_passes(self):
        findings = _make_check([_role()], attached_policies=["arn:aws:iam::aws:policy/ReadOnlyAccess"]).run()
        assert next(f for f in findings if f.check_id == "IAM-001").passed

    def test_no_attached_policies_passes(self):
        findings = _make_check([_role()]).run()
        assert next(f for f in findings if f.check_id == "IAM-001").passed


class TestIAM002WildcardInline:
    def test_wildcard_action_fails(self):
        doc = {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
        findings = _make_check([_role()], inline_names=["MyPolicy"], inline_docs={"MyPolicy": doc}).run()
        iam002 = next(f for f in findings if f.check_id == "IAM-002")
        assert not iam002.passed
        assert iam002.severity == Severity.HIGH

    def test_specific_action_passes(self):
        doc = {"Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]}
        findings = _make_check([_role()], inline_names=["MyPolicy"], inline_docs={"MyPolicy": doc}).run()
        assert next(f for f in findings if f.check_id == "IAM-002").passed

    def test_deny_wildcard_does_not_fail(self):
        doc = {"Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}]}
        findings = _make_check([_role()], inline_names=["MyPolicy"], inline_docs={"MyPolicy": doc}).run()
        assert next(f for f in findings if f.check_id == "IAM-002").passed

    def test_no_inline_policies_passes(self):
        findings = _make_check([_role()]).run()
        assert next(f for f in findings if f.check_id == "IAM-002").passed


class TestIAM003PermissionBoundary:
    def test_no_boundary_fails(self):
        findings = _make_check([_role()]).run()
        iam003 = next(f for f in findings if f.check_id == "IAM-003")
        assert not iam003.passed
        assert iam003.severity == Severity.MEDIUM

    def test_with_boundary_passes(self):
        findings = _make_check([_role(boundary_arn="arn:aws:iam::123:policy/Boundary")]).run()
        assert next(f for f in findings if f.check_id == "IAM-003").passed


class TestNoCicdRoles:
    def test_non_cicd_roles_are_skipped(self):
        non_cicd_trust = {
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"Service": "ec2.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }]
        }
        findings = _make_check([_role(trust=non_cicd_trust)]).run()
        assert findings == []
