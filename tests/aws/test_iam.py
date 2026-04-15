"""Unit tests for IAM checks."""

from unittest.mock import MagicMock

from botocore.exceptions import ClientError

from pipeline_check.core.checks.aws.base import Severity
from pipeline_check.core.checks.aws.iam import IAMChecks
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


class TestIAM004PassRoleWildcard:
    def test_passrole_wildcard_fails(self):
        doc = {"Statement": [{"Effect": "Allow", "Action": "iam:PassRole", "Resource": "*"}]}
        findings = _make_check([_role()], inline_names=["p"], inline_docs={"p": doc}).run()
        f = next(x for x in findings if x.check_id == "IAM-004")
        assert not f.passed
        assert f.severity == Severity.HIGH

    def test_passrole_scoped_passes(self):
        doc = {"Statement": [{"Effect": "Allow", "Action": "iam:PassRole",
                              "Resource": "arn:aws:iam::123:role/target"}]}
        findings = _make_check([_role()], inline_names=["p"], inline_docs={"p": doc}).run()
        assert next(x for x in findings if x.check_id == "IAM-004").passed

    def test_iam_wildcard_star_resource_fails(self):
        doc = {"Statement": [{"Effect": "Allow", "Action": "iam:*", "Resource": "*"}]}
        findings = _make_check([_role()], inline_names=["p"], inline_docs={"p": doc}).run()
        assert not next(x for x in findings if x.check_id == "IAM-004").passed


class TestIAM005ExternalTrust:
    def test_external_aws_principal_without_externalid_fails(self):
        trust = {"Statement": [
            {"Effect": "Allow", "Principal": {"Service": "codebuild.amazonaws.com"},
             "Action": "sts:AssumeRole"},
            {"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::999:root"},
             "Action": "sts:AssumeRole"},
        ]}
        findings = _make_check([_role(trust=trust)]).run()
        f = next(x for x in findings if x.check_id == "IAM-005")
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
        findings = _make_check([_role(trust=trust)]).run()
        assert next(x for x in findings if x.check_id == "IAM-005").passed

    def test_service_only_trust_passes(self):
        findings = _make_check([_role()]).run()
        assert next(x for x in findings if x.check_id == "IAM-005").passed


class TestIAM006SensitiveWildcardResource:
    def test_sensitive_action_wildcard_resource_fails(self):
        doc = {"Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]}
        findings = _make_check([_role()], inline_names=["p"], inline_docs={"p": doc}).run()
        f = next(x for x in findings if x.check_id == "IAM-006")
        assert not f.passed
        assert f.severity == Severity.MEDIUM

    def test_scoped_resource_passes(self):
        doc = {"Statement": [{"Effect": "Allow", "Action": "kms:Decrypt",
                              "Resource": "arn:aws:kms:us-east-1:123:key/abc"}]}
        findings = _make_check([_role()], inline_names=["p"], inline_docs={"p": doc}).run()
        assert next(x for x in findings if x.check_id == "IAM-006").passed

    def test_wildcard_action_skipped(self):
        # Action:"*" is IAM-002's domain; IAM-006 shouldn't double-report.
        doc = {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
        findings = _make_check([_role()], inline_names=["p"], inline_docs={"p": doc}).run()
        assert next(x for x in findings if x.check_id == "IAM-006").passed

    def test_non_sensitive_action_passes(self):
        doc = {"Statement": [{"Effect": "Allow", "Action": "cloudwatch:PutMetricData",
                              "Resource": "*"}]}
        findings = _make_check([_role()], inline_names=["p"], inline_docs={"p": doc}).run()
        assert next(x for x in findings if x.check_id == "IAM-006").passed


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


class TestErrorHandling:
    def test_list_roles_access_denied_returns_iam000(self):
        session = MagicMock()
        client = MagicMock()
        session.client.return_value = client
        paginator = MagicMock()
        paginator.paginate.side_effect = _client_error()
        client.get_paginator.return_value = paginator

        findings = IAMChecks(session).run()
        assert len(findings) == 1
        assert findings[0].check_id == "IAM-000"
        assert not findings[0].passed

    def test_list_attached_policies_error_fails_iam001(self):
        session = MagicMock()
        client = MagicMock()
        session.client.return_value = client
        paginator = make_paginator([{"Roles": [_role()]}])
        client.get_paginator.return_value = paginator
        client.list_attached_role_policies.side_effect = _client_error()
        client.list_role_policies.return_value = {"PolicyNames": []}

        findings = IAMChecks(session).run()
        iam001 = next(f for f in findings if f.check_id == "IAM-001")
        assert not iam001.passed

    def test_list_role_policies_error_fails_iam002(self):
        session = MagicMock()
        client = MagicMock()
        session.client.return_value = client
        paginator = make_paginator([{"Roles": [_role()]}])
        client.get_paginator.return_value = paginator
        client.list_attached_role_policies.return_value = {"AttachedPolicies": []}
        client.list_role_policies.side_effect = _client_error()

        findings = IAMChecks(session).run()
        iam002 = next(f for f in findings if f.check_id == "IAM-002")
        assert not iam002.passed

    def test_multiple_roles_produce_findings_for_each(self):
        findings = _make_check([_role("role-a"), _role("role-b")]).run()
        resources = {f.resource for f in findings}
        assert "role-a" in resources
        assert "role-b" in resources


class TestCustomerManagedPolicyWalk:
    """Exercise `_collect_policy_docs` customer-managed attachment branch."""

    def _base_client(self, attached_policy_arn, policy_doc):
        session = MagicMock()
        client = MagicMock()
        session.client.return_value = client
        paginator = make_paginator([{"Roles": [_role()]}])
        client.get_paginator.return_value = paginator
        client.list_attached_role_policies.return_value = {
            "AttachedPolicies": [{"PolicyName": "p", "PolicyArn": attached_policy_arn}]
        }
        client.list_role_policies.return_value = {"PolicyNames": []}
        client.get_policy.return_value = {"Policy": {"DefaultVersionId": "v1"}}
        client.get_policy_version.return_value = {
            "PolicyVersion": {"Document": policy_doc}
        }
        return session, client

    def test_customer_managed_wildcard_detected(self):
        doc = {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
        session, _ = self._base_client("arn:aws:iam::123:policy/custom", doc)
        findings = IAMChecks(session).run()
        assert not next(f for f in findings if f.check_id == "IAM-002").passed

    def test_aws_managed_policy_skipped(self):
        # AWS-managed ARNs should not be fetched; check passes.
        doc = {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
        session, client = self._base_client("arn:aws:iam::aws:policy/ReadOnlyAccess", doc)
        findings = IAMChecks(session).run()
        assert next(f for f in findings if f.check_id == "IAM-002").passed
        client.get_policy.assert_not_called()

    def test_get_policy_error_skipped(self):
        session, client = self._base_client("arn:aws:iam::123:policy/c", {})
        client.get_policy.side_effect = _client_error()
        findings = IAMChecks(session).run()
        # No docs collected → IAM-002 passes (no error propagated since inline succeeded).
        assert next(f for f in findings if f.check_id == "IAM-002").passed

    def test_list_attached_policies_error_surfaces_in_iam002(self):
        session = MagicMock()
        client = MagicMock()
        session.client.return_value = client
        paginator = make_paginator([{"Roles": [_role()]}])
        client.get_paginator.return_value = paginator
        client.list_role_policies.return_value = {"PolicyNames": []}
        # Collection walk (in run()) happens before _iam001's own call; first
        # invocation errors, second succeeds so IAM-001 still produces a finding.
        client.list_attached_role_policies.side_effect = [
            _client_error(),
            {"AttachedPolicies": []},
        ]
        findings = IAMChecks(session).run()
        assert not next(f for f in findings if f.check_id == "IAM-002").passed
