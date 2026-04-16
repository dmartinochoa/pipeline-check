"""Unit tests for PBAC checks."""

from unittest.mock import MagicMock

from botocore.exceptions import ClientError

from pipeline_check.core.checks.aws.base import Severity
from pipeline_check.core.checks.aws.pbac import PBACChecks
from tests.aws.conftest import make_paginator

_ROLE_ARN = "arn:aws:iam::123456789:role/my-build-role"
_ROLE_ARN_2 = "arn:aws:iam::123456789:role/other-build-role"

_VPC_CFG = {
    "vpcId": "vpc-abc123",
    "subnets": ["subnet-1"],
    "securityGroupIds": ["sg-1"],
}


def _client_error(code="AccessDeniedException"):
    return ClientError({"Error": {"Code": code, "Message": "msg"}}, "op")


def _make_project(
    name="my-build",
    service_role=_ROLE_ARN,
    vpc_config=None,
):
    p = {"name": name, "serviceRole": service_role}
    if vpc_config is not None:
        p["vpcConfig"] = vpc_config
    return p


def _make_check(projects: list[dict]) -> PBACChecks:
    session = MagicMock()
    client = MagicMock()
    session.client.return_value = client

    names = [p["name"] for p in projects]
    paginator = make_paginator([{"projects": names}])
    client.get_paginator.return_value = paginator
    client.batch_get_projects.return_value = {"projects": projects}

    return PBACChecks(session)


# ---------------------------------------------------------------------------
# PBAC-001: VPC configuration
# ---------------------------------------------------------------------------

class TestPBAC001VpcConfig:
    def test_no_vpc_fails(self):
        findings = _make_check([_make_project()]).run()
        f = next(f for f in findings if f.check_id == "PBAC-001")
        assert not f.passed
        assert f.severity == Severity.HIGH

    def test_with_vpc_passes(self):
        findings = _make_check([_make_project(vpc_config=_VPC_CFG)]).run()
        f = next(f for f in findings if f.check_id == "PBAC-001")
        assert f.passed

    def test_empty_vpc_config_fails(self):
        findings = _make_check([_make_project(vpc_config={})]).run()
        f = next(f for f in findings if f.check_id == "PBAC-001")
        assert not f.passed

    def test_partial_vpc_config_fails(self):
        """A vpcConfig with vpcId but no subnets/security groups is not real segmentation."""
        partial = {"vpcId": "vpc-abc", "subnets": [], "securityGroupIds": []}
        findings = _make_check([_make_project(vpc_config=partial)]).run()
        f = next(f for f in findings if f.check_id == "PBAC-001")
        assert not f.passed

    def test_vpc_id_in_description_when_passing(self):
        findings = _make_check([_make_project(vpc_config=_VPC_CFG)]).run()
        f = next(f for f in findings if f.check_id == "PBAC-001")
        assert "vpc-abc123" in f.description

    def test_each_project_gets_own_finding(self):
        projects = [
            _make_project("build-a", vpc_config=_VPC_CFG),
            _make_project("build-b"),  # no vpc
        ]
        findings = _make_check(projects).run()
        pbac001 = [f for f in findings if f.check_id == "PBAC-001"]
        assert len(pbac001) == 2
        passed = {f.resource: f.passed for f in pbac001}
        assert passed["build-a"] is True
        assert passed["build-b"] is False

    def test_owasp_tag(self):
        findings = _make_check([_make_project()]).run()
        f = next(f for f in findings if f.check_id == "PBAC-001")
        # PBACChecks itself no longer sets controls — that happens in Scanner.
        # Verify the standards registry maps PBAC-001 to CICD-SEC-5.
        from pipeline_check.core import standards
        refs = standards.resolve_for_check("PBAC-001")
        assert any(c.control_id == "CICD-SEC-5" for c in refs)
        assert f.check_id == "PBAC-001"


# ---------------------------------------------------------------------------
# PBAC-002: shared service role
# ---------------------------------------------------------------------------

class TestPBAC002SharedServiceRole:
    def test_shared_role_fails(self):
        projects = [
            _make_project("build-a", service_role=_ROLE_ARN),
            _make_project("build-b", service_role=_ROLE_ARN),
        ]
        findings = _make_check(projects).run()
        pbac002 = [f for f in findings if f.check_id == "PBAC-002"]
        assert all(not f.passed for f in pbac002)

    def test_dedicated_roles_pass(self):
        projects = [
            _make_project("build-a", service_role=_ROLE_ARN),
            _make_project("build-b", service_role=_ROLE_ARN_2),
        ]
        findings = _make_check(projects).run()
        pbac002 = [f for f in findings if f.check_id == "PBAC-002"]
        assert all(f.passed for f in pbac002)

    def test_single_project_passes(self):
        findings = _make_check([_make_project()]).run()
        f = next(f for f in findings if f.check_id == "PBAC-002")
        assert f.passed

    def test_shared_role_description_names_other_projects(self):
        projects = [
            _make_project("build-a", service_role=_ROLE_ARN),
            _make_project("build-b", service_role=_ROLE_ARN),
        ]
        findings = _make_check(projects).run()
        finding_a = next(f for f in findings if f.check_id == "PBAC-002" and f.resource == "build-a")
        assert "build-b" in finding_a.description

    def test_three_projects_one_shared(self):
        """Two projects share a role; a third has its own. Only the first two fail."""
        projects = [
            _make_project("build-a", service_role=_ROLE_ARN),
            _make_project("build-b", service_role=_ROLE_ARN),
            _make_project("build-c", service_role=_ROLE_ARN_2),
        ]
        findings = _make_check(projects).run()
        pbac002 = {f.resource: f.passed for f in findings if f.check_id == "PBAC-002"}
        assert pbac002["build-a"] is False
        assert pbac002["build-b"] is False
        assert pbac002["build-c"] is True

    def test_project_without_service_role_skipped(self):
        project = {"name": "no-role-project"}  # no serviceRole key
        findings = _make_check([project]).run()
        pbac002 = [f for f in findings if f.check_id == "PBAC-002"]
        assert pbac002 == []

    def test_owasp_tag(self):
        from pipeline_check.core import standards
        refs = standards.resolve_for_check("PBAC-002")
        assert any(c.control_id == "CICD-SEC-5" for c in refs)


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------

class TestErrorHandling:
    def test_list_projects_access_denied_returns_pbac000(self):
        session = MagicMock()
        client = MagicMock()
        session.client.return_value = client
        paginator = MagicMock()
        paginator.paginate.side_effect = _client_error()
        client.get_paginator.return_value = paginator

        findings = PBACChecks(session).run()
        assert len(findings) == 1
        assert findings[0].check_id == "PBAC-000"
        assert not findings[0].passed

    def test_no_projects_returns_empty(self):
        session = MagicMock()
        client = MagicMock()
        session.client.return_value = client
        paginator = make_paginator([{"projects": []}])
        client.get_paginator.return_value = paginator

        findings = PBACChecks(session).run()
        assert findings == []

    def test_batch_get_error_skips_batch(self):
        session = MagicMock()
        client = MagicMock()
        session.client.return_value = client
        paginator = make_paginator([{"projects": ["my-build"]}])
        client.get_paginator.return_value = paginator
        client.batch_get_projects.side_effect = _client_error()

        findings = PBACChecks(session).run()
        assert findings == []
