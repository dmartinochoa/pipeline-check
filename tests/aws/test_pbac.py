"""Unit tests for PBAC-001 and PBAC-002 rule modules."""
from __future__ import annotations

from unittest.mock import MagicMock

from botocore.exceptions import ClientError

from pipeline_check.core.checks.aws._catalog import ResourceCatalog
from pipeline_check.core.checks.aws.base import Severity
from pipeline_check.core.checks.aws.rules import (
    pbac001_vpc_config as pbac001,
)
from pipeline_check.core.checks.aws.rules import (
    pbac002_shared_service_role as pbac002,
)
from pipeline_check.core.checks.aws.workflows import AWSRuleChecks
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


def _project(name="my-build", service_role=_ROLE_ARN, vpc_config=None):
    p = {"name": name, "serviceRole": service_role}
    if vpc_config is not None:
        p["vpcConfig"] = vpc_config
    return p


def _catalog(projects: list[dict]):
    session = MagicMock()
    client = MagicMock()
    session.client.return_value = client
    names = [p["name"] for p in projects]
    paginator = make_paginator([{"projects": names}])
    client.get_paginator.return_value = paginator
    client.batch_get_projects.return_value = {"projects": projects}
    return ResourceCatalog(session)


class TestPBAC001VpcConfig:
    def test_no_vpc_fails(self):
        f = pbac001.check(_catalog([_project()]))[0]
        assert not f.passed
        assert f.severity == Severity.HIGH

    def test_with_vpc_passes(self):
        assert pbac001.check(_catalog([_project(vpc_config=_VPC_CFG)]))[0].passed

    def test_empty_vpc_config_fails(self):
        assert not pbac001.check(_catalog([_project(vpc_config={})]))[0].passed

    def test_partial_vpc_config_fails(self):
        partial = {"vpcId": "vpc-abc", "subnets": [], "securityGroupIds": []}
        assert not pbac001.check(_catalog([_project(vpc_config=partial)]))[0].passed

    def test_vpc_id_in_description_when_passing(self):
        f = pbac001.check(_catalog([_project(vpc_config=_VPC_CFG)]))[0]
        assert "vpc-abc123" in f.description

    def test_each_project_gets_own_finding(self):
        projects = [
            _project("build-a", vpc_config=_VPC_CFG),
            _project("build-b"),
        ]
        findings = pbac001.check(_catalog(projects))
        assert len(findings) == 2
        passed = {f.resource: f.passed for f in findings}
        assert passed["build-a"] is True
        assert passed["build-b"] is False

    def test_owasp_tag(self):
        from pipeline_check.core import standards
        refs = standards.resolve_for_check("PBAC-001")
        assert any(c.control_id == "CICD-SEC-5" for c in refs)


class TestPBAC002SharedServiceRole:
    def test_shared_role_fails(self):
        projects = [
            _project("build-a", service_role=_ROLE_ARN),
            _project("build-b", service_role=_ROLE_ARN),
        ]
        findings = pbac002.check(_catalog(projects))
        assert all(not f.passed for f in findings)

    def test_dedicated_roles_pass(self):
        projects = [
            _project("build-a", service_role=_ROLE_ARN),
            _project("build-b", service_role=_ROLE_ARN_2),
        ]
        findings = pbac002.check(_catalog(projects))
        assert all(f.passed for f in findings)

    def test_single_project_passes(self):
        assert pbac002.check(_catalog([_project()]))[0].passed

    def test_shared_role_description_names_other_projects(self):
        projects = [
            _project("build-a", service_role=_ROLE_ARN),
            _project("build-b", service_role=_ROLE_ARN),
        ]
        findings = pbac002.check(_catalog(projects))
        finding_a = next(f for f in findings if f.resource == "build-a")
        assert "build-b" in finding_a.description

    def test_three_projects_one_shared(self):
        projects = [
            _project("build-a", service_role=_ROLE_ARN),
            _project("build-b", service_role=_ROLE_ARN),
            _project("build-c", service_role=_ROLE_ARN_2),
        ]
        findings = pbac002.check(_catalog(projects))
        passed = {f.resource: f.passed for f in findings}
        assert passed["build-a"] is False
        assert passed["build-b"] is False
        assert passed["build-c"] is True

    def test_project_without_service_role_skipped(self):
        project = {"name": "no-role-project"}  # no serviceRole key
        assert pbac002.check(_catalog([project])) == []

    def test_owasp_tag(self):
        from pipeline_check.core import standards
        refs = standards.resolve_for_check("PBAC-002")
        assert any(c.control_id == "CICD-SEC-5" for c in refs)


class TestErrorHandling:
    def test_list_projects_access_denied_yields_single_degraded(self):
        """PBAC rules route through the ``codebuild`` service prefix; a
        CodeBuild enumeration failure surfaces as ``CB-000`` and suppresses
        every CB/PBAC rule — verified end-to-end via the orchestrator."""
        session = MagicMock()
        def _pick(svc, **_):
            if svc == "codebuild":
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
        cb_000 = [f for f in findings if f.check_id == "CB-000"]
        assert len(cb_000) == 1
        # PBAC rules were suppressed along with CB rules.
        assert not any(f.check_id.startswith("PBAC-") for f in findings)

    def test_no_projects_returns_empty(self):
        session = MagicMock()
        client = MagicMock()
        session.client.return_value = client
        paginator = make_paginator([{"projects": []}])
        client.get_paginator.return_value = paginator
        cat = ResourceCatalog(session)
        assert pbac001.check(cat) == []
        assert pbac002.check(cat) == []
