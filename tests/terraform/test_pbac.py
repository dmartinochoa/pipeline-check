"""Terraform PBAC tests."""
from __future__ import annotations

from pipeline_check.core.checks.terraform.base import TerraformContext
from pipeline_check.core.checks.terraform.pbac import PBACChecks


def _plan(resources):
    return {"format_version": "1.2", "planned_values": {"root_module": {
        "resources": resources, "child_modules": []}}}


def _project(name, service_role="", vpc=None):
    vals = {"name": name, "service_role": service_role}
    if vpc is not None:
        vals["vpc_config"] = [vpc]
    return {
        "address": f"aws_codebuild_project.{name}",
        "mode": "managed", "type": "aws_codebuild_project", "name": name,
        "values": vals,
    }


def _run(plan):
    return PBACChecks(TerraformContext(plan)).run()


def _by(findings, cid, resource):
    return next(f for f in findings if f.check_id == cid and f.resource == resource)


class TestPBAC001:
    def test_no_vpc_fails(self):
        plan = _plan([_project("p", service_role="arn:r")])
        assert not _by(_run(plan), "PBAC-001", "p").passed

    def test_vpc_configured_passes(self):
        plan = _plan([_project("p", service_role="arn:r", vpc={
            "vpc_id": "vpc-1", "subnets": ["s1"], "security_group_ids": ["sg-1"],
        })])
        assert _by(_run(plan), "PBAC-001", "p").passed

    def test_incomplete_vpc_fails(self):
        plan = _plan([_project("p", service_role="arn:r",
                               vpc={"vpc_id": "vpc-1", "subnets": [], "security_group_ids": []})])
        assert not _by(_run(plan), "PBAC-001", "p").passed


class TestPBAC002:
    def test_shared_role_fails(self):
        plan = _plan([
            _project("a", service_role="arn:shared"),
            _project("b", service_role="arn:shared"),
        ])
        findings = _run(plan)
        assert not _by(findings, "PBAC-002", "a").passed
        assert not _by(findings, "PBAC-002", "b").passed

    def test_dedicated_roles_pass(self):
        plan = _plan([
            _project("a", service_role="arn:a"),
            _project("b", service_role="arn:b"),
        ])
        findings = _run(plan)
        assert _by(findings, "PBAC-002", "a").passed
        assert _by(findings, "PBAC-002", "b").passed
