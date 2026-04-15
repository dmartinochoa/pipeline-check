"""Terraform CD-001/002/003 tests."""
from __future__ import annotations

from pipeline_check.core.checks.terraform.base import TerraformContext
from pipeline_check.core.checks.terraform.codedeploy import CodeDeployChecks


def _plan(resources):
    return {"format_version": "1.2", "planned_values": {"root_module": {
        "resources": resources, "child_modules": []}}}


def _dg(name: str, values: dict) -> dict:
    return {
        "address": f"aws_codedeploy_deployment_group.{name}",
        "mode": "managed",
        "type": "aws_codedeploy_deployment_group",
        "name": name,
        "values": values,
    }


def _run(plan):
    return CodeDeployChecks(TerraformContext(plan)).run()


def _by(findings, cid):
    return next(f for f in findings if f.check_id == cid)


class TestCD001:
    def test_no_rollback_fails(self):
        plan = _plan([_dg("g", {
            "app_name": "app", "deployment_group_name": "g",
            "deployment_config_name": "CodeDeployDefault.OneAtATime",
        })])
        assert not _by(_run(plan), "CD-001").passed

    def test_rollback_enabled_passes(self):
        plan = _plan([_dg("g", {
            "app_name": "app", "deployment_group_name": "g",
            "deployment_config_name": "CodeDeployDefault.OneAtATime",
            "auto_rollback_configuration": [
                {"enabled": True, "events": ["DEPLOYMENT_FAILURE"]}
            ],
        })])
        assert _by(_run(plan), "CD-001").passed


class TestCD002:
    def test_all_at_once_fails(self):
        plan = _plan([_dg("g", {
            "app_name": "app", "deployment_group_name": "g",
            "deployment_config_name": "CodeDeployDefault.AllAtOnce",
        })])
        assert not _by(_run(plan), "CD-002").passed

    def test_graduated_passes(self):
        plan = _plan([_dg("g", {
            "app_name": "app", "deployment_group_name": "g",
            "deployment_config_name": "CodeDeployDefault.LambdaCanary10Percent5Minutes",
        })])
        assert _by(_run(plan), "CD-002").passed


class TestCD003:
    def test_no_alarms_fails(self):
        plan = _plan([_dg("g", {
            "app_name": "app", "deployment_group_name": "g",
            "deployment_config_name": "x",
        })])
        assert not _by(_run(plan), "CD-003").passed

    def test_alarms_configured_passes(self):
        plan = _plan([_dg("g", {
            "app_name": "app", "deployment_group_name": "g",
            "deployment_config_name": "x",
            "alarm_configuration": [{"enabled": True, "alarms": ["a1"]}],
        })])
        assert _by(_run(plan), "CD-003").passed
