"""Terraform CP-001/002/003 tests."""
from __future__ import annotations

from pipeline_check.core.checks.terraform.base import TerraformContext
from pipeline_check.core.checks.terraform.codepipeline import CodePipelineChecks


def _plan(resources: list[dict]) -> dict:
    return {
        "format_version": "1.2",
        "planned_values": {
            "root_module": {"resources": resources, "child_modules": []}
        },
    }


def _pipeline(name: str, stages: list[dict], artifact_stores: list[dict]) -> dict:
    return {
        "address": f"aws_codepipeline.{name}",
        "mode": "managed",
        "type": "aws_codepipeline",
        "name": name,
        "values": {
            "name": name,
            "stage": stages,
            "artifact_store": artifact_stores,
        },
    }


def _by(findings, cid):
    return next(f for f in findings if f.check_id == cid)


def _run(plan):
    return CodePipelineChecks(TerraformContext(plan)).run()


class TestCP001:
    def test_deploy_without_approval_fails(self):
        plan = _plan([_pipeline("p", [
            {"name": "Source", "action": [{"name": "s", "category": "Source"}]},
            {"name": "Deploy", "action": [{"name": "d", "category": "Deploy"}]},
        ], [{"location": "b", "encryption_key": [{"id": "k"}]}])])
        assert not _by(_run(plan), "CP-001").passed

    def test_approval_before_deploy_passes(self):
        plan = _plan([_pipeline("p", [
            {"name": "Approve", "action": [{"name": "a", "category": "Approval"}]},
            {"name": "Deploy", "action": [{"name": "d", "category": "Deploy"}]},
        ], [{"location": "b", "encryption_key": [{"id": "k"}]}])])
        assert _by(_run(plan), "CP-001").passed


class TestCP002:
    def test_no_encryption_key_fails(self):
        plan = _plan([_pipeline("p", [], [{"location": "bkt"}])])
        assert not _by(_run(plan), "CP-002").passed

    def test_encryption_key_passes(self):
        plan = _plan([_pipeline("p", [], [{"location": "bkt", "encryption_key": [{"id": "k"}]}])])
        assert _by(_run(plan), "CP-002").passed


class TestCP003:
    def test_polling_source_fails(self):
        plan = _plan([_pipeline("p", [
            {"name": "Source", "action": [{"name": "s", "category": "Source",
                                           "configuration": {"PollForSourceChanges": "true"}}]},
        ], [{"location": "b", "encryption_key": [{"id": "k"}]}])])
        assert not _by(_run(plan), "CP-003").passed

    def test_event_driven_source_passes(self):
        plan = _plan([_pipeline("p", [
            {"name": "Source", "action": [{"name": "s", "category": "Source",
                                           "configuration": {"PollForSourceChanges": "false"}}]},
        ], [{"location": "b", "encryption_key": [{"id": "k"}]}])])
        assert _by(_run(plan), "CP-003").passed


class TestCP004:
    def test_legacy_thirdparty_github_fails(self):
        plan = _plan([_pipeline("p", [
            {"name": "Source", "action": [{
                "name": "s", "category": "Source",
                "owner": "ThirdParty", "provider": "GitHub",
            }]},
        ], [{"location": "b", "encryption_key": [{"id": "k"}]}])])
        assert not _by(_run(plan), "CP-004").passed

    def test_codestar_connection_passes(self):
        plan = _plan([_pipeline("p", [
            {"name": "Source", "action": [{
                "name": "s", "category": "Source",
                "owner": "AWS", "provider": "CodeStarSourceConnection",
            }]},
        ], [{"location": "b", "encryption_key": [{"id": "k"}]}])])
        assert _by(_run(plan), "CP-004").passed

    def test_no_source_action_passes(self):
        plan = _plan([_pipeline("p", [], [{"location": "b", "encryption_key": [{"id": "k"}]}])])
        assert _by(_run(plan), "CP-004").passed
