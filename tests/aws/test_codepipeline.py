"""Unit tests for CodePipeline checks."""

from unittest.mock import MagicMock

from pipeline_check.core.checks.aws.base import Severity
from pipeline_check.core.checks.aws.codepipeline import CodePipelineChecks
from tests.aws.conftest import make_paginator


def _action(category, name="action", poll=None):
    cfg = {}
    if poll is not None:
        cfg["PollForSourceChanges"] = "true" if poll else "false"
    return {
        "name": name,
        "actionTypeId": {"category": category, "owner": "AWS", "provider": "X", "version": "1"},
        "configuration": cfg,
    }


def _pipeline(name, stages, artifact_store=None):
    store = artifact_store or {"type": "S3", "location": "my-bucket"}
    return {
        "name": name,
        "stages": stages,
        "artifactStore": store,
    }


def _make_check(pipeline):
    session = MagicMock()
    client = MagicMock()
    session.client.return_value = client
    paginator = make_paginator([{"pipelines": [{"name": pipeline["name"]}]}])
    client.get_paginator.return_value = paginator
    client.get_pipeline.return_value = {"pipeline": pipeline}
    return CodePipelineChecks(session)


class TestCP001ApprovalBeforeDeploy:
    def test_deploy_without_approval_fails(self):
        p = _pipeline("pipe", stages=[
            {"actions": [_action("Source")]},
            {"actions": [_action("Deploy")]},
        ])
        findings = _make_check(p).run()
        cp001 = next(f for f in findings if f.check_id == "CP-001")
        assert not cp001.passed
        assert cp001.severity == Severity.HIGH

    def test_approval_before_deploy_passes(self):
        p = _pipeline("pipe", stages=[
            {"actions": [_action("Source")]},
            {"actions": [_action("Approval")]},
            {"actions": [_action("Deploy")]},
        ])
        findings = _make_check(p).run()
        cp001 = next(f for f in findings if f.check_id == "CP-001")
        assert cp001.passed

    def test_no_deploy_stage_passes(self):
        p = _pipeline("pipe", stages=[
            {"actions": [_action("Source")]},
            {"actions": [_action("Build")]},
        ])
        findings = _make_check(p).run()
        assert next(f for f in findings if f.check_id == "CP-001").passed


class TestCP002ArtifactEncryption:
    def test_no_kms_key_fails(self):
        p = _pipeline("pipe", stages=[], artifact_store={"type": "S3", "location": "bucket"})
        findings = _make_check(p).run()
        cp002 = next(f for f in findings if f.check_id == "CP-002")
        assert not cp002.passed
        assert cp002.severity == Severity.MEDIUM

    def test_with_kms_key_passes(self):
        store = {
            "type": "S3",
            "location": "bucket",
            "encryptionKey": {"id": "arn:aws:kms:us-east-1:123:key/abc", "type": "KMS"},
        }
        p = _pipeline("pipe", stages=[], artifact_store=store)
        findings = _make_check(p).run()
        assert next(f for f in findings if f.check_id == "CP-002").passed


class TestCP003SourcePolling:
    def test_polling_source_fails(self):
        p = _pipeline("pipe", stages=[
            {"actions": [_action("Source", poll=True)]},
        ])
        findings = _make_check(p).run()
        cp003 = next(f for f in findings if f.check_id == "CP-003")
        assert not cp003.passed
        assert cp003.severity == Severity.LOW

    def test_event_driven_source_passes(self):
        p = _pipeline("pipe", stages=[
            {"actions": [_action("Source", poll=False)]},
        ])
        findings = _make_check(p).run()
        assert next(f for f in findings if f.check_id == "CP-003").passed

    def test_no_source_config_passes(self):
        p = _pipeline("pipe", stages=[
            {"actions": [_action("Source")]},
        ])
        findings = _make_check(p).run()
        assert next(f for f in findings if f.check_id == "CP-003").passed
