"""Unit tests for CodePipeline checks."""

from unittest.mock import MagicMock

from botocore.exceptions import ClientError

from pipeline_check.core.checks.aws.base import Severity
from pipeline_check.core.checks.aws.codepipeline import CodePipelineChecks
from tests.aws.conftest import make_paginator


def _client_error(code="AccessDeniedException"):
    return ClientError({"Error": {"Code": code, "Message": "msg"}}, "op")


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


class TestCP004LegacyGitHub:
    def test_thirdparty_github_fails(self):
        p = _pipeline("pipe", stages=[
            {"actions": [{
                "name": "Src",
                "actionTypeId": {"category": "Source", "owner": "ThirdParty",
                                 "provider": "GitHub", "version": "1"},
                "configuration": {},
            }]},
        ])
        cp004 = next(f for f in _make_check(p).run() if f.check_id == "CP-004")
        assert not cp004.passed
        assert cp004.severity == Severity.HIGH

    def test_codestar_connection_passes(self):
        p = _pipeline("pipe", stages=[
            {"actions": [{
                "name": "Src",
                "actionTypeId": {"category": "Source", "owner": "AWS",
                                 "provider": "CodeStarSourceConnection", "version": "1"},
                "configuration": {},
            }]},
        ])
        assert next(f for f in _make_check(p).run() if f.check_id == "CP-004").passed


class TestNoPipelines:
    def test_no_pipelines_returns_empty(self):
        session = MagicMock()
        client = MagicMock()
        session.client.return_value = client
        paginator = make_paginator([{"pipelines": []}])
        client.get_paginator.return_value = paginator
        findings = CodePipelineChecks(session).run()
        assert findings == []


class TestErrorHandling:
    def test_list_pipelines_access_denied_returns_cp000(self):
        session = MagicMock()
        client = MagicMock()
        session.client.return_value = client
        paginator = MagicMock()
        paginator.paginate.side_effect = _client_error()
        client.get_paginator.return_value = paginator

        findings = CodePipelineChecks(session).run()
        assert len(findings) == 1
        assert findings[0].check_id == "CP-000"
        assert not findings[0].passed

    def test_get_pipeline_error_skips_pipeline(self):
        session = MagicMock()
        client = MagicMock()
        session.client.return_value = client
        paginator = make_paginator([{"pipelines": [{"name": "bad-pipe"}]}])
        client.get_paginator.return_value = paginator
        client.get_pipeline.side_effect = _client_error()

        findings = CodePipelineChecks(session).run()
        # Degraded-mode CP-000 finding surfaces the skipped pipeline,
        # so the operator can tell the silence apart from a real pass.
        assert len(findings) == 1
        assert findings[0].check_id == "CP-000"
        assert "bad-pipe" in findings[0].resource
        assert not findings[0].passed

    def test_target_flag_skips_list_pipelines(self):
        """When target is set the list_pipelines call should be skipped entirely."""
        p = _pipeline("my-pipe", stages=[
            {"actions": [_action("Source")]},
            {"actions": [_action("Approval")]},
            {"actions": [_action("Deploy")]},
        ])
        session = MagicMock()
        client = MagicMock()
        session.client.return_value = client
        client.get_pipeline.return_value = {"pipeline": p}

        findings = CodePipelineChecks(session, target="my-pipe").run()
        client.get_paginator.assert_not_called()
        assert any(f.check_id == "CP-001" and f.passed for f in findings)
