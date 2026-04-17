"""Unit tests for CodePipeline CP-001..CP-004 rule modules."""
from __future__ import annotations

from unittest.mock import MagicMock

from botocore.exceptions import ClientError

from pipeline_check.core.checks.aws._catalog import ResourceCatalog
from pipeline_check.core.checks.aws.base import Severity
from pipeline_check.core.checks.aws.rules import (
    cp001_approval_before_deploy as cp001,
)
from pipeline_check.core.checks.aws.rules import (
    cp002_artifact_encryption as cp002,
)
from pipeline_check.core.checks.aws.rules import (
    cp003_source_polling as cp003,
)
from pipeline_check.core.checks.aws.rules import (
    cp004_legacy_github as cp004,
)
from pipeline_check.core.checks.aws.workflows import AWSRuleChecks
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


def _catalog_with(pipeline):
    session = MagicMock()
    client = MagicMock()
    session.client.return_value = client
    paginator = make_paginator([{"pipelines": [{"name": pipeline["name"]}]}])
    client.get_paginator.return_value = paginator
    client.get_pipeline.return_value = {"pipeline": pipeline}
    return ResourceCatalog(session)


class TestCP001ApprovalBeforeDeploy:
    def test_deploy_without_approval_fails(self):
        p = _pipeline("pipe", stages=[
            {"actions": [_action("Source")]},
            {"actions": [_action("Deploy")]},
        ])
        f = cp001.check(_catalog_with(p))[0]
        assert not f.passed
        assert f.severity == Severity.HIGH

    def test_approval_before_deploy_passes(self):
        p = _pipeline("pipe", stages=[
            {"actions": [_action("Source")]},
            {"actions": [_action("Approval")]},
            {"actions": [_action("Deploy")]},
        ])
        assert cp001.check(_catalog_with(p))[0].passed

    def test_no_deploy_stage_passes(self):
        p = _pipeline("pipe", stages=[
            {"actions": [_action("Source")]},
            {"actions": [_action("Build")]},
        ])
        assert cp001.check(_catalog_with(p))[0].passed


class TestCP002ArtifactEncryption:
    def test_no_kms_key_fails(self):
        p = _pipeline("pipe", stages=[], artifact_store={"type": "S3", "location": "bucket"})
        f = cp002.check(_catalog_with(p))[0]
        assert not f.passed
        assert f.severity == Severity.MEDIUM

    def test_with_kms_key_passes(self):
        store = {
            "type": "S3",
            "location": "bucket",
            "encryptionKey": {"id": "arn:aws:kms:us-east-1:123:key/abc", "type": "KMS"},
        }
        p = _pipeline("pipe", stages=[], artifact_store=store)
        assert cp002.check(_catalog_with(p))[0].passed


class TestCP003SourcePolling:
    def test_polling_source_fails(self):
        p = _pipeline("pipe", stages=[{"actions": [_action("Source", poll=True)]}])
        f = cp003.check(_catalog_with(p))[0]
        assert not f.passed
        assert f.severity == Severity.LOW

    def test_event_driven_source_passes(self):
        p = _pipeline("pipe", stages=[{"actions": [_action("Source", poll=False)]}])
        assert cp003.check(_catalog_with(p))[0].passed

    def test_no_source_config_passes(self):
        p = _pipeline("pipe", stages=[{"actions": [_action("Source")]}])
        assert cp003.check(_catalog_with(p))[0].passed


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
        f = cp004.check(_catalog_with(p))[0]
        assert not f.passed
        assert f.severity == Severity.HIGH

    def test_codestar_connection_passes(self):
        p = _pipeline("pipe", stages=[
            {"actions": [{
                "name": "Src",
                "actionTypeId": {"category": "Source", "owner": "AWS",
                                 "provider": "CodeStarSourceConnection", "version": "1"},
                "configuration": {},
            }]},
        ])
        assert cp004.check(_catalog_with(p))[0].passed


class TestNoPipelines:
    def test_no_pipelines_returns_empty(self):
        session = MagicMock()
        client = MagicMock()
        session.client.return_value = client
        paginator = make_paginator([{"pipelines": []}])
        client.get_paginator.return_value = paginator
        catalog = ResourceCatalog(session)
        for rule in (cp001, cp002, cp003, cp004):
            assert rule.check(catalog) == []


class TestOrchestratorDegraded:
    def test_list_pipelines_access_denied_yields_single_cp000(self):
        """An AWS-rule-orchestrator degraded regression: when CodePipeline
        enumeration errors, exactly one ``CP-000`` INFO finding should be
        emitted regardless of how many CP rules depend on the catalog."""
        session = MagicMock()
        client = MagicMock()
        session.client.return_value = client
        # batch_get_projects/pipelines and every other call would normally
        # succeed; we only want CodePipeline to fail.
        def _pick(svc, **_kw):
            if svc == "codepipeline":
                paginator = MagicMock()
                paginator.paginate.side_effect = _client_error()
                client.get_paginator.return_value = paginator
                return client
            # Every other service returns an empty, successful client.
            other = MagicMock()
            empty = MagicMock()
            empty.paginate.return_value = iter([])
            other.get_paginator.return_value = empty
            return other
        session.client.side_effect = _pick

        findings = AWSRuleChecks(session).run()
        cp_000 = [f for f in findings if f.check_id == "CP-000"]
        assert len(cp_000) == 1
        assert not cp_000[0].passed
        # None of the CP-xxx rules should have emitted their own findings.
        assert not any(
            f.check_id.startswith("CP-") and f.check_id != "CP-000"
            for f in findings
        )
