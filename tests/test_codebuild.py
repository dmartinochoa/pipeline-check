"""Unit tests for CodeBuild checks."""

from unittest.mock import MagicMock

from pipeline_check.core.checks.base import Severity
from pipeline_check.core.checks.codebuild import CodeBuildChecks
from tests.conftest import make_paginator


def _project(
    name="my-project",
    env_vars=None,
    privileged=False,
    cw_logs="ENABLED",
    s3_logs="DISABLED",
    timeout=60,
    image="aws/codebuild/standard:7.0",
):
    return {
        "name": name,
        "environment": {
            "environmentVariables": env_vars or [],
            "privilegedMode": privileged,
            "image": image,
        },
        "logsConfig": {
            "cloudWatchLogs": {"status": cw_logs},
            "s3Logs": {"status": s3_logs},
        },
        "timeoutInMinutes": timeout,
    }


def _make_check(projects):
    session = MagicMock()
    client = MagicMock()
    session.client.return_value = client

    paginator = make_paginator([{"projects": [p["name"] for p in projects]}])
    client.get_paginator.return_value = paginator
    client.batch_get_projects.return_value = {"projects": projects}

    return CodeBuildChecks(session)


class TestCB001PlaintextSecrets:
    def test_plaintext_secret_fails(self):
        proj = _project(env_vars=[{"name": "DB_PASSWORD", "type": "PLAINTEXT", "value": "x"}])
        findings = _make_check([proj]).run()
        cb001 = next(f for f in findings if f.check_id == "CB-001")
        assert not cb001.passed
        assert cb001.severity == Severity.CRITICAL

    def test_parameter_store_secret_passes(self):
        proj = _project(env_vars=[{"name": "DB_PASSWORD", "type": "PARAMETER_STORE", "value": "/my/param"}])
        findings = _make_check([proj]).run()
        cb001 = next(f for f in findings if f.check_id == "CB-001")
        assert cb001.passed

    def test_innocuous_plaintext_passes(self):
        proj = _project(env_vars=[{"name": "REGION", "type": "PLAINTEXT", "value": "us-east-1"}])
        findings = _make_check([proj]).run()
        cb001 = next(f for f in findings if f.check_id == "CB-001")
        assert cb001.passed

    def test_multiple_secrets_all_listed(self):
        proj = _project(env_vars=[
            {"name": "API_KEY", "type": "PLAINTEXT", "value": "x"},
            {"name": "SECRET_TOKEN", "type": "PLAINTEXT", "value": "y"},
        ])
        findings = _make_check([proj]).run()
        cb001 = next(f for f in findings if f.check_id == "CB-001")
        assert not cb001.passed
        assert "API_KEY" in cb001.description
        assert "SECRET_TOKEN" in cb001.description


class TestCB002PrivilegedMode:
    def test_privileged_fails(self):
        proj = _project(privileged=True)
        findings = _make_check([proj]).run()
        cb002 = next(f for f in findings if f.check_id == "CB-002")
        assert not cb002.passed
        assert cb002.severity == Severity.HIGH

    def test_not_privileged_passes(self):
        proj = _project(privileged=False)
        findings = _make_check([proj]).run()
        cb002 = next(f for f in findings if f.check_id == "CB-002")
        assert cb002.passed


class TestCB003Logging:
    def test_no_logging_fails(self):
        proj = _project(cw_logs="DISABLED", s3_logs="DISABLED")
        findings = _make_check([proj]).run()
        cb003 = next(f for f in findings if f.check_id == "CB-003")
        assert not cb003.passed
        assert cb003.severity == Severity.MEDIUM

    def test_cloudwatch_logging_passes(self):
        proj = _project(cw_logs="ENABLED", s3_logs="DISABLED")
        findings = _make_check([proj]).run()
        assert next(f for f in findings if f.check_id == "CB-003").passed

    def test_s3_logging_passes(self):
        proj = _project(cw_logs="DISABLED", s3_logs="ENABLED")
        findings = _make_check([proj]).run()
        assert next(f for f in findings if f.check_id == "CB-003").passed


class TestCB004Timeout:
    def test_max_timeout_fails(self):
        proj = _project(timeout=480)
        findings = _make_check([proj]).run()
        cb004 = next(f for f in findings if f.check_id == "CB-004")
        assert not cb004.passed
        assert cb004.severity == Severity.LOW

    def test_sensible_timeout_passes(self):
        proj = _project(timeout=30)
        findings = _make_check([proj]).run()
        assert next(f for f in findings if f.check_id == "CB-004").passed

    def test_479_passes(self):
        proj = _project(timeout=479)
        findings = _make_check([proj]).run()
        assert next(f for f in findings if f.check_id == "CB-004").passed


class TestCB005ImageVersion:
    def test_outdated_image_fails(self):
        proj = _project(image="aws/codebuild/standard:5.0")
        findings = _make_check([proj]).run()
        cb005 = next(f for f in findings if f.check_id == "CB-005")
        assert not cb005.passed

    def test_current_image_passes(self):
        proj = _project(image="aws/codebuild/standard:7.0")
        findings = _make_check([proj]).run()
        assert next(f for f in findings if f.check_id == "CB-005").passed

    def test_custom_image_passes(self):
        proj = _project(image="123456789.dkr.ecr.us-east-1.amazonaws.com/my-builder:latest")
        findings = _make_check([proj]).run()
        assert next(f for f in findings if f.check_id == "CB-005").passed

    def test_version_1_fails(self):
        proj = _project(image="aws/codebuild/standard:1.0")
        findings = _make_check([proj]).run()
        assert not next(f for f in findings if f.check_id == "CB-005").passed


class TestNoProjects:
    def test_returns_empty_when_no_projects(self):
        session = MagicMock()
        client = MagicMock()
        session.client.return_value = client
        paginator = make_paginator([{"projects": []}])
        client.get_paginator.return_value = paginator
        findings = CodeBuildChecks(session).run()
        assert findings == []
