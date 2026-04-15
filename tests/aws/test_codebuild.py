"""Unit tests for CodeBuild checks."""

from unittest.mock import MagicMock

from pipeline_check.core.checks.aws.base import Severity
from pipeline_check.core.checks.aws.codebuild import CodeBuildChecks
from tests.aws.conftest import make_paginator


def _project(
    name="my-project",
    env_vars=None,
    privileged=False,
    cw_logs="ENABLED",
    s3_logs="DISABLED",
    timeout=60,
    image="aws/codebuild/standard:7.0",
    source=None,
    webhook=None,
):
    proj = {
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
    if source is not None:
        proj["source"] = source
    if webhook is not None:
        proj["webhook"] = webhook
    return proj


def _make_check(projects, source_credentials=None):
    session = MagicMock()
    client = MagicMock()
    session.client.return_value = client

    paginator = make_paginator([{"projects": [p["name"] for p in projects]}])
    client.get_paginator.return_value = paginator
    client.batch_get_projects.return_value = {"projects": projects}
    client.list_source_credentials.return_value = {
        "sourceCredentialsInfos": source_credentials or []
    }

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


class TestCB001ValuePatterns:
    def test_aws_access_key_value_detected(self):
        proj = _project(env_vars=[{"name": "X", "type": "PLAINTEXT", "value": "AKIA" + "A" * 16}])
        cb001 = next(f for f in _make_check([proj]).run() if f.check_id == "CB-001")
        assert not cb001.passed
        assert "credential-like values" in cb001.description

    def test_github_pat_value_detected(self):
        proj = _project(env_vars=[{"name": "X", "type": "PLAINTEXT", "value": "ghp_" + "a" * 40}])
        assert not next(f for f in _make_check([proj]).run() if f.check_id == "CB-001").passed

    def test_slack_token_value_detected(self):
        proj = _project(env_vars=[{"name": "X", "type": "PLAINTEXT", "value": "xoxb-abcdefghijk-xyz"}])
        assert not next(f for f in _make_check([proj]).run() if f.check_id == "CB-001").passed


class TestCB006SourceAuth:
    def test_oauth_auth_fails(self):
        proj = _project(source={"type": "GITHUB", "auth": {"type": "OAUTH"}})
        cb006 = next(f for f in _make_check([proj]).run() if f.check_id == "CB-006")
        assert not cb006.passed
        assert cb006.severity == Severity.HIGH

    def test_pat_auth_fails(self):
        proj = _project(source={"type": "GITHUB", "auth": {"type": "PERSONAL_ACCESS_TOKEN"}})
        assert not next(f for f in _make_check([proj]).run() if f.check_id == "CB-006").passed

    def test_no_auth_on_external_source_passes(self):
        proj = _project(source={"type": "GITHUB"})
        assert next(f for f in _make_check([proj]).run() if f.check_id == "CB-006").passed

    def test_non_external_source_passes(self):
        proj = _project(source={"type": "CODECOMMIT"})
        assert next(f for f in _make_check([proj]).run() if f.check_id == "CB-006").passed

    def test_stored_pat_credential_for_matching_server_fails(self):
        proj = _project(source={"type": "GITHUB"})
        creds = [{"serverType": "GITHUB", "authType": "PERSONAL_ACCESS_TOKEN",
                  "arn": "arn:aws:codebuild:us-east-1:123:token/github"}]
        cb006 = next(f for f in _make_check([proj], source_credentials=creds).run()
                     if f.check_id == "CB-006")
        assert not cb006.passed
        assert "account-level" in cb006.description

    def test_stored_credential_for_other_server_does_not_fail(self):
        proj = _project(source={"type": "GITHUB"})
        creds = [{"serverType": "BITBUCKET", "authType": "OAUTH", "arn": "a"}]
        assert next(
            f for f in _make_check([proj], source_credentials=creds).run()
            if f.check_id == "CB-006"
        ).passed

    def test_list_source_credentials_access_denied_does_not_break(self):
        from botocore.exceptions import ClientError
        proj = _project(source={"type": "GITHUB"})
        session = MagicMock()
        client = MagicMock()
        session.client.return_value = client
        paginator = make_paginator([{"projects": [proj["name"]]}])
        client.get_paginator.return_value = paginator
        client.batch_get_projects.return_value = {"projects": [proj]}
        client.list_source_credentials.side_effect = ClientError(
            {"Error": {"Code": "AccessDeniedException", "Message": "msg"}}, "op"
        )
        cb006 = next(f for f in CodeBuildChecks(session).run() if f.check_id == "CB-006")
        assert cb006.passed  # no inline auth, no stored creds visible


class TestCB007WebhookFilter:
    def test_no_webhook_passes(self):
        proj = _project()
        assert next(f for f in _make_check([proj]).run() if f.check_id == "CB-007").passed

    def test_webhook_without_filter_fails(self):
        proj = _project(webhook={"url": "https://x"})
        cb007 = next(f for f in _make_check([proj]).run() if f.check_id == "CB-007")
        assert not cb007.passed
        assert cb007.severity == Severity.MEDIUM

    def test_webhook_with_filter_passes(self):
        proj = _project(webhook={"filterGroups": [[{"type": "EVENT", "pattern": "PUSH"}]]})
        assert next(f for f in _make_check([proj]).run() if f.check_id == "CB-007").passed


class TestNoProjects:
    def test_returns_empty_when_no_projects(self):
        session = MagicMock()
        client = MagicMock()
        session.client.return_value = client
        paginator = make_paginator([{"projects": []}])
        client.get_paginator.return_value = paginator
        findings = CodeBuildChecks(session).run()
        assert findings == []
