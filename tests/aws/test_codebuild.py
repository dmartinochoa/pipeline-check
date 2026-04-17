"""Unit tests for CodeBuild CB-001..CB-007 rule modules.

These rules share ``catalog.codebuild_projects()`` for project enumeration;
CB-006 additionally consumes ``catalog.codebuild_source_credentials()``.
"""
from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from pipeline_check.core.checks.aws._catalog import ResourceCatalog
from pipeline_check.core.checks.aws.base import Severity
from pipeline_check.core.checks.aws.rules import (
    cb001_plaintext_secrets as cb001,
    cb002_privileged_mode as cb002,
    cb003_logging as cb003,
    cb004_timeout as cb004,
    cb005_image_version as cb005,
    cb006_source_auth as cb006,
    cb007_webhook_filter as cb007,
)
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


def _catalog(projects, source_credentials=None):
    session = MagicMock()
    client = MagicMock()
    session.client.return_value = client

    paginator = make_paginator([{"projects": [p["name"] for p in projects]}])
    client.get_paginator.return_value = paginator
    client.batch_get_projects.return_value = {"projects": projects}
    client.list_source_credentials.return_value = {
        "sourceCredentialsInfos": source_credentials or []
    }

    return ResourceCatalog(session)


class TestCB001PlaintextSecrets:
    def test_plaintext_secret_fails(self):
        proj = _project(env_vars=[{"name": "DB_PASSWORD", "type": "PLAINTEXT", "value": "x"}])
        f = cb001.check(_catalog([proj]))[0]
        assert not f.passed
        assert f.severity == Severity.CRITICAL

    def test_parameter_store_secret_passes(self):
        proj = _project(env_vars=[{"name": "DB_PASSWORD", "type": "PARAMETER_STORE", "value": "/my/param"}])
        assert cb001.check(_catalog([proj]))[0].passed

    def test_innocuous_plaintext_passes(self):
        proj = _project(env_vars=[{"name": "REGION", "type": "PLAINTEXT", "value": "us-east-1"}])
        assert cb001.check(_catalog([proj]))[0].passed

    def test_multiple_secrets_all_listed(self):
        proj = _project(env_vars=[
            {"name": "API_KEY", "type": "PLAINTEXT", "value": "x"},
            {"name": "SECRET_TOKEN", "type": "PLAINTEXT", "value": "y"},
        ])
        f = cb001.check(_catalog([proj]))[0]
        assert not f.passed
        assert "API_KEY" in f.description
        assert "SECRET_TOKEN" in f.description


class TestCB001ValuePatterns:
    def test_aws_access_key_value_detected(self):
        proj = _project(env_vars=[{"name": "X", "type": "PLAINTEXT", "value": "AKIA" + "A" * 16}])
        f = cb001.check(_catalog([proj]))[0]
        assert not f.passed
        assert "credential-like values" in f.description

    def test_github_pat_value_detected(self):
        proj = _project(env_vars=[{"name": "X", "type": "PLAINTEXT", "value": "ghp_" + "a" * 40}])
        assert not cb001.check(_catalog([proj]))[0].passed

    def test_slack_token_value_detected(self):
        proj = _project(env_vars=[{"name": "X", "type": "PLAINTEXT", "value": "xoxb-abcdefghijk-xyz"}])
        assert not cb001.check(_catalog([proj]))[0].passed


class TestCB002PrivilegedMode:
    def test_privileged_fails(self):
        f = cb002.check(_catalog([_project(privileged=True)]))[0]
        assert not f.passed
        assert f.severity == Severity.HIGH

    def test_not_privileged_passes(self):
        assert cb002.check(_catalog([_project(privileged=False)]))[0].passed


class TestCB003Logging:
    def test_no_logging_fails(self):
        proj = _project(cw_logs="DISABLED", s3_logs="DISABLED")
        f = cb003.check(_catalog([proj]))[0]
        assert not f.passed
        assert f.severity == Severity.MEDIUM

    def test_cloudwatch_logging_passes(self):
        proj = _project(cw_logs="ENABLED", s3_logs="DISABLED")
        assert cb003.check(_catalog([proj]))[0].passed

    def test_s3_logging_passes(self):
        proj = _project(cw_logs="DISABLED", s3_logs="ENABLED")
        assert cb003.check(_catalog([proj]))[0].passed


class TestCB004Timeout:
    def test_max_timeout_fails(self):
        f = cb004.check(_catalog([_project(timeout=480)]))[0]
        assert not f.passed
        assert f.severity == Severity.LOW

    def test_sensible_timeout_passes(self):
        assert cb004.check(_catalog([_project(timeout=30)]))[0].passed

    def test_479_passes(self):
        assert cb004.check(_catalog([_project(timeout=479)]))[0].passed


class TestCB005ImageVersion:
    def test_outdated_image_fails(self):
        proj = _project(image="aws/codebuild/standard:5.0")
        assert not cb005.check(_catalog([proj]))[0].passed

    def test_current_image_passes(self):
        proj = _project(image="aws/codebuild/standard:7.0")
        assert cb005.check(_catalog([proj]))[0].passed

    def test_custom_image_passes(self):
        proj = _project(image="123456789.dkr.ecr.us-east-1.amazonaws.com/my-builder:latest")
        assert cb005.check(_catalog([proj]))[0].passed

    def test_version_1_fails(self):
        proj = _project(image="aws/codebuild/standard:1.0")
        assert not cb005.check(_catalog([proj]))[0].passed


class TestCB006SourceAuth:
    def test_oauth_auth_fails(self):
        proj = _project(source={"type": "GITHUB", "auth": {"type": "OAUTH"}})
        f = cb006.check(_catalog([proj]))[0]
        assert not f.passed
        assert f.severity == Severity.HIGH

    def test_pat_auth_fails(self):
        proj = _project(source={"type": "GITHUB", "auth": {"type": "PERSONAL_ACCESS_TOKEN"}})
        assert not cb006.check(_catalog([proj]))[0].passed

    def test_no_auth_on_external_source_passes(self):
        proj = _project(source={"type": "GITHUB"})
        assert cb006.check(_catalog([proj]))[0].passed

    def test_non_external_source_passes(self):
        proj = _project(source={"type": "CODECOMMIT"})
        assert cb006.check(_catalog([proj]))[0].passed

    def test_stored_pat_credential_for_matching_server_fails(self):
        proj = _project(source={"type": "GITHUB"})
        creds = [{"serverType": "GITHUB", "authType": "PERSONAL_ACCESS_TOKEN",
                  "arn": "arn:aws:codebuild:us-east-1:123:token/github"}]
        f = cb006.check(_catalog([proj], source_credentials=creds))[0]
        assert not f.passed
        assert "account-level" in f.description

    def test_stored_credential_for_other_server_does_not_fail(self):
        proj = _project(source={"type": "GITHUB"})
        creds = [{"serverType": "BITBUCKET", "authType": "OAUTH", "arn": "a"}]
        assert cb006.check(_catalog([proj], source_credentials=creds))[0].passed

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
        catalog = ResourceCatalog(session)
        f = cb006.check(catalog)[0]
        assert f.passed  # no inline auth, no stored creds visible


class TestCB007WebhookFilter:
    def test_no_webhook_passes(self):
        assert cb007.check(_catalog([_project()]))[0].passed

    def test_webhook_without_filter_fails(self):
        proj = _project(webhook={"url": "https://x"})
        f = cb007.check(_catalog([proj]))[0]
        assert not f.passed
        assert f.severity == Severity.MEDIUM

    def test_webhook_with_filter_passes(self):
        proj = _project(webhook={"filterGroups": [[{"type": "EVENT", "pattern": "PUSH"}]]})
        assert cb007.check(_catalog([proj]))[0].passed


class TestNoProjects:
    def test_returns_empty_when_no_projects(self):
        session = MagicMock()
        client = MagicMock()
        session.client.return_value = client
        paginator = make_paginator([{"projects": []}])
        client.get_paginator.return_value = paginator
        catalog = ResourceCatalog(session)
        for rule in (cb001, cb002, cb003, cb004, cb005, cb006, cb007):
            assert rule.check(catalog) == []
