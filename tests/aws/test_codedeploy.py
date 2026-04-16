"""Unit tests for CodeDeploy checks."""

from unittest.mock import MagicMock

from botocore.exceptions import ClientError

from pipeline_check.core.checks.aws.base import Severity
from pipeline_check.core.checks.aws.codedeploy import CodeDeployChecks
from tests.aws.conftest import make_paginator


def _client_error(code="AccessDeniedException"):
    return ClientError({"Error": {"Code": code, "Message": "msg"}}, "op")


def _group(
    name="my-group",
    rollback_enabled=True,
    rollback_events=None,
    deployment_config="CodeDeployDefault.LambdaCanary10Percent5Minutes",
    alarm_enabled=True,
    alarms=None,
):
    """Build a minimal deploymentGroupsInfo entry."""
    if rollback_events is None:
        rollback_events = ["DEPLOYMENT_FAILURE"]
    if alarms is None:
        alarms = [{"name": "ErrorRateHigh"}]
    return {
        "deploymentGroupName": name,
        "autoRollbackConfiguration": {
            "enabled": rollback_enabled,
            "events": rollback_events,
        },
        "deploymentConfigName": deployment_config,
        "alarmConfiguration": {
            "enabled": alarm_enabled,
            "alarms": alarms,
        },
    }


def _make_check(app_groups: dict[str, list[dict]] | None = None):
    """Wire up a CodeDeployChecks instance with canned API responses.

    app_groups: {app_name: [group_dict, ...]}
    """
    if app_groups is None:
        app_groups = {"my-app": [_group()]}

    session = MagicMock()
    client = MagicMock()
    session.client.return_value = client

    app_names = list(app_groups.keys())

    # list_applications paginator
    app_paginator = make_paginator([{"applications": app_names}])

    # list_deployment_groups paginators — one per app, keyed by applicationName kwarg
    def get_paginator(operation):
        if operation == "list_applications":
            return app_paginator
        if operation == "list_deployment_groups":
            # Return a fresh paginator stub; paginate() is called with applicationName=
            p = MagicMock()
            p.paginate.side_effect = lambda applicationName, **_: iter(
                [{"deploymentGroups": [g["deploymentGroupName"] for g in app_groups[applicationName]]}]
            )
            return p
        raise ValueError(f"Unexpected paginator: {operation}")

    client.get_paginator.side_effect = get_paginator

    def batch_get(applicationName, deploymentGroupNames, **_):
        groups = [g for g in app_groups[applicationName] if g["deploymentGroupName"] in deploymentGroupNames]
        return {"deploymentGroupsInfo": groups}

    client.batch_get_deployment_groups.side_effect = batch_get

    return CodeDeployChecks(session)


# ---------------------------------------------------------------------------
# CD-001  Automatic rollback on failure
# ---------------------------------------------------------------------------

class TestCD001AutoRollback:
    def test_rollback_on_failure_passes(self):
        findings = _make_check({"app": [_group(rollback_enabled=True, rollback_events=["DEPLOYMENT_FAILURE"])]}).run()
        cd001 = next(f for f in findings if f.check_id == "CD-001")
        assert cd001.passed

    def test_rollback_disabled_fails(self):
        findings = _make_check({"app": [_group(rollback_enabled=False)]}).run()
        cd001 = next(f for f in findings if f.check_id == "CD-001")
        assert not cd001.passed
        assert cd001.severity == Severity.MEDIUM

    def test_rollback_enabled_but_wrong_event_fails(self):
        findings = _make_check({"app": [_group(rollback_enabled=True, rollback_events=["DEPLOYMENT_STOP_ON_ALARM"])]}).run()
        cd001 = next(f for f in findings if f.check_id == "CD-001")
        assert not cd001.passed

    def test_rollback_enabled_no_events_fails(self):
        findings = _make_check({"app": [_group(rollback_enabled=True, rollback_events=[])]}).run()
        cd001 = next(f for f in findings if f.check_id == "CD-001")
        assert not cd001.passed

    def test_missing_rollback_config_fails(self):
        group = _group()
        del group["autoRollbackConfiguration"]
        findings = _make_check({"app": [group]}).run()
        cd001 = next(f for f in findings if f.check_id == "CD-001")
        assert not cd001.passed


# ---------------------------------------------------------------------------
# CD-002  AllAtOnce deployment config
# ---------------------------------------------------------------------------

class TestCD002AllAtOnce:
    def test_all_at_once_ec2_fails(self):
        findings = _make_check({"app": [_group(deployment_config="CodeDeployDefault.AllAtOnce")]}).run()
        cd002 = next(f for f in findings if f.check_id == "CD-002")
        assert not cd002.passed
        assert cd002.severity == Severity.HIGH

    def test_all_at_once_lambda_fails(self):
        findings = _make_check({"app": [_group(deployment_config="CodeDeployDefault.LambdaAllAtOnce")]}).run()
        assert not next(f for f in findings if f.check_id == "CD-002").passed

    def test_all_at_once_ecs_fails(self):
        findings = _make_check({"app": [_group(deployment_config="CodeDeployDefault.ECSAllAtOnce")]}).run()
        assert not next(f for f in findings if f.check_id == "CD-002").passed

    def test_canary_config_passes(self):
        findings = _make_check({"app": [_group(deployment_config="CodeDeployDefault.LambdaCanary10Percent5Minutes")]}).run()
        assert next(f for f in findings if f.check_id == "CD-002").passed

    def test_linear_config_passes(self):
        findings = _make_check({"app": [_group(deployment_config="CodeDeployDefault.LambdaLinear10PercentEvery1Minute")]}).run()
        assert next(f for f in findings if f.check_id == "CD-002").passed

    def test_custom_config_passes(self):
        findings = _make_check({"app": [_group(deployment_config="my-company-rolling")]}).run()
        assert next(f for f in findings if f.check_id == "CD-002").passed


# ---------------------------------------------------------------------------
# CD-003  CloudWatch alarm monitoring
# ---------------------------------------------------------------------------

class TestCD003AlarmConfig:
    def test_alarm_enabled_with_alarms_passes(self):
        findings = _make_check({"app": [_group(alarm_enabled=True, alarms=[{"name": "HighErrorRate"}])]}).run()
        cd003 = next(f for f in findings if f.check_id == "CD-003")
        assert cd003.passed

    def test_alarm_disabled_fails(self):
        findings = _make_check({"app": [_group(alarm_enabled=False, alarms=[{"name": "HighErrorRate"}])]}).run()
        cd003 = next(f for f in findings if f.check_id == "CD-003")
        assert not cd003.passed
        assert cd003.severity == Severity.MEDIUM

    def test_alarm_enabled_but_no_alarms_fails(self):
        findings = _make_check({"app": [_group(alarm_enabled=True, alarms=[])]}).run()
        assert not next(f for f in findings if f.check_id == "CD-003").passed

    def test_missing_alarm_config_fails(self):
        group = _group()
        del group["alarmConfiguration"]
        findings = _make_check({"app": [group]}).run()
        assert not next(f for f in findings if f.check_id == "CD-003").passed

    def test_alarm_names_appear_in_description(self):
        findings = _make_check({"app": [_group(alarm_enabled=True, alarms=[{"name": "MyAlarm"}])]}).run()
        cd003 = next(f for f in findings if f.check_id == "CD-003")
        assert "MyAlarm" in cd003.description


# ---------------------------------------------------------------------------
# Resource naming
# ---------------------------------------------------------------------------

class TestResourceNaming:
    def test_resource_is_app_slash_group(self):
        findings = _make_check({"my-app": [_group(name="my-group")]}).run()
        for f in findings:
            assert f.resource == "my-app/my-group"


# ---------------------------------------------------------------------------
# Multi-app / multi-group
# ---------------------------------------------------------------------------

class TestMultipleAppsAndGroups:
    def test_findings_emitted_for_every_group(self):
        findings = _make_check({
            "app-a": [_group(name="g1"), _group(name="g2")],
            "app-b": [_group(name="g3")],
        }).run()
        # 3 checks × 3 groups = 9 findings
        assert len(findings) == 9

    def test_check_ids_present_for_each_group(self):
        findings = _make_check({
            "app-a": [_group(name="g1")],
            "app-b": [_group(name="g2")],
        }).run()
        resources = {f.resource for f in findings}
        assert "app-a/g1" in resources
        assert "app-b/g2" in resources


# ---------------------------------------------------------------------------
# Error / edge-case handling
# ---------------------------------------------------------------------------

class TestErrorHandling:
    def test_no_applications_returns_empty(self):
        findings = _make_check({}).run()
        assert findings == []

    def test_list_applications_access_denied_returns_cd000(self):
        session = MagicMock()
        client = MagicMock()
        session.client.return_value = client

        p = MagicMock()
        p.paginate.side_effect = _client_error("AccessDeniedException")
        client.get_paginator.return_value = p

        findings = CodeDeployChecks(session).run()
        assert len(findings) == 1
        assert findings[0].check_id == "CD-000"
        assert not findings[0].passed

    def test_list_deployment_groups_error_skips_app(self):
        session = MagicMock()
        client = MagicMock()
        session.client.return_value = client

        app_paginator = make_paginator([{"applications": ["app-ok", "app-bad"]}])

        def get_paginator(operation):
            if operation == "list_applications":
                return app_paginator
            p = MagicMock()

            def paginate_side_effect(applicationName, **_):
                if applicationName == "app-bad":
                    raise _client_error()
                return iter([{"deploymentGroups": ["g1"]}])

            p.paginate.side_effect = paginate_side_effect
            return p

        client.get_paginator.side_effect = get_paginator
        client.batch_get_deployment_groups.return_value = {"deploymentGroupsInfo": [_group()]}

        findings = CodeDeployChecks(session).run()
        # app-ok produces real CD-00X findings; app-bad produces a
        # single CD-000 degraded-mode finding, not silence — so the
        # operator can see that not every application was evaluated.
        bad_failures = [
            f for f in findings
            if "app-bad" in f.resource and f.check_id == "CD-000"
        ]
        assert len(bad_failures) == 1
        # No CD-001/002/003 findings for app-bad (we couldn't list its groups).
        non_degraded_bad = [
            f for f in findings
            if "app-bad" in f.resource and f.check_id != "CD-000"
        ]
        assert non_degraded_bad == []
        assert any("app-ok" in f.resource for f in findings)

    def test_app_with_no_groups_produces_no_findings(self):
        findings = _make_check({"empty-app": []}).run()
        assert findings == []
