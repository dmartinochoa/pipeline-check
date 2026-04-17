"""Unit tests for CodeDeploy CD-001..CD-003 rule modules."""
from __future__ import annotations

from unittest.mock import MagicMock

from botocore.exceptions import ClientError

from pipeline_check.core.checks.aws._catalog import ResourceCatalog
from pipeline_check.core.checks.aws.base import Severity
from pipeline_check.core.checks.aws.rules import (
    cd001_auto_rollback as cd001,
)
from pipeline_check.core.checks.aws.rules import (
    cd002_all_at_once as cd002,
)
from pipeline_check.core.checks.aws.rules import (
    cd003_alarm_config as cd003,
)
from pipeline_check.core.checks.aws.workflows import AWSRuleChecks
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


def _catalog_with(app_groups: dict[str, list[dict]] | None = None):
    """Wire a ResourceCatalog backed by canned CodeDeploy API responses.

    app_groups: {app_name: [group_dict, ...]}
    """
    if app_groups is None:
        app_groups = {"my-app": [_group()]}

    session = MagicMock()
    client = MagicMock()
    session.client.return_value = client

    app_names = list(app_groups.keys())
    app_paginator = make_paginator([{"applications": app_names}])

    def get_paginator(operation):
        if operation == "list_applications":
            return app_paginator
        if operation == "list_deployment_groups":
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
    return ResourceCatalog(session)


class TestCD001AutoRollback:
    def test_rollback_on_failure_passes(self):
        cat = _catalog_with({"app": [_group(rollback_enabled=True, rollback_events=["DEPLOYMENT_FAILURE"])]})
        assert cd001.check(cat)[0].passed

    def test_rollback_disabled_fails(self):
        cat = _catalog_with({"app": [_group(rollback_enabled=False)]})
        f = cd001.check(cat)[0]
        assert not f.passed
        assert f.severity == Severity.MEDIUM

    def test_rollback_enabled_but_wrong_event_fails(self):
        cat = _catalog_with({"app": [_group(rollback_enabled=True, rollback_events=["DEPLOYMENT_STOP_ON_ALARM"])]})
        assert not cd001.check(cat)[0].passed

    def test_rollback_enabled_no_events_fails(self):
        cat = _catalog_with({"app": [_group(rollback_enabled=True, rollback_events=[])]})
        assert not cd001.check(cat)[0].passed

    def test_missing_rollback_config_fails(self):
        group = _group()
        del group["autoRollbackConfiguration"]
        cat = _catalog_with({"app": [group]})
        assert not cd001.check(cat)[0].passed


class TestCD002AllAtOnce:
    def test_all_at_once_ec2_fails(self):
        cat = _catalog_with({"app": [_group(deployment_config="CodeDeployDefault.AllAtOnce")]})
        f = cd002.check(cat)[0]
        assert not f.passed
        assert f.severity == Severity.HIGH

    def test_all_at_once_lambda_fails(self):
        cat = _catalog_with({"app": [_group(deployment_config="CodeDeployDefault.LambdaAllAtOnce")]})
        assert not cd002.check(cat)[0].passed

    def test_all_at_once_ecs_fails(self):
        cat = _catalog_with({"app": [_group(deployment_config="CodeDeployDefault.ECSAllAtOnce")]})
        assert not cd002.check(cat)[0].passed

    def test_canary_config_passes(self):
        cat = _catalog_with({"app": [_group(deployment_config="CodeDeployDefault.LambdaCanary10Percent5Minutes")]})
        assert cd002.check(cat)[0].passed

    def test_linear_config_passes(self):
        cat = _catalog_with({"app": [_group(deployment_config="CodeDeployDefault.LambdaLinear10PercentEvery1Minute")]})
        assert cd002.check(cat)[0].passed

    def test_custom_config_passes(self):
        cat = _catalog_with({"app": [_group(deployment_config="my-company-rolling")]})
        assert cd002.check(cat)[0].passed


class TestCD003AlarmConfig:
    def test_alarm_enabled_with_alarms_passes(self):
        cat = _catalog_with({"app": [_group(alarm_enabled=True, alarms=[{"name": "HighErrorRate"}])]})
        assert cd003.check(cat)[0].passed

    def test_alarm_disabled_fails(self):
        cat = _catalog_with({"app": [_group(alarm_enabled=False, alarms=[{"name": "HighErrorRate"}])]})
        f = cd003.check(cat)[0]
        assert not f.passed
        assert f.severity == Severity.MEDIUM

    def test_alarm_enabled_but_no_alarms_fails(self):
        cat = _catalog_with({"app": [_group(alarm_enabled=True, alarms=[])]})
        assert not cd003.check(cat)[0].passed

    def test_missing_alarm_config_fails(self):
        group = _group()
        del group["alarmConfiguration"]
        cat = _catalog_with({"app": [group]})
        assert not cd003.check(cat)[0].passed

    def test_alarm_names_appear_in_description(self):
        cat = _catalog_with({"app": [_group(alarm_enabled=True, alarms=[{"name": "MyAlarm"}])]})
        assert "MyAlarm" in cd003.check(cat)[0].description


class TestResourceNaming:
    def test_resource_is_app_slash_group(self):
        cat = _catalog_with({"my-app": [_group(name="my-group")]})
        for rule in (cd001, cd002, cd003):
            f = rule.check(cat)[0]
            assert f.resource == "my-app/my-group"


class TestMultipleAppsAndGroups:
    def test_findings_emitted_for_every_group(self):
        cat = _catalog_with({
            "app-a": [_group(name="g1"), _group(name="g2")],
            "app-b": [_group(name="g3")],
        })
        all_findings = cd001.check(cat) + cd002.check(cat) + cd003.check(cat)
        assert len(all_findings) == 9

    def test_check_ids_present_for_each_group(self):
        cat = _catalog_with({
            "app-a": [_group(name="g1")],
            "app-b": [_group(name="g2")],
        })
        resources = {f.resource for f in cd001.check(cat)}
        assert "app-a/g1" in resources
        assert "app-b/g2" in resources


class TestErrorHandling:
    def test_no_applications_returns_empty(self):
        cat = _catalog_with({})
        for rule in (cd001, cd002, cd003):
            assert rule.check(cat) == []

    def test_list_applications_access_denied_yields_single_cd000(self):
        """Orchestrator degraded test: when CodeDeploy enumeration errors,
        exactly one ``CD-000`` finding should cover the three dependent rules."""
        session = MagicMock()
        def _pick(svc, **_):
            if svc == "codedeploy":
                c = MagicMock()
                p = MagicMock()
                p.paginate.side_effect = _client_error()
                c.get_paginator.return_value = p
                return c
            c = MagicMock()
            empty = MagicMock()
            empty.paginate.return_value = iter([])
            c.get_paginator.return_value = empty
            return c
        session.client.side_effect = _pick

        findings = AWSRuleChecks(session).run()
        cd_000 = [f for f in findings if f.check_id == "CD-000"]
        assert len(cd_000) == 1
        assert not cd_000[0].passed
        assert not any(
            f.check_id.startswith("CD-") and f.check_id != "CD-000"
            for f in findings
        )

    def test_list_deployment_groups_error_skips_app(self):
        """Per-app list_deployment_groups failures silently drop that app
        from the catalog; other apps still enumerate normally."""
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

        cat = ResourceCatalog(session)
        resources = {f.resource for f in cd001.check(cat)}
        assert any("app-ok" in r for r in resources)
        assert not any("app-bad" in r for r in resources)

    def test_app_with_no_groups_produces_no_findings(self):
        cat = _catalog_with({"empty-app": []})
        for rule in (cd001, cd002, cd003):
            assert rule.check(cat) == []
