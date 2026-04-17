"""CloudFormation CodeDeploy checks — CD-001..003.

Runs over ``AWS::CodeDeploy::DeploymentGroup`` resources.
"""
from __future__ import annotations

from ..base import Finding, Severity
from .base import CloudFormationBaseCheck, as_str, is_true

_ALL_AT_ONCE_CONFIGS = {
    "CodeDeployDefault.AllAtOnce",
    "CodeDeployDefault.LambdaAllAtOnce",
    "CodeDeployDefault.ECSAllAtOnce",
}


class CodeDeployChecks(CloudFormationBaseCheck):

    def run(self) -> list[Finding]:
        findings: list[Finding] = []
        for r in self.ctx.resources("AWS::CodeDeploy::DeploymentGroup"):
            app = as_str(r.properties.get("ApplicationName"))
            group = as_str(r.properties.get("DeploymentGroupName")) or r.logical_id
            resource = f"{app}/{group}" if app else group
            findings.extend([
                _cd001_auto_rollback(r.properties, resource),
                _cd002_all_at_once(r.properties, resource),
                _cd003_alarm_config(r.properties, resource),
            ])
        return findings


def _cd001_auto_rollback(properties: dict, resource: str) -> Finding:
    rollback = properties.get("AutoRollbackConfiguration") or {}
    enabled = is_true(rollback.get("Enabled"))
    events = rollback.get("Events") or []
    has_failure_rollback = enabled and "DEPLOYMENT_FAILURE" in events
    desc = (
        "Automatic rollback on deployment failure is enabled."
        if has_failure_rollback else
        "Automatic rollback on deployment failure is not configured. "
        "A failed deployment will leave the environment in an inconsistent state."
    )
    return Finding(
        check_id="CD-001",
        title="Automatic rollback on failure not enabled",
        severity=Severity.MEDIUM,
        resource=resource,
        description=desc,
        recommendation=(
            "Enable AutoRollbackConfiguration with at least the DEPLOYMENT_FAILURE event."
        ),
        passed=has_failure_rollback,
    )


def _cd002_all_at_once(properties: dict, resource: str) -> Finding:
    config_name = as_str(properties.get("DeploymentConfigName"))
    is_all_at_once = config_name in _ALL_AT_ONCE_CONFIGS
    desc = (
        f"Deployment uses a graduated config ({config_name!r})."
        if not is_all_at_once else
        f"Deployment is configured with '{config_name}', which routes all "
        "traffic simultaneously — no canary validation window."
    )
    return Finding(
        check_id="CD-002",
        title="AllAtOnce deployment config — no canary or rolling strategy",
        severity=Severity.HIGH,
        resource=resource,
        description=desc,
        recommendation="Switch to a canary or linear deployment configuration.",
        passed=not is_all_at_once,
    )


def _cd003_alarm_config(properties: dict, resource: str) -> Finding:
    alarm_cfg = properties.get("AlarmConfiguration") or {}
    enabled = is_true(alarm_cfg.get("Enabled"))
    alarms = alarm_cfg.get("Alarms") or []
    passed = enabled and len(alarms) > 0
    if passed:
        names = sorted([as_str(a.get("Name")) for a in alarms if isinstance(a, dict)])
        desc = f"CloudWatch alarm monitoring is enabled: {names}."
    else:
        desc = (
            "No CloudWatch alarms are configured for this deployment group. "
            "Error spikes introduced by a deployment will not automatically halt it."
        )
    return Finding(
        check_id="CD-003",
        title="No CloudWatch alarm monitoring on deployment group",
        severity=Severity.MEDIUM,
        resource=resource,
        description=desc,
        recommendation="Add CloudWatch alarms to the AlarmConfiguration.",
        passed=passed,
    )
