"""Terraform CodeDeploy checks (CD-001 … CD-003).

Runs over ``aws_codedeploy_deployment_group`` resources.
"""
from __future__ import annotations

from ..base import Finding, Severity
from .base import TerraformBaseCheck

_ALL_AT_ONCE_CONFIGS = {
    "CodeDeployDefault.AllAtOnce",
    "CodeDeployDefault.LambdaAllAtOnce",
    "CodeDeployDefault.ECSAllAtOnce",
}


def _first(block_list: list | None) -> dict:
    if not block_list:
        return {}
    return block_list[0] or {}


class CodeDeployChecks(TerraformBaseCheck):

    def run(self) -> list[Finding]:
        findings: list[Finding] = []
        for r in self.ctx.resources("aws_codedeploy_deployment_group"):
            app = r.values.get("app_name", "")
            group = r.values.get("deployment_group_name", "") or r.name
            resource = f"{app}/{group}" if app else group
            findings.extend([
                _cd001_auto_rollback(r.values, resource),
                _cd002_all_at_once(r.values, resource),
                _cd003_alarm_config(r.values, resource),
            ])
        return findings


def _cd001_auto_rollback(values: dict, resource: str) -> Finding:
    rollback = _first(values.get("auto_rollback_configuration"))
    enabled = bool(rollback.get("enabled", False))
    events = rollback.get("events", []) or []
    has_failure_rollback = enabled and "DEPLOYMENT_FAILURE" in events

    desc = (
        "Automatic rollback on deployment failure is enabled."
        if has_failure_rollback else
        "Automatic rollback on deployment failure is not configured. "
        "A failed deployment will leave the environment in an inconsistent "
        "or broken state until manually remediated."
    )
    return Finding(
        check_id="CD-001",
        title="Automatic rollback on failure not enabled",
        severity=Severity.MEDIUM,
        resource=resource,
        description=desc,
        recommendation=(
            "Enable auto_rollback_configuration with at least the "
            "DEPLOYMENT_FAILURE event."
        ),
        passed=has_failure_rollback,
    )


def _cd002_all_at_once(values: dict, resource: str) -> Finding:
    config_name = values.get("deployment_config_name", "") or ""
    is_all_at_once = config_name in _ALL_AT_ONCE_CONFIGS
    desc = (
        f"Deployment uses a graduated config ({config_name!r})."
        if not is_all_at_once else
        f"Deployment is configured with '{config_name}', which routes all "
        f"traffic to the new revision simultaneously. A defective build "
        f"immediately impacts 100% of traffic with no canary validation window."
    )
    return Finding(
        check_id="CD-002",
        title="AllAtOnce deployment config — no canary or rolling strategy",
        severity=Severity.HIGH,
        resource=resource,
        description=desc,
        recommendation=(
            "Switch to a canary or linear deployment configuration."
        ),
        passed=not is_all_at_once,
    )


def _cd003_alarm_config(values: dict, resource: str) -> Finding:
    alarm_cfg = _first(values.get("alarm_configuration"))
    enabled = bool(alarm_cfg.get("enabled", False))
    alarms = alarm_cfg.get("alarms", []) or []
    passed = enabled and len(alarms) > 0

    if passed:
        desc = f"CloudWatch alarm monitoring is enabled: {sorted(alarms)}."
    else:
        desc = (
            "No CloudWatch alarms are configured for this deployment group. "
            "Without alarm-based monitoring, error spikes or latency regressions "
            "introduced by a deployment will not automatically halt or roll back "
            "the release."
        )
    return Finding(
        check_id="CD-003",
        title="No CloudWatch alarm monitoring on deployment group",
        severity=Severity.MEDIUM,
        resource=resource,
        description=desc,
        recommendation=(
            "Add CloudWatch alarms to the deployment group's "
            "alarm_configuration block."
        ),
        passed=passed,
    )
