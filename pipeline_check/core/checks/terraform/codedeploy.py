"""Terraform CodeDeploy checks (CD-001 … CD-003).

Runs over ``aws_codedeploy_deployment_group`` resources.
"""
from __future__ import annotations

from typing import Any

from ..base import Finding, Severity
from .base import TerraformBaseCheck, TerraformContext

_ALL_AT_ONCE_CONFIGS = {
    "CodeDeployDefault.AllAtOnce",
    "CodeDeployDefault.LambdaAllAtOnce",
    "CodeDeployDefault.ECSAllAtOnce",
}


def _custom_all_at_once_config_names(ctx: TerraformContext) -> frozenset[str]:
    """Names of in-plan custom deployment configs that are all-at-once.

    A custom ``aws_codedeploy_deployment_config`` is semantically
    all-at-once when it requires zero healthy hosts
    (``minimum_healthy_hosts { value = 0 }``, HOST_COUNT or
    FLEET_PERCENT) or declares ``traffic_routing_config { type =
    "AllAtOnce" }``. Such a config is as risky as the managed
    ``CodeDeployDefault.AllAtOnce`` but wears a custom name.
    """
    names: set[str] = set()
    for r in ctx.resources("aws_codedeploy_deployment_config"):
        cfg_name = r.values.get("deployment_config_name", "") or r.name
        mhh = _first(r.values.get("minimum_healthy_hosts"))
        try:
            zero_healthy = int(mhh.get("value", -1)) == 0 if mhh else False
        except (TypeError, ValueError):
            zero_healthy = False
        routing = _first(r.values.get("traffic_routing_config"))
        all_at_once_routing = routing.get("type") == "AllAtOnce"
        if zero_healthy or all_at_once_routing:
            names.add(cfg_name)
    return frozenset(names)


def _first(block_list: object) -> dict[str, Any]:
    # Validate both container and head. ``block_list`` may surface as
    # a non-list ``object`` (a ``values.get`` Any can be a dict, str,
    # int, …); the head may be a non-dict truthy value. Mirrors
    # ``extended._first`` so callers always see a mapping safe to
    # ``.get()``.
    if not isinstance(block_list, list) or not block_list:
        return {}
    head = block_list[0]
    return head if isinstance(head, dict) else {}


class CodeDeployChecks(TerraformBaseCheck):

    def run(self) -> list[Finding]:
        findings: list[Finding] = []
        custom_all_at_once = _custom_all_at_once_config_names(self.ctx)
        for r in self.ctx.resources("aws_codedeploy_deployment_group"):
            app = r.values.get("app_name", "")
            group = r.values.get("deployment_group_name", "") or r.name
            resource = f"{app}/{group}" if app else group
            findings.extend([
                _cd001_auto_rollback(r.values, resource),
                _cd002_all_at_once(r.values, resource, custom_all_at_once),
                _cd003_alarm_config(r.values, resource),
            ])
        return findings


def _cd001_auto_rollback(values: dict[str, Any], resource: str) -> Finding:
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


def _cd002_all_at_once(
    values: dict[str, Any],
    resource: str,
    custom_all_at_once: frozenset[str] = frozenset(),
) -> Finding:
    config_name = values.get("deployment_config_name", "") or ""
    is_all_at_once = (
        config_name in _ALL_AT_ONCE_CONFIGS or config_name in custom_all_at_once
    )
    desc = (
        f"Deployment uses a graduated config ({config_name!r})."
        if not is_all_at_once else
        f"Deployment is configured with '{config_name}', which routes all "
        f"traffic to the new revision simultaneously. A defective build "
        f"immediately impacts 100% of traffic with no canary validation window."
    )
    return Finding(
        check_id="CD-002",
        title="AllAtOnce deployment config, no canary or rolling strategy",
        severity=Severity.HIGH,
        resource=resource,
        description=desc,
        recommendation=(
            "Switch to a canary or linear deployment configuration."
        ),
        passed=not is_all_at_once,
    )


def _cd003_alarm_config(values: dict[str, Any], resource: str) -> Finding:
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
