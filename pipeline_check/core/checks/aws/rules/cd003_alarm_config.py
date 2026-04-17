"""CD-003 — CodeDeploy deployment group has no CloudWatch alarm monitoring."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="CD-003",
    title="No CloudWatch alarm monitoring on deployment group",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-10",),
    cwe=("CWE-778",),
    recommendation=(
        "Add CloudWatch alarms (e.g. error rate, 5xx count, latency p99) "
        "to the deployment group's alarmConfiguration. Enable automatic "
        "rollback on DEPLOYMENT_STOP_ON_ALARM to halt bad deployments."
    ),
)


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    for group in catalog.codedeploy_deployment_groups():
        resource = f"{group['_ApplicationName']}/{group['deploymentGroupName']}"
        alarm_cfg = group.get("alarmConfiguration", {}) or {}
        enabled = alarm_cfg.get("enabled", False)
        alarms = alarm_cfg.get("alarms", []) or []
        passed = enabled and len(alarms) > 0
        if passed:
            names = [a["name"] for a in alarms]
            desc = f"CloudWatch alarm monitoring is enabled: {names}."
        else:
            desc = (
                "No CloudWatch alarms are configured for this deployment group. "
                "Without alarm-based monitoring, error spikes or latency regressions "
                "introduced by a deployment will not automatically halt or roll back "
                "the release."
            )
        findings.append(Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=resource, description=desc,
            recommendation=RULE.recommendation, passed=passed,
        ))
    return findings
