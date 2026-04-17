"""CD-001 — CodeDeploy deployment group has no auto-rollback on failure."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="CD-001",
    title="Automatic rollback on failure not enabled",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-1",),
    cwe=("CWE-754",),
    recommendation=(
        "Enable autoRollbackConfiguration with at least the "
        "DEPLOYMENT_FAILURE event so CodeDeploy automatically reverts to "
        "the last successful revision when a deployment fails."
    ),
)


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    for group in catalog.codedeploy_deployment_groups():
        resource = f"{group['_ApplicationName']}/{group['deploymentGroupName']}"
        rollback = group.get("autoRollbackConfiguration", {}) or {}
        enabled = rollback.get("enabled", False)
        events = rollback.get("events", []) or []
        has_failure_rollback = enabled and "DEPLOYMENT_FAILURE" in events
        if has_failure_rollback:
            desc = "Automatic rollback on deployment failure is enabled."
        else:
            desc = (
                "Automatic rollback on deployment failure is not configured. "
                "A failed deployment will leave the environment in an inconsistent "
                "or broken state until manually remediated."
            )
        findings.append(Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=resource, description=desc,
            recommendation=RULE.recommendation, passed=has_failure_rollback,
        ))
    return findings
