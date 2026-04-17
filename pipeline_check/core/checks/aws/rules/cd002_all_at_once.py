"""CD-002 — CodeDeploy deployment group uses AllAtOnce (no canary/rolling)."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

# Deployment configs that shift 100% of traffic at once.
_ALL_AT_ONCE_CONFIGS = {
    "CodeDeployDefault.AllAtOnce",
    "CodeDeployDefault.LambdaAllAtOnce",
    "CodeDeployDefault.ECSAllAtOnce",
}

RULE = Rule(
    id="CD-002",
    title="AllAtOnce deployment config \u2014 no canary or rolling strategy",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-1",),
    cwe=("CWE-754",),
    recommendation=(
        "Switch to a canary or linear deployment configuration "
        "(e.g. CodeDeployDefault.LambdaCanary10Percent5Minutes or a custom "
        "rolling config) so that defects are caught before they affect all "
        "instances or traffic."
    ),
)


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    for group in catalog.codedeploy_deployment_groups():
        resource = f"{group['_ApplicationName']}/{group['deploymentGroupName']}"
        config_name = group.get("deploymentConfigName", "") or ""
        is_all_at_once = config_name in _ALL_AT_ONCE_CONFIGS
        if not is_all_at_once:
            desc = f"Deployment uses a graduated config ({config_name!r})."
        else:
            desc = (
                f"Deployment is configured with '{config_name}', which routes all "
                f"traffic to the new revision simultaneously. A defective build "
                f"immediately impacts 100% of traffic with no canary validation window."
            )
        findings.append(Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=resource, description=desc,
            recommendation=RULE.recommendation, passed=not is_all_at_once,
        ))
    return findings
