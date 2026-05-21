"""CD-002. CodeDeploy deployment group uses AllAtOnce (no canary/rolling)."""
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
    title="AllAtOnce deployment config, no canary or rolling strategy",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-1",),
    cwe=("CWE-754",),
    recommendation=(
        "Switch to a canary or linear deployment configuration "
        "(e.g. CodeDeployDefault.LambdaCanary10Percent5Minutes or a custom "
        "rolling config) so that defects are caught before they affect all "
        "instances or traffic."
    ),
    docs_note=(
        "AllAtOnce shifts 100% of traffic to the new revision in one "
        "step. There's no gradient to halt on if a CloudWatch alarm "
        "trips mid-rollout, the bad revision is already serving "
        "every request. Canary / linear configs introduce the "
        "shift-then-watch shape that lets monitors catch a "
        "regression before it's universal."
    ),
    exploit_example=(
        "# Vulnerable: ``CodeDeployDefault.AllAtOnce``. Every\n"
        "# deploy ships to every instance simultaneously. A bad\n"
        "# build (or a malicious one) takes the entire fleet down\n"
        "# at once; there's no canary window in which a regression\n"
        "# could be caught before customer-facing impact.\n"
        "import boto3\n"
        "cd = boto3.client('codedeploy')\n"
        "cd.create_deployment_group(\n"
        "    applicationName='my-app',\n"
        "    deploymentGroupName='prod',\n"
        "    deploymentConfigName='CodeDeployDefault.AllAtOnce',\n"
        "    # ...\n"
        ")\n"
        "\n"
        "# Safe: a canary / linear / blue-green config. Bad\n"
        "# deploys are caught before they reach the full fleet.\n"
        "cd.update_deployment_group(\n"
        "    applicationName='my-app',\n"
        "    currentDeploymentGroupName='prod',\n"
        "    deploymentConfigName='CodeDeployDefault.LambdaCanary10Percent5Minutes',\n"
        "    # or 'CodeDeployDefault.HalfAtATime' / 'CodeDeployDefault.OneAtATime'\n"
        ")"
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
