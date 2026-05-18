"""CD-002 (CloudFormation). CodeDeploy AllAtOnce config."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import CloudFormationContext, as_str
from ..codedeploy import _cd002_all_at_once

RULE = Rule(
    id="CD-002",
    title="AllAtOnce deployment config, no canary or rolling strategy",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-7",),
    cwe=("CWE-754",),
    recommendation=(
        "Switch ``DeploymentConfigName`` to a canary or linear "
        "config (e.g. "
        "``CodeDeployDefault.LambdaCanary10Percent5Minutes``). A "
        "staged rollout gives alarm-based rollback a window to "
        "catch regressions before they hit 100% of traffic."
    ),
    docs_note=(
        "Reads ``AWS::CodeDeploy::DeploymentGroup."
        "Properties.DeploymentConfigName``. Fires when the value is "
        "``CodeDeployDefault.AllAtOnce``, ``LambdaAllAtOnce``, or "
        "``ECSAllAtOnce`` — these route every request to the new "
        "revision simultaneously."
    ),
)


def check(ctx: CloudFormationContext) -> list[Finding]:
    findings: list[Finding] = []
    for r in ctx.resources("AWS::CodeDeploy::DeploymentGroup"):
        app = as_str(r.properties.get("ApplicationName"))
        group = as_str(r.properties.get("DeploymentGroupName")) or r.logical_id
        resource = f"{app}/{group}" if app else group
        findings.append(_cd002_all_at_once(r.properties, resource))
    return findings
