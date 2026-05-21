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
    owasp=("CICD-SEC-1",),
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
    exploit_example=(
        "# Vulnerable: ``DeploymentConfigName: CodeDeployDefault\n"
        "# .AllAtOnce``. Bad deploys take the entire fleet down\n"
        "# in one go; no canary window to catch regressions.\n"
        "Resources:\n"
        "  DG:\n"
        "    Type: AWS::CodeDeploy::DeploymentGroup\n"
        "    Properties:\n"
        "      ApplicationName: !Ref App\n"
        "      DeploymentConfigName: CodeDeployDefault.AllAtOnce\n"
        "\n"
        "# Safe: canary / linear / half-at-a-time config so bad\n"
        "# deploys are caught before they reach the full fleet.\n"
        "Resources:\n"
        "  DG:\n"
        "    Type: AWS::CodeDeploy::DeploymentGroup\n"
        "    Properties:\n"
        "      ApplicationName: !Ref App\n"
        "      DeploymentConfigName: CodeDeployDefault.HalfAtATime"
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
