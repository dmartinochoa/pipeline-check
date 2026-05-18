"""CD-001 (CloudFormation). CodeDeploy auto-rollback not enabled."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import CloudFormationContext, as_str
from ..codedeploy import _cd001_auto_rollback

RULE = Rule(
    id="CD-001",
    title="Automatic rollback on failure not enabled",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-7",),
    cwe=("CWE-754",),
    recommendation=(
        "Enable ``AutoRollbackConfiguration`` with at least the "
        "``DEPLOYMENT_FAILURE`` event so a failed release returns "
        "the environment to its prior state without manual "
        "intervention."
    ),
    docs_note=(
        "Reads ``AWS::CodeDeploy::DeploymentGroup."
        "Properties.AutoRollbackConfiguration``. The block needs "
        "``Enabled: true`` AND ``\"DEPLOYMENT_FAILURE\"`` present in "
        "``Events`` for the deployment group to self-heal."
    ),
)


def check(ctx: CloudFormationContext) -> list[Finding]:
    findings: list[Finding] = []
    for r in ctx.resources("AWS::CodeDeploy::DeploymentGroup"):
        app = as_str(r.properties.get("ApplicationName"))
        group = as_str(r.properties.get("DeploymentGroupName")) or r.logical_id
        resource = f"{app}/{group}" if app else group
        findings.append(_cd001_auto_rollback(r.properties, resource))
    return findings
