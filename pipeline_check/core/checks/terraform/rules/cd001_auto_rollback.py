"""CD-001 (Terraform). CodeDeploy auto-rollback on failure not enabled."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import TerraformContext
from ..codedeploy import _cd001_auto_rollback

RULE = Rule(
    id="CD-001",
    title="Automatic rollback on failure not enabled",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-1",),
    cwe=("CWE-754",),
    recommendation=(
        "Enable ``auto_rollback_configuration`` with at least the "
        "``DEPLOYMENT_FAILURE`` event so a failed release returns the "
        "environment to its prior state without manual intervention."
    ),
    docs_note=(
        "Reads ``aws_codedeploy_deployment_group."
        "auto_rollback_configuration[0]``. The block needs "
        "``enabled = true`` AND ``\"DEPLOYMENT_FAILURE\"`` present in "
        "``events`` for the deployment group to self-heal."
    ),
)


def check(ctx: TerraformContext) -> list[Finding]:
    findings: list[Finding] = []
    for r in ctx.resources("aws_codedeploy_deployment_group"):
        app = r.values.get("app_name", "")
        group = r.values.get("deployment_group_name", "") or r.name
        resource = f"{app}/{group}" if app else group
        findings.append(_cd001_auto_rollback(r.values, resource))
    return findings
