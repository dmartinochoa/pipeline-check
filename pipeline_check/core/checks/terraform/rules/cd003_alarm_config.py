"""CD-003 (Terraform). CodeDeploy deployment group has no alarm config."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import TerraformContext
from ..codedeploy import _cd003_alarm_config

RULE = Rule(
    id="CD-003",
    title="No CloudWatch alarm monitoring on deployment group",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-10",),
    cwe=("CWE-778",),
    recommendation=(
        "Add CloudWatch alarms to "
        "``alarm_configuration.alarms`` and set ``enabled = true``. "
        "Pair this with CD-001 — alarm-triggered rollback only fires "
        "when at least one alarm exists to monitor."
    ),
    docs_note=(
        "Reads ``aws_codedeploy_deployment_group."
        "alarm_configuration[0].{enabled,alarms}``. Without an alarm "
        "list, error spikes or latency regressions from a release "
        "won't auto-halt the deployment or trigger rollback."
    ),
)


def check(ctx: TerraformContext) -> list[Finding]:
    findings: list[Finding] = []
    for r in ctx.resources("aws_codedeploy_deployment_group"):
        app = r.values.get("app_name", "")
        group = r.values.get("deployment_group_name", "") or r.name
        resource = f"{app}/{group}" if app else group
        findings.append(_cd003_alarm_config(r.values, resource))
    return findings
