"""CD-003 (CloudFormation). CodeDeploy deployment group has no alarms."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import CloudFormationContext, as_str
from ..codedeploy import _cd003_alarm_config

RULE = Rule(
    id="CD-003",
    title="No CloudWatch alarm monitoring on deployment group",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-10",),
    cwe=("CWE-778",),
    recommendation=(
        "Add CloudWatch alarms to "
        "``AlarmConfiguration.Alarms`` and set "
        "``AlarmConfiguration.Enabled: true``. Pair with CD-001 — "
        "alarm-triggered rollback only fires when at least one "
        "alarm exists to monitor."
    ),
    docs_note=(
        "Reads ``AWS::CodeDeploy::DeploymentGroup."
        "Properties.AlarmConfiguration.{Enabled,Alarms}``. Without "
        "an alarm list, error spikes or latency regressions from a "
        "release won't auto-halt the deployment."
    ),
)


def check(ctx: CloudFormationContext) -> list[Finding]:
    findings: list[Finding] = []
    for r in ctx.resources("AWS::CodeDeploy::DeploymentGroup"):
        app = as_str(r.properties.get("ApplicationName"))
        group = as_str(r.properties.get("DeploymentGroupName")) or r.logical_id
        resource = f"{app}/{group}" if app else group
        findings.append(_cd003_alarm_config(r.properties, resource))
    return findings
