"""EB-001 (CloudFormation). No EventBridge rule for CodePipeline failures."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import CloudFormationContext
from ..phase3 import _eb001

RULE = Rule(
    id="EB-001",
    title="No EventBridge rule for CodePipeline failure notifications",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-10",),
    cwe=("CWE-778",),
    recommendation=(
        "Declare an ``AWS::Events::Rule`` whose ``EventPattern`` "
        "matches ``aws.codepipeline`` events with ``detail.state: "
        "FAILED``, and target it at the notification destination of "
        "your choice (SNS, Slack via Chatbot, PagerDuty)."
    ),
    docs_note=(
        "Looks for at least one ``AWS::Events::Rule`` whose "
        "``EventPattern`` JSON matches ``aws.codepipeline`` "
        "``Pipeline Execution State Change`` events filtered to "
        "``FAILED``."
    ),
)


def check(ctx: CloudFormationContext) -> list[Finding]:
    return _eb001(ctx)
