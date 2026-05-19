"""EB-001 (Terraform). No EventBridge rule for CodePipeline failures."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import TerraformContext
from ..phase3 import _eb001

RULE = Rule(
    id="EB-001",
    title="No EventBridge rule for CodePipeline failure notifications",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-10",),
    cwe=("CWE-778",),
    recommendation=(
        "Declare an ``aws_cloudwatch_event_rule`` whose "
        "``event_pattern`` matches ``aws.codepipeline`` events with "
        "``detail.state = \"FAILED\"``, and target it at the "
        "notification destination of your choice (SNS, Slack via "
        "Chatbot, PagerDuty)."
    ),
    docs_note=(
        "Looks for at least one ``aws_cloudwatch_event_rule`` whose "
        "``event_pattern`` JSON matches ``aws.codepipeline`` "
        "``Pipeline Execution State Change`` events filtered to "
        "``FAILED``. Without one, the only failure signal is "
        "engineers noticing the pipeline didn't update."
    ),
)


def check(ctx: TerraformContext) -> list[Finding]:
    return _eb001(ctx)
