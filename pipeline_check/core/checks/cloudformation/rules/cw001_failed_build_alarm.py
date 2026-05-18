"""CW-001 (CloudFormation). No CloudWatch alarm on CodeBuild FailedBuilds."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import CloudFormationContext
from ..phase4 import _cw001

RULE = Rule(
    id="CW-001",
    title="No CloudWatch alarm on CodeBuild FailedBuilds metric",
    severity=Severity.LOW,
    owasp=("CICD-SEC-10",),
    cwe=("CWE-778",),
    recommendation=(
        "Declare an ``AWS::CloudWatch::Alarm`` with "
        "``Namespace: AWS/CodeBuild`` and "
        "``MetricName: FailedBuilds`` and route it to an actionable "
        "destination (PagerDuty, Slack via Chatbot, SNS topic with "
        "a human responder)."
    ),
    docs_note=(
        "Gated check: fires only when the template declares "
        "``AWS::CodeBuild::Project``. Passes when at least one "
        "``AWS::CloudWatch::Alarm`` is configured for "
        "``Namespace: AWS/CodeBuild`` + "
        "``MetricName: FailedBuilds``."
    ),
)


def check(ctx: CloudFormationContext) -> list[Finding]:
    return _cw001(ctx)
