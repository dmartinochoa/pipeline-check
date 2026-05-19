"""CW-001 (Terraform). No CloudWatch alarm on CodeBuild FailedBuilds."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import TerraformContext
from ..phase4 import _cw001

RULE = Rule(
    id="CW-001",
    title="No CloudWatch alarm on CodeBuild FailedBuilds metric",
    severity=Severity.LOW,
    owasp=("CICD-SEC-10",),
    cwe=("CWE-778",),
    recommendation=(
        "Declare an ``aws_cloudwatch_metric_alarm`` with "
        "``namespace = \"AWS/CodeBuild\"`` and "
        "``metric_name = \"FailedBuilds\"`` and route it to an "
        "actionable destination (PagerDuty, Slack via Chatbot, SNS "
        "topic with a human responder)."
    ),
    docs_note=(
        "Gated check: fires only when the plan declares "
        "``aws_codebuild_project``. Passes when at least one "
        "``aws_cloudwatch_metric_alarm`` is configured for "
        "``namespace = \"AWS/CodeBuild\"`` "
        "+ ``metric_name = \"FailedBuilds\"``."
    ),
)


def check(ctx: TerraformContext) -> list[Finding]:
    return _cw001(ctx)
