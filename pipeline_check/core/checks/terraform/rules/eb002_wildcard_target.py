"""EB-002 (Terraform). EventBridge target ARN contains a literal wildcard."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import TerraformContext
from ..phase4 import _eb002

RULE = Rule(
    id="EB-002",
    title="EventBridge rule has a wildcard target ARN",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-8",),
    cwe=("CWE-441",),
    recommendation=(
        "Pin ``aws_cloudwatch_event_target.arn`` to a specific "
        "function or queue ARN. Wildcards in target ARNs (e.g. "
        "``arn:aws:lambda:*:*:function:*``) defeat the per-target "
        "audit trail and let any resource matching the pattern receive "
        "the event."
    ),
    docs_note=(
        "Reads ``aws_cloudwatch_event_target.arn``. A literal ``*`` "
        "in the ARN is the offending shape, even when EventBridge "
        "allows it at the API level, it makes the target opaque to "
        "any reviewer trying to trace event flow."
    ),
    exploit_example=(
        "# Vulnerable: EventBridge target uses a wildcard ARN.\n"
        "# Any matching resource receives the event.\n"
        'resource "aws_cloudwatch_event_target" "notify" {\n'
        "  rule = aws_cloudwatch_event_rule.pipeline.name\n"
        '  arn  = "arn:aws:lambda:*:*:function:*"\n'
        "}\n"
        "\n"
        "# Safe: pin to a specific function ARN.\n"
        'resource "aws_cloudwatch_event_target" "notify" {\n'
        "  rule = aws_cloudwatch_event_rule.pipeline.name\n"
        "  arn  = aws_lambda_function.handler.arn\n"
        "}"
    ),
)


def check(ctx: TerraformContext) -> list[Finding]:
    return _eb002(ctx)
