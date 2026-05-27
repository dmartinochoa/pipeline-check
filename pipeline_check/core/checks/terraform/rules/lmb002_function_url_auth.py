"""LMB-002 (Terraform). Lambda function URL has AuthType = NONE."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import TerraformContext
from ..services import _lambda

RULE = Rule(
    id="LMB-002",
    title="Lambda Function URL configured with AuthType = NONE",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-8",),
    cwe=("CWE-862",),
    recommendation=(
        "Set ``authorization_type = \"AWS_IAM\"`` on every "
        "``aws_lambda_function_url`` and grant invoke permission via "
        "explicit ``aws_lambda_permission`` resources rather than "
        "leaving the URL public."
    ),
    docs_note=(
        "Reads ``aws_lambda_function_url.authorization_type``. The "
        "``NONE`` setting exposes the function over a public HTTPS "
        "endpoint with no authentication — if invoke is the goal, "
        "AWS_IAM with a scoped resource policy is almost always the "
        "right answer."
    ),
    exploit_example=(
        "# Vulnerable: function URL has no auth. Anyone on the\n"
        "# internet can invoke the function.\n"
        'resource "aws_lambda_function_url" "public" {\n'
        "  function_name      = aws_lambda_function.api.function_name\n"
        '  authorization_type = "NONE"\n'
        "}\n"
        "\n"
        "# Safe: require AWS IAM auth.\n"
        'resource "aws_lambda_function_url" "authed" {\n'
        "  function_name      = aws_lambda_function.api.function_name\n"
        '  authorization_type = "AWS_IAM"\n'
        "}"
    ),
)


def check(ctx: TerraformContext) -> list[Finding]:
    return [f for f in _lambda(ctx) if f.check_id == "LMB-002"]
