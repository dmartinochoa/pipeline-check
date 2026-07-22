"""LMB-004 (Terraform). Lambda permission grants Principal '*'."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import TerraformContext
from ..services import _lambda

RULE = Rule(
    id="LMB-004",
    title="Lambda resource policy grants wildcard principal",
    severity=Severity.CRITICAL,
    owasp=("CICD-SEC-8",),
    cwe=("CWE-732",),
    recommendation=(
        "Drop any ``aws_lambda_permission`` with ``principal = \"*\"`` "
        "(or ``principal = \"arn:aws:iam::*:root\"``). Name the "
        "specific service principal or account that needs invoke, "
        "and scope further with ``source_account`` / ``source_arn`` "
        "conditions."
    ),
    docs_note=(
        "Inspects every ``aws_lambda_permission`` resource. Fires "
        "when ``principal`` is exactly ``\"*\"`` and the permission "
        "carries no ``source_account`` / ``source_arn`` scoping "
        "condition. (The Lambda API rejects wildcard ARN principals "
        "like ``arn:aws:iam::*:root``, so only the bare ``\"*\"`` "
        "reaches this rule.) A wildcard invoker exposes the function — "
        "and whatever role it executes with — to the whole internet."
    ),
    exploit_example=(
        "# Vulnerable: any AWS account (or anonymous caller via\n"
        "# API Gateway) can invoke this function and execute\n"
        "# with its role's permissions.\n"
        'resource "aws_lambda_permission" "open" {\n'
        '  action        = "lambda:InvokeFunction"\n'
        "  function_name = aws_lambda_function.deployer.function_name\n"
        '  principal     = "*"\n'
        "}\n"
        "\n"
        "# Safe: name the specific service and scope with\n"
        "# source_arn.\n"
        'resource "aws_lambda_permission" "scoped" {\n'
        '  action        = "lambda:InvokeFunction"\n'
        "  function_name = aws_lambda_function.deployer.function_name\n"
        '  principal     = "apigateway.amazonaws.com"\n'
        "  source_arn    = aws_api_gateway_rest_api.api.execution_arn\n"
        "}"
    ),
)


def check(ctx: TerraformContext) -> list[Finding]:
    return [f for f in _lambda(ctx) if f.check_id == "LMB-004"]
