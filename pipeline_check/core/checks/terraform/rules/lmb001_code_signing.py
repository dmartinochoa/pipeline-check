"""LMB-001 (Terraform). Lambda function has no CodeSigningConfigArn."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import TerraformContext
from ..services import _lambda

RULE = Rule(
    id="LMB-001",
    title="Lambda function has no code-signing config",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-9",),
    cwe=("CWE-345",),
    recommendation=(
        "Set ``code_signing_config_arn`` on every "
        "``aws_lambda_function`` to an "
        "``aws_lambda_code_signing_config`` whose allowed publishers "
        "list signing profiles your release pipeline uses."
    ),
    docs_note=(
        "Reads ``aws_lambda_function.code_signing_config_arn``. "
        "Without it, Lambda accepts any zip the deployer can upload "
        "— there's no cryptographic check that the artifact came "
        "from the expected pipeline."
    ),
    exploit_example=(
        "# Vulnerable: no code signing config. A compromised\n"
        "# deployment pipeline can push arbitrary code to the\n"
        "# function without verification.\n"
        'resource "aws_lambda_function" "deployer" {\n'
        "  function_name = \"deployer\"\n"
        '  runtime       = "python3.12"\n'
        '  handler       = "index.handler"\n'
        "  filename      = \"deployer.zip\"\n"
        "  role          = aws_iam_role.lambda.arn\n"
        "}\n"
        "\n"
        "# Safe: attach a code signing config.\n"
        'resource "aws_lambda_function" "deployer" {\n'
        "  function_name          = \"deployer\"\n"
        '  runtime                = "python3.12"\n'
        '  handler                = "index.handler"\n'
        "  filename               = \"deployer.zip\"\n"
        "  role                   = aws_iam_role.lambda.arn\n"
        "  code_signing_config_arn = aws_lambda_code_signing_config.csc.arn\n"
        "}"
    ),
)


def check(ctx: TerraformContext) -> list[Finding]:
    return [f for f in _lambda(ctx) if f.check_id == "LMB-001"]
