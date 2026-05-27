"""LMB-003 (Terraform). Lambda env vars contain plaintext secrets."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import TerraformContext
from ..services import _lambda

RULE = Rule(
    id="LMB-003",
    title="Lambda environment variables contain plaintext secrets",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-6",),
    cwe=("CWE-798",),
    recommendation=(
        "Move secrets to Secrets Manager or SSM Parameter Store and "
        "read them at function init time. For static values that "
        "must live in the env, encrypt them at rest with a customer "
        "CMK via ``kms_key_arn``."
    ),
    docs_note=(
        "Walks ``aws_lambda_function.environment[0].variables`` for "
        "(a) secret-like names (``PASSWORD``, ``TOKEN``, ``API_KEY``) "
        "and (b) credential-shaped values (``AKIA…``, ``ghp_…``, "
        "``xox*``, JWTs). Env vars are visible to anyone with "
        "``lambda:GetFunctionConfiguration``."
    ),
    exploit_example=(
        "# Vulnerable: secret stored as a plaintext Lambda env\n"
        "# var. Visible in the AWS console and API responses.\n"
        'resource "aws_lambda_function" "api" {\n'
        "  function_name = \"api\"\n"
        "  environment {\n"
        "    variables = {\n"
        '      DB_PASSWORD = "hunter2"\n'
        "    }\n"
        "  }\n"
        "}\n"
        "\n"
        "# Safe: reference Secrets Manager at runtime.\n"
        'resource "aws_lambda_function" "api" {\n'
        "  function_name = \"api\"\n"
        "  environment {\n"
        "    variables = {\n"
        "      DB_SECRET_ARN = aws_secretsmanager_secret.db.arn\n"
        "    }\n"
        "  }\n"
        "}"
    ),
)


def check(ctx: TerraformContext) -> list[Finding]:
    return [f for f in _lambda(ctx) if f.check_id == "LMB-003"]
