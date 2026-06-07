"""CB-001 (Terraform). Plaintext-secret CodeBuild environment variables."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import TerraformContext
from ..codebuild import _cb001_plaintext_secrets

RULE = Rule(
    id="CB-001",
    title="Secrets in plaintext environment variables",
    severity=Severity.CRITICAL,
    owasp=("CICD-SEC-6",),
    cwe=("CWE-798",),
    recommendation=(
        "Move secrets to AWS Secrets Manager or SSM Parameter Store and "
        "reference them using ``type = \"SECRETS_MANAGER\"`` or "
        "``type = \"PARAMETER_STORE\"`` on the corresponding "
        "``environment_variable`` block."
    ),
    docs_note=(
        "Walks every ``aws_codebuild_project.environment[0]."
        "environment_variable[*]``. Flags any entry whose ``type`` is "
        "``PLAINTEXT`` (or absent, which Terraform defaults to "
        "PLAINTEXT) when (a) the ``name`` matches a secret-like pattern "
        "(``PASSWORD``, ``TOKEN``, ``API_KEY``, …) or (b) the ``value`` "
        "matches one of pipeline-check's known credential shapes (cloud "
        "access keys, VCS / registry / CI / cloud-service tokens, Slack "
        "``xox*`` tokens, JWTs — the same shared detector catalog GHA-008 "
        "uses). Plaintext values land in the AWS console, CloudTrail, and "
        "build logs."
    ),
    exploit_example=(
        "# Vulnerable: secret value is PLAINTEXT (the default).\n"
        "# The key appears in the AWS console, CloudTrail API\n"
        "# logs, and build output.\n"
        'resource "aws_codebuild_project" "ci" {\n'
        "  environment {\n"
        "    environment_variable {\n"
        '      name  = "DB_PASSWORD"\n'
        '      value = "hunter2"\n'
        "    }\n"
        "  }\n"
        "}\n"
        "\n"
        "# Safe: reference Secrets Manager.\n"
        'resource "aws_codebuild_project" "ci" {\n'
        "  environment {\n"
        "    environment_variable {\n"
        '      name  = "DB_PASSWORD"\n'
        '      value = "arn:aws:secretsmanager:us-east-1:123456789012:secret:db-pass"\n'
        '      type  = "SECRETS_MANAGER"\n'
        "    }\n"
        "  }\n"
        "}"
    ),
)


def check(ctx: TerraformContext) -> list[Finding]:
    return [
        _cb001_plaintext_secrets(r.values, r.address)
        for r in ctx.resources("aws_codebuild_project")
    ]
