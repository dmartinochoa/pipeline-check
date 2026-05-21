"""LMB-003 (CloudFormation). Lambda env vars contain plaintext secrets."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import CloudFormationContext
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
        "CMK via ``KmsKeyArn``."
    ),
    docs_note=(
        "Walks ``AWS::Lambda::Function.Properties.Environment.Variables`` "
        "for (a) secret-like names (``PASSWORD``, ``TOKEN``, "
        "``API_KEY``) and (b) credential-shaped values (``AKIA…``, "
        "``ghp_…``, ``xox*``, JWTs)."
    ),
    exploit_example=(
        "# Vulnerable: plaintext credentials in\n"
        "# ``Environment.Variables``. Visible to anyone with\n"
        "# ``lambda:GetFunction`` (wider than Secrets Manager\n"
        "# access), logged in CloudTrail.\n"
        "Resources:\n"
        "  Fn:\n"
        "    Type: AWS::Lambda::Function\n"
        "    Properties:\n"
        "      Environment:\n"
        "        Variables:\n"
        "          DB_PASSWORD: hunter2-prod-pw\n"
        "          API_KEY: sk_live_abc123def456ghi789\n"
        "\n"
        "# Safe: env carries only the secret's ARN; the\n"
        "# function fetches the value from Secrets Manager at\n"
        "# runtime via its role.\n"
        "Resources:\n"
        "  Fn:\n"
        "    Type: AWS::Lambda::Function\n"
        "    Properties:\n"
        "      Environment:\n"
        "        Variables:\n"
        "          DB_SECRET_ARN: !Ref DbSecret\n"
        "          API_KEY_SECRET_ARN: !Ref ApiKeySecret"
    ),
)


def check(ctx: CloudFormationContext) -> list[Finding]:
    return [f for f in _lambda(ctx) if f.check_id == "LMB-003"]
