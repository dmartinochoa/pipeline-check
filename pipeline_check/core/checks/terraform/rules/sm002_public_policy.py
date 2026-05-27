"""SM-002 (Terraform). Secrets Manager resource policy allows wildcard."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import TerraformContext
from ..extended import _secretsmanager_checks

RULE = Rule(
    id="SM-002",
    title="Secrets Manager resource policy allows wildcard principal",
    severity=Severity.CRITICAL,
    owasp=("CICD-SEC-8",),
    cwe=("CWE-732",),
    recommendation=(
        "Remove ``Principal: \"*\"`` (or ``Principal.AWS = \"*\"``) "
        "from every ``Allow`` statement in the resource policy. If "
        "cross-account access is intentional, name the specific "
        "accounts and add an ``aws:PrincipalOrgID`` condition."
    ),
    docs_note=(
        "Parses ``aws_secretsmanager_secret_policy.policy`` JSON and "
        "fires on any ``Allow`` statement that names a wildcard "
        "principal. The secret content is readable by every AWS "
        "account in the world until the policy is fixed."
    ),
    exploit_example=(
        "# Vulnerable: wildcard principal lets any AWS account\n"
        "# read the secret value (e.g. a production DB password).\n"
        'resource "aws_secretsmanager_secret_policy" "open" {\n'
        "  secret_arn = aws_secretsmanager_secret.db_pass.arn\n"
        "  policy     = jsonencode({\n"
        "    Statement = [{\n"
        '      Effect    = "Allow"\n'
        '      Principal = "*"\n'
        '      Action    = "secretsmanager:GetSecretValue"\n'
        '      Resource  = "*"\n'
        "    }]\n"
        "  })\n"
        "}\n"
        "\n"
        "# Safe: name the specific account and add an org condition.\n"
        'resource "aws_secretsmanager_secret_policy" "scoped" {\n'
        "  secret_arn = aws_secretsmanager_secret.db_pass.arn\n"
        "  policy     = jsonencode({\n"
        "    Statement = [{\n"
        '      Effect    = "Allow"\n'
        '      Principal = { AWS = "arn:aws:iam::123456789012:role/CIRole" }\n'
        '      Action    = "secretsmanager:GetSecretValue"\n'
        '      Resource  = "*"\n'
        "    }]\n"
        "  })\n"
        "}"
    ),
)


def check(ctx: TerraformContext) -> list[Finding]:
    return [f for f in _secretsmanager_checks(ctx) if f.check_id == "SM-002"]
