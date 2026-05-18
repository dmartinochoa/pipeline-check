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
)


def check(ctx: TerraformContext) -> list[Finding]:
    return [f for f in _secretsmanager_checks(ctx) if f.check_id == "SM-002"]
