"""SM-002 (CloudFormation). Secrets Manager resource policy allows wildcard."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import CloudFormationContext
from ..extended import _secrets

RULE = Rule(
    id="SM-002",
    title="Secrets Manager resource policy allows wildcard principal",
    severity=Severity.CRITICAL,
    owasp=("CICD-SEC-8",),
    cwe=("CWE-732",),
    recommendation=(
        "Remove ``Principal: \"*\"`` (or ``Principal.AWS: \"*\"``) "
        "from every ``Allow`` statement on "
        "``AWS::SecretsManager::ResourcePolicy``. If cross-account "
        "access is intentional, name the specific accounts and add "
        "an ``aws:PrincipalOrgID`` condition."
    ),
    docs_note=(
        "Parses ``AWS::SecretsManager::ResourcePolicy.Properties."
        "ResourcePolicy``. Fires on any ``Allow`` statement that "
        "names a wildcard principal — the secret content is readable "
        "by every AWS account in the world until the policy is "
        "fixed."
    ),
)


def check(ctx: CloudFormationContext) -> list[Finding]:
    return [f for f in _secrets(ctx) if f.check_id == "SM-002"]
