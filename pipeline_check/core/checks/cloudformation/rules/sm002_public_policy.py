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
    exploit_example=(
        "# Vulnerable: Secrets Manager resource policy with\n"
        "# ``Principal: '*'``. Anyone (no auth required) can\n"
        "# call GetSecretValue.\n"
        "Resources:\n"
        "  Policy:\n"
        "    Type: AWS::SecretsManager::ResourcePolicy\n"
        "    Properties:\n"
        "      SecretId: !Ref Secret\n"
        "      ResourcePolicy:\n"
        "        Version: '2012-10-17'\n"
        "        Statement:\n"
        "          - Effect: Allow\n"
        "            Principal: '*'\n"
        "            Action: secretsmanager:GetSecretValue\n"
        "            Resource: '*'\n"
        "\n"
        "# Safe: don't attach a resource policy at all (rely on\n"
        "# IAM). If a resource policy is needed, scope\n"
        "# ``Principal`` to specific roles in your account /\n"
        "# org.\n"
        "Resources:\n"
        "  Policy:\n"
        "    Type: AWS::SecretsManager::ResourcePolicy\n"
        "    Properties:\n"
        "      SecretId: !Ref Secret\n"
        "      ResourcePolicy:\n"
        "        Version: '2012-10-17'\n"
        "        Statement:\n"
        "          - Effect: Allow\n"
        "            Principal: { AWS: !GetAtt ConsumerRole.Arn }\n"
        "            Action: secretsmanager:GetSecretValue\n"
        "            Resource: '*'"
    ),
)


def check(ctx: CloudFormationContext) -> list[Finding]:
    return [f for f in _secrets(ctx) if f.check_id == "SM-002"]
