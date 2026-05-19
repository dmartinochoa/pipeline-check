"""CB-001 (CloudFormation). Plaintext-secret CodeBuild environment variables."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import CloudFormationContext
from ..codebuild import _cb001_plaintext_secrets

RULE = Rule(
    id="CB-001",
    title="Secrets in plaintext environment variables",
    severity=Severity.CRITICAL,
    owasp=("CICD-SEC-6",),
    cwe=("CWE-798",),
    recommendation=(
        "Move secrets to AWS Secrets Manager or SSM Parameter Store and "
        "reference them via ``Type: SECRETS_MANAGER`` or "
        "``Type: PARAMETER_STORE`` on the corresponding "
        "``Environment.EnvironmentVariables`` entry."
    ),
    docs_note=(
        "Walks every ``AWS::CodeBuild::Project``'s "
        "``Properties.Environment.EnvironmentVariables`` list. Flags "
        "any entry whose ``Type`` is ``PLAINTEXT`` (or absent — the "
        "CFN default) when (a) the ``Name`` matches a secret-like "
        "pattern (``PASSWORD``, ``TOKEN``, ``API_KEY``, …) or (b) the "
        "``Value`` matches a known credential shape (AKIA/ASIA, "
        "GitHub tokens, JWTs)."
    ),
)


def check(ctx: CloudFormationContext) -> list[Finding]:
    return [
        _cb001_plaintext_secrets(r.properties, r.address)
        for r in ctx.resources("AWS::CodeBuild::Project")
    ]
