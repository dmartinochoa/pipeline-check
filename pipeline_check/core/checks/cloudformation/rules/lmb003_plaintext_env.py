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
)


def check(ctx: CloudFormationContext) -> list[Finding]:
    return [f for f in _lambda(ctx) if f.check_id == "LMB-003"]
