"""SM-001 (CloudFormation). Secrets Manager secret has no rotation."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import CloudFormationContext
from ..extended import _secrets

RULE = Rule(
    id="SM-001",
    title="Secrets Manager secret has no rotation configured",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-6",),
    cwe=("CWE-262",),
    recommendation=(
        "Declare an ``AWS::SecretsManager::RotationSchedule`` that "
        "targets the secret via ``SecretId`` (literal ARN or "
        "``{ Ref: <SecretLogicalId> }``), with "
        "``HostedRotationLambda`` or a ``RotationLambdaARN`` plus "
        "``RotationRules.AutomaticallyAfterDays``."
    ),
    docs_note=(
        "Joins ``AWS::SecretsManager::RotationSchedule`` to "
        "``AWS::SecretsManager::Secret`` by ``SecretId``. Fires when "
        "a secret has no matching rotation resource — a static "
        "secret lives forever in any backup or snapshot taken since "
        "the leak."
    ),
)


def check(ctx: CloudFormationContext) -> list[Finding]:
    return [f for f in _secrets(ctx) if f.check_id == "SM-001"]
