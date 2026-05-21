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
    exploit_example=(
        "# Vulnerable: a Secrets Manager secret with no rotation\n"
        "# (no ``AWS::SecretsManager::RotationSchedule`` resource\n"
        "# referencing it). The credential lives forever; any\n"
        "# leak stays valid until manual rotation.\n"
        "Resources:\n"
        "  Secret:\n"
        "    Type: AWS::SecretsManager::Secret\n"
        "    Properties:\n"
        "      Name: prod/db-master\n"
        "      Description: prod DB password\n"
        "      # no rotation schedule\n"
        "\n"
        "# Safe: pair the secret with a rotation Lambda + 30-day\n"
        "# schedule. AWS provides templates for RDS / DocumentDB\n"
        "# / Redshift; custom secrets need a custom Lambda.\n"
        "Resources:\n"
        "  Secret:\n"
        "    Type: AWS::SecretsManager::Secret\n"
        "    Properties:\n"
        "      Name: prod/db-master\n"
        "  Rotation:\n"
        "    Type: AWS::SecretsManager::RotationSchedule\n"
        "    Properties:\n"
        "      SecretId: !Ref Secret\n"
        "      RotationLambdaARN: !GetAtt RotateDbFn.Arn\n"
        "      RotationRules:\n"
        "        AutomaticallyAfterDays: 30"
    ),
)


def check(ctx: CloudFormationContext) -> list[Finding]:
    return [f for f in _secrets(ctx) if f.check_id == "SM-001"]
