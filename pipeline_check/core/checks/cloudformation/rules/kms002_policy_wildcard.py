"""KMS-002 (CloudFormation). KMS key policy grants kms:* to a principal."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import CloudFormationContext
from ..services import _kms

RULE = Rule(
    id="KMS-002",
    title="KMS key policy grants kms:* to an IAM principal",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-2",),
    cwe=("CWE-732",),
    recommendation=(
        "Enumerate the specific KMS actions each principal needs "
        "(``kms:Encrypt``, ``kms:Decrypt``, ``kms:GenerateDataKey``, "
        "``kms:DescribeKey``). Reserve ``kms:*`` for the root "
        "principal that owns the key."
    ),
    docs_note=(
        "Parses ``AWS::KMS::Key.Properties.KeyPolicy``. Fires on "
        "any ``Allow`` statement that pairs ``kms:*`` with a "
        "non-root IAM principal — that's the canonical "
        "key-compromise primitive."
    ),
    exploit_example=(
        "# Vulnerable: KMS key policy with ``kms:*`` (or ``'*'``)\n"
        "# granted to an IAM principal. ScheduleKeyDeletion +\n"
        "# PutKeyPolicy mean a compromise of that principal\n"
        "# collapses every secret encrypted with the key.\n"
        "Resources:\n"
        "  Key:\n"
        "    Type: AWS::KMS::Key\n"
        "    Properties:\n"
        "      KeyPolicy:\n"
        "        Statement:\n"
        "          - Effect: Allow\n"
        "            Principal: { AWS: !GetAtt CIRole.Arn }\n"
        "            Action: 'kms:*'\n"
        "            Resource: '*'\n"
        "\n"
        "# Safe: enumerate the verbs the workload needs. Key-\n"
        "# admin verbs stay scoped to a separate admin role.\n"
        "Resources:\n"
        "  Key:\n"
        "    Type: AWS::KMS::Key\n"
        "    Properties:\n"
        "      KeyPolicy:\n"
        "        Statement:\n"
        "          - Effect: Allow\n"
        "            Principal: { AWS: !GetAtt CIRole.Arn }\n"
        "            Action:\n"
        "              - kms:Encrypt\n"
        "              - kms:Decrypt\n"
        "              - kms:GenerateDataKey\n"
        "              - kms:DescribeKey\n"
        "            Resource: '*'"
    ),
)


def check(ctx: CloudFormationContext) -> list[Finding]:
    return [f for f in _kms(ctx) if f.check_id == "KMS-002"]
