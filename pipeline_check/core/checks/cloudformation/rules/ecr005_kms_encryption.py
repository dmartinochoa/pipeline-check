"""ECR-005 (CloudFormation). ECR repo uses AES256, not KMS CMK."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import CloudFormationContext, as_str
from ..ecr import _ecr005_kms_encryption

RULE = Rule(
    id="ECR-005",
    title="Repository encrypted with AES256 rather than KMS CMK",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-9",),
    cwe=("CWE-311",),
    recommendation=(
        "Set "
        "``EncryptionConfiguration.EncryptionType: KMS`` and "
        "``EncryptionConfiguration.KmsKey: <CMK ARN>`` referencing a "
        "customer-managed CMK with a key policy scoped to the "
        "principals that legitimately pull."
    ),
    docs_note=(
        "Reads ``AWS::ECR::Repository."
        "Properties.EncryptionConfiguration.{EncryptionType,KmsKey}``. "
        "The AES256 default uses an AWS-owned key — you can't audit "
        "who used it or revoke access with a key policy."
    ),
)


def check(ctx: CloudFormationContext) -> list[Finding]:
    findings: list[Finding] = []
    for r in ctx.resources("AWS::ECR::Repository"):
        name = as_str(r.properties.get("RepositoryName")) or r.logical_id
        findings.append(_ecr005_kms_encryption(r.properties, name))
    return findings
