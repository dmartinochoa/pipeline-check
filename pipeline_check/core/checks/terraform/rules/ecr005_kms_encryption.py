"""ECR-005 (Terraform). ECR repo uses AES256, not KMS CMK."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import TerraformContext
from ..ecr import _ecr005_kms_encryption

RULE = Rule(
    id="ECR-005",
    title="Repository encrypted with AES256 rather than KMS CMK",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-9",),
    cwe=("CWE-311",),
    recommendation=(
        "Set ``encryption_configuration { encryption_type = \"KMS\" "
        "kms_key = aws_kms_key.ecr.arn }`` referencing a "
        "customer-managed CMK with a key policy that scopes "
        "``kms:Decrypt`` to the principals that legitimately pull."
    ),
    docs_note=(
        "Reads ``aws_ecr_repository.encryption_configuration[0]."
        "{encryption_type,kms_key}``. The AES256 default uses an "
        "AWS-owned key — you can't audit who used it or revoke access "
        "with a key policy."
    ),
)


def check(ctx: TerraformContext) -> list[Finding]:
    findings: list[Finding] = []
    for r in ctx.resources("aws_ecr_repository"):
        name = r.values.get("name") or r.name
        findings.append(_ecr005_kms_encryption(r.values, name))
    return findings
