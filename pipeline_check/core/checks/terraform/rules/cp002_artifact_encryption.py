"""CP-002 (Terraform). Pipeline artifact store not encrypted by CMK."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import TerraformContext
from ..codepipeline import _cp002_artifact_encryption

RULE = Rule(
    id="CP-002",
    title="Artifact store not encrypted with customer-managed KMS key",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-9",),
    cwe=("CWE-311",),
    recommendation=(
        "Set ``artifact_store[*].encryption_key`` to a customer-managed "
        "KMS CMK on every artifact store. Default S3 SSE is encrypted "
        "by an AWS-owned key you can't rotate or scope by IAM."
    ),
    docs_note=(
        "Reads every ``aws_codepipeline.artifact_store[*]"
        ".encryption_key`` block. An empty list means the store falls "
        "back to AWS-owned-key S3 SSE; with a CMK you control key "
        "policy and rotation independently."
    ),
)


def check(ctx: TerraformContext) -> list[Finding]:
    findings: list[Finding] = []
    for r in ctx.resources("aws_codepipeline"):
        name = r.values.get("name") or r.name
        findings.append(_cp002_artifact_encryption(r.values, name))
    return findings
