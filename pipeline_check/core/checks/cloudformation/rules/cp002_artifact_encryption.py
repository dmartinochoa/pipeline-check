"""CP-002 (CloudFormation). Pipeline artifact store not CMK-encrypted."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import CloudFormationContext, as_str
from ..codepipeline import _cp002_artifact_encryption

RULE = Rule(
    id="CP-002",
    title="Artifact store not encrypted with customer-managed KMS key",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-9",),
    cwe=("CWE-311",),
    recommendation=(
        "Set ``ArtifactStore.EncryptionKey`` (or every entry in "
        "``ArtifactStores.EncryptionKey``) to a customer-managed "
        "KMS CMK. Default S3 SSE is encrypted by an AWS-owned key "
        "you can't rotate or scope by IAM."
    ),
    docs_note=(
        "Reads ``ArtifactStore.EncryptionKey`` (or ``ArtifactStores`` "
        "for cross-region pipelines). An empty value means the "
        "store falls back to AWS-owned-key S3 SSE; with a CMK you "
        "control key policy and rotation independently."
    ),
)


def check(ctx: CloudFormationContext) -> list[Finding]:
    findings: list[Finding] = []
    for r in ctx.resources("AWS::CodePipeline::Pipeline"):
        name = as_str(r.properties.get("Name")) or r.logical_id
        findings.append(_cp002_artifact_encryption(r.properties, name))
    return findings
