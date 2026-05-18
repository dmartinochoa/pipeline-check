"""S3-002 (CloudFormation). Artifact bucket SSE not configured."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import CloudFormationContext
from ..s3 import _s3002_encryption
from ._s3_context import discover_targets

RULE = Rule(
    id="S3-002",
    title="Artifact bucket server-side encryption not configured",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-9",),
    cwe=("CWE-311",),
    recommendation=(
        "Configure ``BucketEncryption.ServerSideEncryptionConfiguration`` "
        "with ``ServerSideEncryptionByDefault.SSEAlgorithm: aws:kms`` "
        "and ``KMSMasterKeyID`` set to a customer-managed CMK."
    ),
    docs_note=(
        "Reads ``AWS::S3::Bucket."
        "Properties.BucketEncryption.ServerSideEncryptionConfiguration"
        "[0].ServerSideEncryptionByDefault.SSEAlgorithm``."
    ),
)


def check(ctx: CloudFormationContext) -> list[Finding]:
    return [
        _s3002_encryption(props, name) for name, props, _ in discover_targets(ctx)
    ]
