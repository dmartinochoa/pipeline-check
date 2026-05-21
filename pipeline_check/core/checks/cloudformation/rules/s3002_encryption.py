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
    exploit_example=(
        "# Vulnerable: artifact bucket with no SSE configured.\n"
        "# Build artifacts sit in plaintext at rest.\n"
        "Resources:\n"
        "  Bucket:\n"
        "    Type: AWS::S3::Bucket\n"
        "    Properties:\n"
        "      BucketName: my-artifacts\n"
        "      # no BucketEncryption block\n"
        "\n"
        "# Safe: SSE-KMS with a customer-managed key. Bucket key\n"
        "# enabled for cost (fewer KMS API calls per object).\n"
        "Resources:\n"
        "  Bucket:\n"
        "    Type: AWS::S3::Bucket\n"
        "    Properties:\n"
        "      BucketName: my-artifacts\n"
        "      BucketEncryption:\n"
        "        ServerSideEncryptionConfiguration:\n"
        "          - ServerSideEncryptionByDefault:\n"
        "              SSEAlgorithm: aws:kms\n"
        "              KMSMasterKeyID: !Ref ArtifactsKey\n"
        "            BucketKeyEnabled: true"
    ),
)


def check(ctx: CloudFormationContext) -> list[Finding]:
    return [
        _s3002_encryption(props, name) for name, props, _ in discover_targets(ctx)
    ]
