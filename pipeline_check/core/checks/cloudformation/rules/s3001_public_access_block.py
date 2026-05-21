"""S3-001 (CloudFormation). Artifact bucket PAB not fully enabled."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import CloudFormationContext
from ..s3 import _s3001_pab
from ._s3_context import discover_targets

RULE = Rule(
    id="S3-001",
    title="Artifact bucket public access block not fully enabled",
    severity=Severity.CRITICAL,
    owasp=("CICD-SEC-9",),
    cwe=("CWE-732",),
    recommendation=(
        "Set ``PublicAccessBlockConfiguration.{BlockPublicAcls,"
        "IgnorePublicAcls,BlockPublicPolicy,RestrictPublicBuckets}`` "
        "all to ``true`` on every artifact bucket."
    ),
    docs_note=(
        "Discovers pipeline artifact buckets via "
        "``ArtifactStore.Location`` / ``ArtifactStores[*].Location`` "
        "and reads ``AWS::S3::Bucket."
        "Properties.PublicAccessBlockConfiguration``. Any of the four "
        "PAB flags left ``false`` (or missing) lets an ACL or bucket "
        "policy expose build artifacts."
    ),
    exploit_example=(
        "# Vulnerable: ``PublicAccessBlockConfiguration`` with\n"
        "# any of the four toggles off. A future bucket policy\n"
        "# / ACL change can re-expose the bucket.\n"
        "Resources:\n"
        "  Bucket:\n"
        "    Type: AWS::S3::Bucket\n"
        "    Properties:\n"
        "      BucketName: my-artifacts\n"
        "      PublicAccessBlockConfiguration:\n"
        "        BlockPublicAcls: true\n"
        "        IgnorePublicAcls: false      # missing\n"
        "        BlockPublicPolicy: true\n"
        "        RestrictPublicBuckets: false # missing\n"
        "\n"
        "# Safe: all four ON.\n"
        "Resources:\n"
        "  Bucket:\n"
        "    Type: AWS::S3::Bucket\n"
        "    Properties:\n"
        "      BucketName: my-artifacts\n"
        "      PublicAccessBlockConfiguration:\n"
        "        BlockPublicAcls: true\n"
        "        IgnorePublicAcls: true\n"
        "        BlockPublicPolicy: true\n"
        "        RestrictPublicBuckets: true"
    ),
)


def check(ctx: CloudFormationContext) -> list[Finding]:
    return [
        _s3001_pab(props, name) for name, props, _ in discover_targets(ctx)
    ]
