"""S3-002 (Terraform). Pipeline artifact bucket SSE not configured."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import TerraformContext
from ..s3 import _s3002_encryption
from ._s3_context import artifact_buckets, index_by_bucket

RULE = Rule(
    id="S3-002",
    title="Artifact bucket server-side encryption not configured",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-9",),
    cwe=("CWE-311",),
    recommendation=(
        "Attach an "
        "``aws_s3_bucket_server_side_encryption_configuration`` with "
        "``rule { apply_server_side_encryption_by_default { "
        "sse_algorithm = \"aws:kms\" } }`` referencing a "
        "customer-managed KMS CMK."
    ),
    docs_note=(
        "Discovers pipeline artifact buckets from "
        "``aws_codepipeline.artifact_store[*].location`` and joins "
        "``aws_s3_bucket_server_side_encryption_configuration`` by "
        "``bucket``. Reads ``rule[0]."
        "apply_server_side_encryption_by_default[0].sse_algorithm``."
    ),
)


def check(ctx: TerraformContext) -> list[Finding]:
    buckets = artifact_buckets(ctx)
    enc = index_by_bucket(
        ctx, "aws_s3_bucket_server_side_encryption_configuration",
    )
    return [_s3002_encryption(enc.get(b), b) for b in sorted(buckets)]
