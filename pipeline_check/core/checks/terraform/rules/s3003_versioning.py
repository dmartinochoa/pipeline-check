"""S3-003 (Terraform). Pipeline artifact bucket versioning not enabled."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import TerraformContext
from ..s3 import _s3003_versioning
from ._s3_context import artifact_buckets, index_by_bucket

RULE = Rule(
    id="S3-003",
    title="Artifact bucket versioning not enabled",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-9",),
    cwe=("CWE-353",),
    recommendation=(
        "Attach an ``aws_s3_bucket_versioning`` with "
        "``versioning_configuration { status = \"Enabled\" }`` to every "
        "artifact bucket. Versioning lets you recover from accidental "
        "or malicious overwrites without restoring from external "
        "backups."
    ),
    docs_note=(
        "Joins ``aws_s3_bucket_versioning`` by ``bucket`` for every "
        "pipeline artifact bucket. Reads "
        "``versioning_configuration[0].status``, passes only when it "
        "is ``Enabled``."
    ),
)


def check(ctx: TerraformContext) -> list[Finding]:
    buckets = artifact_buckets(ctx)
    ver = index_by_bucket(ctx, "aws_s3_bucket_versioning")
    return [_s3003_versioning(ver.get(b), b) for b in sorted(buckets)]
