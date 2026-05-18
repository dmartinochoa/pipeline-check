"""S3-004 (Terraform). Pipeline artifact bucket access logging off."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import TerraformContext
from ..s3 import _s3004_logging
from ._s3_context import artifact_buckets, index_by_bucket

RULE = Rule(
    id="S3-004",
    title="Artifact bucket access logging not enabled",
    severity=Severity.LOW,
    owasp=("CICD-SEC-10",),
    cwe=("CWE-778",),
    recommendation=(
        "Attach an ``aws_s3_bucket_logging`` resource pointing "
        "``target_bucket`` at a central, write-protected logging "
        "bucket. Access logs are what forensics use to reconstruct "
        "who pulled which artifact during an incident."
    ),
    docs_note=(
        "Joins ``aws_s3_bucket_logging`` by ``bucket`` for every "
        "pipeline artifact bucket. Passes when ``target_bucket`` is "
        "set on the joined resource."
    ),
)


def check(ctx: TerraformContext) -> list[Finding]:
    buckets = artifact_buckets(ctx)
    log = index_by_bucket(ctx, "aws_s3_bucket_logging")
    return [_s3004_logging(log.get(b), b) for b in sorted(buckets)]
