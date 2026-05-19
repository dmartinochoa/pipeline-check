"""S3-001 (Terraform). Pipeline artifact bucket PAB not fully enabled."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import TerraformContext
from ..s3 import _s3001_pab
from ._s3_context import artifact_buckets, index_by_bucket

RULE = Rule(
    id="S3-001",
    title="Artifact bucket public access block not fully enabled",
    severity=Severity.CRITICAL,
    owasp=("CICD-SEC-9",),
    cwe=("CWE-732",),
    recommendation=(
        "Attach an ``aws_s3_bucket_public_access_block`` with all four "
        "flags ``true`` to every artifact bucket: ``block_public_acls "
        "= true``, ``ignore_public_acls = true``, "
        "``block_public_policy = true``, ``restrict_public_buckets = "
        "true``."
    ),
    docs_note=(
        "Discovers pipeline artifact buckets from "
        "``aws_codepipeline.artifact_store[*].location``. For each, "
        "joins the corresponding ``aws_s3_bucket_public_access_block`` "
        "by ``bucket``. Any of the four PAB flags left ``false`` (or "
        "missing entirely) lets an ACL or bucket policy make build "
        "artifacts publicly readable."
    ),
)


def check(ctx: TerraformContext) -> list[Finding]:
    buckets = artifact_buckets(ctx)
    pab = index_by_bucket(ctx, "aws_s3_bucket_public_access_block")
    return [_s3001_pab(pab.get(b), b) for b in sorted(buckets)]
