"""S3-001 (Terraform). Pipeline artifact bucket PAB not fully enabled."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import TerraformContext
from ..s3 import _s3001_pab
from ._s3_context import (
    artifact_buckets,
    has_unresolved_bucket,
    index_by_bucket,
)

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
    exploit_example=(
        "# Vulnerable: no public access block on the artifact\n"
        "# bucket. A permissive bucket policy or ACL can make\n"
        "# build artifacts (wheels, JARs, container layers)\n"
        "# world-readable.\n"
        'resource "aws_s3_bucket" "artifacts" {\n'
        '  bucket = "my-pipeline-artifacts"\n'
        "}\n"
        "# (no aws_s3_bucket_public_access_block resource)\n"
        "\n"
        "# Safe: attach a full public access block.\n"
        'resource "aws_s3_bucket_public_access_block" "artifacts" {\n'
        "  bucket                  = aws_s3_bucket.artifacts.id\n"
        "  block_public_acls       = true\n"
        "  ignore_public_acls      = true\n"
        "  block_public_policy     = true\n"
        "  restrict_public_buckets = true\n"
        "}"
    ),
)


def check(ctx: TerraformContext) -> list[Finding]:
    buckets = artifact_buckets(ctx)
    rtype = "aws_s3_bucket_public_access_block"
    pab = index_by_bucket(ctx, rtype)
    unresolved = has_unresolved_bucket(ctx, rtype)
    return [
        _s3001_pab(pab.get(b), b, unresolved=unresolved)
        for b in sorted(buckets)
    ]
