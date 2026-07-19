"""S3-002 (Terraform). Pipeline artifact bucket SSE not configured."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import TerraformContext
from ..s3 import _s3002_encryption
from ._s3_context import (
    _first_block,
    artifact_buckets,
    bucket_resource_values,
    has_unresolved_bucket,
    index_by_bucket,
)

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
    exploit_example=(
        "# Vulnerable: artifact bucket has no server-side\n"
        "# encryption. Build artifacts stored at rest are\n"
        "# readable if the disk is accessed outside AWS.\n"
        'resource "aws_s3_bucket" "artifacts" {\n'
        '  bucket = "pipeline-artifacts"\n'
        "}\n"
        "# (no aws_s3_bucket_server_side_encryption_configuration)\n"
        "\n"
        "# Safe: enable default encryption.\n"
        'resource "aws_s3_bucket_server_side_encryption_configuration" "enc" {\n'
        "  bucket = aws_s3_bucket.artifacts.id\n"
        "  rule {\n"
        "    apply_server_side_encryption_by_default {\n"
        '      sse_algorithm = "AES256"\n'
        "    }\n"
        "  }\n"
        "}"
    ),
)


def _inline_sse(
    ctx: TerraformContext, bucket: str,
) -> dict[str, Any] | None:
    """Provider-v3 inline ``server_side_encryption_configuration`` block
    on the ``aws_s3_bucket``, reshaped to the standalone resource's
    ``rule`` form. ``None`` when the bucket / block is absent."""
    vals = bucket_resource_values(ctx, bucket)
    if vals is None:
        return None
    inline = _first_block(vals.get("server_side_encryption_configuration"))
    if not inline:
        return None
    return {"rule": inline.get("rule")}


def check(ctx: TerraformContext) -> list[Finding]:
    buckets = artifact_buckets(ctx)
    rtype = "aws_s3_bucket_server_side_encryption_configuration"
    enc = index_by_bucket(ctx, rtype)
    unresolved = has_unresolved_bucket(ctx, rtype)
    out: list[Finding] = []
    for b in sorted(buckets):
        vals = enc.get(b) or _inline_sse(ctx, b)
        out.append(_s3002_encryption(vals, b, unresolved=unresolved))
    return out
