"""S3-004 (Terraform). Pipeline artifact bucket access logging off."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import TerraformContext
from ..s3 import _s3004_logging
from ._s3_context import (
    _first_block,
    artifact_buckets,
    bucket_resource_values,
    has_unresolved_bucket,
    index_by_bucket,
)

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


def _inline_logging(
    ctx: TerraformContext, bucket: str,
) -> dict[str, Any] | None:
    """Provider-v3 inline ``logging { target_bucket = ... }`` on the
    ``aws_s3_bucket`` (the standalone resource uses the same key)."""
    vals = bucket_resource_values(ctx, bucket)
    if vals is None:
        return None
    inline = _first_block(vals.get("logging"))
    if not inline:
        return None
    return {"target_bucket": inline.get("target_bucket")}


def check(ctx: TerraformContext) -> list[Finding]:
    buckets = artifact_buckets(ctx)
    rtype = "aws_s3_bucket_logging"
    log = index_by_bucket(ctx, rtype)
    unresolved = has_unresolved_bucket(ctx, rtype)
    out: list[Finding] = []
    for b in sorted(buckets):
        vals = log.get(b) or _inline_logging(ctx, b)
        out.append(_s3004_logging(vals, b, unresolved=unresolved))
    return out
