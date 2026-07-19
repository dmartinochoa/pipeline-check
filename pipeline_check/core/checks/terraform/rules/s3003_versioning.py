"""S3-003 (Terraform). Pipeline artifact bucket versioning not enabled."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import TerraformContext
from ..s3 import _s3003_versioning
from ._s3_context import (
    _first_block,
    artifact_buckets,
    bucket_resource_values,
    has_unresolved_bucket,
    index_by_bucket,
)

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


def _inline_versioning(
    ctx: TerraformContext, bucket: str,
) -> dict[str, Any] | None:
    """Provider-v3 inline ``versioning { enabled = true }`` on the
    ``aws_s3_bucket``, reshaped to the standalone resource's
    ``versioning_configuration.status`` form."""
    vals = bucket_resource_values(ctx, bucket)
    if vals is None:
        return None
    inline = _first_block(vals.get("versioning"))
    if not inline:
        return None
    status = "Enabled" if inline.get("enabled") else "Suspended"
    return {"versioning_configuration": [{"status": status}]}


def check(ctx: TerraformContext) -> list[Finding]:
    buckets = artifact_buckets(ctx)
    rtype = "aws_s3_bucket_versioning"
    ver = index_by_bucket(ctx, rtype)
    unresolved = has_unresolved_bucket(ctx, rtype)
    out: list[Finding] = []
    for b in sorted(buckets):
        vals = ver.get(b) or _inline_versioning(ctx, b)
        out.append(_s3003_versioning(vals, b, unresolved=unresolved))
    return out
