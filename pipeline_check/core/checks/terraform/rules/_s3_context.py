"""Shared S3 artifact-bucket enumeration for the S3-* Terraform rules.

The S3 rules all care about the same set of buckets: those declared as
``aws_codepipeline.artifact_store[*].location``. Each rule additionally
needs a ``bucket → side-resource.values`` index for its specific
``aws_s3_bucket_*`` resource type. Centralizing the discovery here
keeps each rule's ``check(ctx)`` short.

Underscore-prefixed so :func:`discover_rules` skips it.
"""
from __future__ import annotations

from typing import Any

from ..base import TerraformContext


def artifact_buckets(ctx: TerraformContext) -> set[str]:
    """Return the set of bucket names used as pipeline artifact stores."""
    buckets: set[str] = set()
    for r in ctx.resources("aws_codepipeline"):
        for store in r.values.get("artifact_store", []) or []:
            loc = store.get("location")
            if loc:
                buckets.add(loc)
    return buckets


def index_by_bucket(
    ctx: TerraformContext, resource_type: str,
) -> dict[str, dict[str, Any]]:
    """Index resources of *resource_type* by their ``bucket`` attribute."""
    out: dict[str, dict[str, Any]] = {}
    for r in ctx.resources(resource_type):
        bucket = r.values.get("bucket")
        if bucket:
            out[bucket] = r.values
    return out
